package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import io.github.hectorvent.floci.services.iam.IamService;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;
import org.jboss.logging.Logger;

import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates SigV4 {@code Authorization} headers on inbound AWS API requests when
 * {@link AuthPosture#signatureValidationActive()} is true.
 *
 * <p>Runs at {@link Priorities#AUTHENTICATION} so signature verification happens
 * before {@link IamEnforcementFilter} policy checks. On successful verification,
 * publishes {@link RequestContext#setAccessKeyId(String)} for PassRole (O23).
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION)
public class SigV4ValidationFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(SigV4ValidationFilter.class);

    /** Set on the request when SigV4 header auth verifies successfully. */
    public static final String SIGV4_VERIFIED_PROPERTY = "floci.sigv4.verified";

    private static final String AWS4_HMAC_SHA256 = "AWS4-HMAC-SHA256";

    private static final Pattern SERVICE_PATTERN =
            Pattern.compile("Credential=\\S+/\\d{8}/[^/]+/([^/]+)/");

    private final EmulatorConfig config;
    private final AccountResolver accountResolver;
    private final IamService iamService;
    private final AuthPosture authPosture;
    private final RequestContext requestContext;

    @Inject
    public SigV4ValidationFilter(EmulatorConfig config,
                                 AccountResolver accountResolver,
                                 IamService iamService,
                                 AuthPosture authPosture,
                                 RequestContext requestContext) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
        this.authPosture = authPosture;
        this.requestContext = requestContext;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!authPosture.signatureValidationActive()) {
            return;
        }

        String path = ctx.getUriInfo().getPath();
        String auth = ctx.getHeaderString("Authorization");

        // Unsigned internal health/info routes stay open. When Authorization is present
        // (operator root on /_floci/*), still verify so IamEnforcementFilter can trust
        // SIGV4_VERIFIED for the operator bypass.
        if (SecurityBypassPaths.isInternalHealthOrInfoPath(
                path, config.ctf().hideInternalEndpointsMode())
                && (auth == null || auth.isBlank())) {
            return;
        }

        if (SecurityBypassPaths.isPresignedUrlRequest(ctx)) {
            return;
        }

        if (SecurityBypassPaths.isCognitoOAuthPath(path)) {
            return;
        }

        if (SecurityBypassPaths.isFederatedStsAssumeRequest(ctx)) {
            return;
        }

        if (auth == null || auth.isBlank()) {
            return;
        }

        String trimmedAuth = auth.trim();
        if (!trimmedAuth.startsWith(AWS4_HMAC_SHA256)) {
            if (isCredentialSmugglingOrMalformedSigV4(trimmedAuth)) {
                LOG.debugv("SigV4 validation DENY: malformed Authorization (missing {0} prefix)",
                        AWS4_HMAC_SHA256);
                ctx.abortWith(errorResponse("IncompleteSignature",
                        "Authorization header requires '" + AWS4_HMAC_SHA256 + "' algorithm prefix.",
                        extractService(trimmedAuth),
                        ctx.getMediaType()));
            }
            return;
        }

        String akid = accountResolver.extractAccessKeyId(trimmedAuth);
        if (akid == null) {
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(trimmedAuth),
                    ctx.getMediaType()));
            return;
        }

        Optional<String> secret = resolveSecret(akid);
        if (secret.isEmpty()) {
            LOG.debugv("SigV4 validation: no secret for access key {0}", akid);
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(trimmedAuth),
                    ctx.getMediaType()));
            return;
        }

        if (IamService.isTemporaryAccessKey(akid) && !validateSessionToken(ctx, akid)) {
            return;
        }

        byte[] body = RequestBodyBuffer.buffer(ctx);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                ctx.getMethod(),
                ctx.getUriInfo().getRequestUri().getRawPath(),
                ctx.getUriInfo().getRequestUri().getRawQuery(),
                ctx.getHeaders(),
                trimmedAuth,
                secret.get(),
                body);

        switch (result) {
            case VALID -> {
                ctx.setProperty(SIGV4_VERIFIED_PROPERTY, Boolean.TRUE);
                requestContext.setAccessKeyId(akid);
            }
            case EXPIRED -> ctx.abortWith(errorResponse("RequestExpired",
                    "Request is expired.",
                    extractService(trimmedAuth),
                    ctx.getMediaType()));
            case INVALID_AUTHORIZATION, INVALID_SIGNATURE -> {
                LOG.debugv("SigV4 validation failed for access key {0}: {1}", akid, result);
                ctx.abortWith(errorResponse("SignatureDoesNotMatch",
                        "The request signature we calculated does not match the signature you provided. "
                                + "Check your AWS Secret Access Key and signing method. "
                                + "Consult the service documentation for details.",
                        extractService(trimmedAuth),
                        ctx.getMediaType()));
            }
        }
    }

    /**
     * True when the header carries a SigV4 {@code Credential=} field or a case-variant
     * algorithm token, but lacks the exact {@code AWS4-HMAC-SHA256} prefix.
     */
    static boolean isCredentialSmugglingOrMalformedSigV4(String trimmedAuth) {
        if (trimmedAuth == null || trimmedAuth.isBlank()) {
            return false;
        }
        if (trimmedAuth.contains("Credential=")) {
            return true;
        }
        return trimmedAuth.regionMatches(true, 0, AWS4_HMAC_SHA256, 0, AWS4_HMAC_SHA256.length());
    }

    private Optional<String> resolveSecret(String akid) {
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return config.auth().resolveRootSecretAccessKey();
        }
        return iamService.findSecretKey(akid);
    }

    private boolean validateSessionToken(ContainerRequestContext ctx, String akid) {
        String provided = ctx.getHeaderString("x-amz-security-token");
        if (provided == null || provided.isBlank()) {
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(ctx.getHeaderString("Authorization")),
                    ctx.getMediaType()));
            return false;
        }
        Optional<String> expected = iamService.findSessionToken(akid);
        if (expected.isEmpty() || !expected.get().equals(provided)) {
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(ctx.getHeaderString("Authorization")),
                    ctx.getMediaType()));
            return false;
        }
        return true;
    }

    static boolean isInternalPath(String path) {
        return SecurityBypassPaths.isInternalHealthOrInfoPath(path, CtfHideInternalEndpointsMode.OFF);
    }

    private static String extractService(String auth) {
        Matcher m = SERVICE_PATTERN.matcher(auth);
        return m.find() ? m.group(1) : null;
    }

    static Response errorResponse(String code, String message, String service, MediaType requestMediaType) {
        if ("s3".equals(service)) {
            return s3XmlError(code, message);
        }
        if (isFormEncoded(requestMediaType)) {
            return queryXmlError(code, message);
        }
        return jsonError(code, message);
    }

    private static boolean isFormEncoded(MediaType mt) {
        return mt != null
                && "application".equalsIgnoreCase(mt.getType())
                && "x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype());
    }

    private static Response s3XmlError(String code, String message) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", code)
                  .elem("Message", message)
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("Error")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response queryXmlError(String code, String message) {
        String xml = new XmlBuilder()
                .start("ErrorResponse")
                  .start("Error")
                    .elem("Type", "Sender")
                    .elem("Code", code)
                    .elem("Message", message)
                  .end("Error")
                  .elem("RequestId", UUID.randomUUID().toString())
                .end("ErrorResponse")
                .build();
        return Response.status(403).type(MediaType.APPLICATION_XML).entity(xml).build();
    }

    private static Response jsonError(String code, String message) {
        String type = switch (code) {
            case "SignatureDoesNotMatch" -> "SignatureDoesNotMatch";
            case "IncompleteSignature" -> "IncompleteSignature";
            case "InvalidClientTokenId" -> "InvalidClientTokenId";
            case "RequestExpired" -> "RequestExpiredException";
            default -> code;
        };
        String body = "{\"__type\":\"" + type + "\",\"message\":\"" + escapeJson(message) + "\"}";
        return Response.status(403).type(MediaType.APPLICATION_JSON).entity(body).build();
    }

    private static String escapeJson(String value) {
        return value.replace("\\", "\\\\").replace("\"", "\\\"");
    }

}
