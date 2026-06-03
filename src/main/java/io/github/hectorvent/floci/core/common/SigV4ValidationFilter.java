package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.UUID;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Validates SigV4 {@code Authorization} headers on inbound AWS API requests when
 * {@code floci.auth.validate-signatures = true}.
 *
 * <p>Runs at {@link Priorities#AUTHENTICATION} so signature verification happens
 * before {@link IamEnforcementFilter} policy checks.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION)
public class SigV4ValidationFilter implements ContainerRequestFilter {

    private static final Logger LOG = Logger.getLogger(SigV4ValidationFilter.class);

    private static final Pattern SERVICE_PATTERN =
            Pattern.compile("Credential=\\S+/\\d{8}/[^/]+/([^/]+)/");

    private final EmulatorConfig config;
    private final AccountResolver accountResolver;
    private final IamService iamService;

    @Inject
    public SigV4ValidationFilter(EmulatorConfig config,
                                 AccountResolver accountResolver,
                                 IamService iamService) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.iamService = iamService;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!config.auth().validateSignatures()) {
            return;
        }

        if (SecurityBypassPaths.isInternalHealthOrInfoPath(
                ctx.getUriInfo().getPath(), config.ctf().hideInternalEndpointsMode())) {
            return;
        }

        if (SecurityBypassPaths.isPresignedUrlRequest(ctx)) {
            return;
        }

        String auth = ctx.getHeaderString("Authorization");
        if (auth == null || auth.isBlank()) {
            return;
        }
        if (!auth.startsWith("AWS4-HMAC-SHA256")) {
            return;
        }

        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null) {
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(auth),
                    ctx.getMediaType()));
            return;
        }

        Optional<String> secret = resolveSecret(akid);
        if (secret.isEmpty()) {
            LOG.debugv("SigV4 validation: no secret for access key {0}", akid);
            ctx.abortWith(errorResponse("InvalidClientTokenId",
                    "The security token included in the request is invalid.",
                    extractService(auth),
                    ctx.getMediaType()));
            return;
        }

        byte[] body = bufferBody(ctx);

        SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                ctx.getMethod(),
                ctx.getUriInfo().getRequestUri().getRawPath(),
                ctx.getUriInfo().getRequestUri().getRawQuery(),
                ctx.getHeaders(),
                auth,
                secret.get(),
                body);

        switch (result) {
            case VALID -> {
                // continue
            }
            case EXPIRED -> ctx.abortWith(errorResponse("RequestExpired",
                    "Request is expired.",
                    extractService(auth),
                    ctx.getMediaType()));
            case INVALID_AUTHORIZATION, INVALID_SIGNATURE -> {
                LOG.debugv("SigV4 validation failed for access key {0}: {1}", akid, result);
                ctx.abortWith(errorResponse("SignatureDoesNotMatch",
                        "The request signature we calculated does not match the signature you provided. "
                                + "Check your AWS Secret Access Key and signing method. "
                                + "Consult the service documentation for details.",
                        extractService(auth),
                        ctx.getMediaType()));
            }
        }
    }

    private Optional<String> resolveSecret(String akid) {
        if (config.auth().rootAccessKeyId().filter(akid::equals).isPresent()) {
            return config.auth().resolveRootSecretAccessKey();
        }
        return iamService.findSecretKey(akid);
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

    /**
     * Reads the full entity stream and restores it so downstream handlers (IAM
     * enforcement, resource methods) can still consume the body.
     */
    private static byte[] bufferBody(ContainerRequestContext ctx) {
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return new byte[0];
        }
        try {
            byte[] body = in.readAllBytes();
            ctx.setEntityStream(new ByteArrayInputStream(body));
            return body;
        } catch (IOException e) {
            return new byte[0];
        }
    }
}
