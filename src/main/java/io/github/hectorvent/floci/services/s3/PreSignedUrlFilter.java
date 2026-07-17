package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.core.common.SigV4aPublicKeyResolver;
import io.github.hectorvent.floci.core.common.XmlBuilder;
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

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 10)
public class PreSignedUrlFilter implements ContainerRequestFilter {

    /** Set after expiry check and optional SigV4 verification succeed. */
    public static final String PRESIGN_VERIFIED_PROPERTY = "floci.s3.presign.verified";

    private final PreSignedUrlGenerator presignGenerator;
    private final EmulatorConfig config;
    private final IamService iamService;
    private final SigV4aPublicKeyResolver sigV4aPublicKeyResolver;
    private final AuthPosture authPosture;
    private final RequestContext flociRequestContext;

    @Inject
    public PreSignedUrlFilter(PreSignedUrlGenerator presignGenerator,
                              EmulatorConfig config,
                              IamService iamService,
                              SigV4aPublicKeyResolver sigV4aPublicKeyResolver,
                              AuthPosture authPosture,
                              RequestContext flociRequestContext) {
        this.presignGenerator = presignGenerator;
        this.config = config;
        this.iamService = iamService;
        this.sigV4aPublicKeyResolver = sigV4aPublicKeyResolver;
        this.authPosture = authPosture;
        this.flociRequestContext = flociRequestContext;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        var queryParams = requestContext.getUriInfo().getQueryParameters();

        String algorithm = queryParams.getFirst("X-Amz-Algorithm");
        if (algorithm == null) {
            return;
        }

        if ("AWS4-ECDSA-P256-SHA256".equals(algorithm)) {
            if (config.services().iam().strictEnforcementEnabled() && !presignGenerator.shouldValidateSignatures()) {
                requestContext.abortWith(errorResponse(403, "AccessDenied",
                        "Pre-signed URLs require FLOCI_AUTH_VALIDATE_SIGNATURES when strict IAM enforcement is enabled."));
                return;
            }
            handleSigV4aPresignedUrl(requestContext, queryParams, algorithm);
            return;
        }
        if (!"AWS4-HMAC-SHA256".equals(algorithm)) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Unsupported X-Amz-Algorithm value."));
            return;
        }

        if (config.services().iam().strictEnforcementEnabled() && !presignGenerator.shouldValidateSignatures()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Pre-signed URLs require FLOCI_AUTH_VALIDATE_SIGNATURES when strict IAM enforcement is enabled."));
            return;
        }

        if (S3RequestAuthorizationParser.isMissingRequiredPresignedParameter(queryParams)) {
            requestContext.abortWith(errorResponse(
                    S3RequestAuthorizationParser.AUTHORIZATION_QUERY_PARAMETERS_ERROR_STATUS,
                    S3RequestAuthorizationParser.AUTHORIZATION_QUERY_PARAMETERS_ERROR_CODE,
                    S3RequestAuthorizationParser.AUTHORIZATION_QUERY_PARAMETERS_ERROR_MESSAGE));
            return;
        }

        String amzDate = queryParams.getFirst("X-Amz-Date");
        String expiresStr = queryParams.getFirst("X-Amz-Expires");
        String credential = queryParams.getFirst("X-Amz-Credential");

        int expires;
        try {
            expires = Integer.parseInt(expiresStr);
        } catch (NumberFormatException e) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Invalid X-Amz-Expires value."));
            return;
        }

        Optional<Instant> signedAt = presignGenerator.parseAmzDate(amzDate);
        if (signedAt.isEmpty()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Invalid X-Amz-Date value."));
            return;
        }

        if (presignGenerator.isExpired(signedAt.get(), expires)) {
            requestContext.abortWith(expiredResponse(signedAt.get(), expires));
            return;
        }

        if (presignGenerator.shouldValidateSignatures()) {
            String path = requestContext.getUriInfo().getRequestUri().getRawPath();
            String rawQuery = requestContext.getUriInfo().getRequestUri().getRawQuery();
            String host = requestContext.getHeaderString("Host");
            if (host == null || host.isBlank()) {
                requestContext.abortWith(errorResponse(403, "AccessDenied",
                        "Missing Host header for pre-signed URL validation."));
                return;
            }

            String accessKeyId = SigV4RequestValidator.parseAccessKeyIdFromCredential(credential);
            Optional<String> secret = resolvePresignSecret(accessKeyId);
            if (secret.isEmpty()) {
                requestContext.abortWith(errorResponse(403, "AccessDenied",
                        "Unknown credentials for pre-signed URL."));
                return;
            }

            if (IamService.isTemporaryAccessKey(accessKeyId) && !validatePresignSessionToken(requestContext, accessKeyId)) {
                return;
            }

            SigV4RequestValidator.Result sigv4Result = SigV4RequestValidator.validatePresignedUrl(
                    requestContext.getMethod(),
                    path,
                    rawQuery,
                    host,
                    secret.get(),
                    collectRequestHeaders(requestContext));

            if (sigv4Result != SigV4RequestValidator.Result.VALID) {
                requestContext.abortWith(errorResponse(403, "SignatureDoesNotMatch",
                        "The request signature we calculated does not match the signature you provided."));
                return;
            }
        }

        markPresignVerified(requestContext, credential);
    }

    private void handleSigV4aPresignedUrl(ContainerRequestContext requestContext,
                                            jakarta.ws.rs.core.MultivaluedMap<String, String> queryParams,
                                            String algorithm) {
        String amzDate = queryParams.getFirst("X-Amz-Date");
        String expiresStr = queryParams.getFirst("X-Amz-Expires");
        String signature = queryParams.getFirst("X-Amz-Signature");
        String credential = queryParams.getFirst("X-Amz-Credential");

        if (amzDate == null || expiresStr == null || signature == null || credential == null) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Missing required pre-signed URL parameters."));
            return;
        }

        int expires;
        try {
            expires = Integer.parseInt(expiresStr);
        } catch (NumberFormatException e) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Invalid X-Amz-Expires value."));
            return;
        }

        Optional<Instant> signedAt = presignGenerator.parseAmzDate(amzDate);
        if (signedAt.isEmpty()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Invalid X-Amz-Date value."));
            return;
        }

        if (presignGenerator.isExpired(signedAt.get(), expires)) {
            requestContext.abortWith(expiredResponse(signedAt.get(), expires));
            return;
        }

        if (!presignGenerator.shouldValidateSignatures()) {
            markPresignVerified(requestContext, credential);
            return;
        }

        String path = requestContext.getUriInfo().getRequestUri().getRawPath();
        String rawQuery = requestContext.getUriInfo().getRequestUri().getRawQuery();
        String host = requestContext.getHeaderString("Host");
        if (host == null || host.isBlank()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Missing Host header for pre-signed URL validation."));
            return;
        }

        String accessKeyId = SigV4RequestValidator.parseAccessKeyIdFromCredential(credential);
        var publicKey = sigV4aPublicKeyResolver.resolve(accessKeyId);
        if (publicKey.isEmpty()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Unknown credentials for pre-signed URL."));
            return;
        }

        if (IamService.isTemporaryAccessKey(accessKeyId) && !validatePresignSessionToken(requestContext, accessKeyId)) {
            return;
        }

        SigV4RequestValidator.Result sigv4aResult = SigV4RequestValidator.validatePresignedUrlSigV4a(
                requestContext.getMethod(),
                path,
                rawQuery,
                host,
                publicKey.get(),
                collectRequestHeaders(requestContext));

        if (sigv4aResult != SigV4RequestValidator.Result.VALID) {
            requestContext.abortWith(errorResponse(403, "SignatureDoesNotMatch",
                    "The request signature we calculated does not match the signature you provided."));
            return;
        }

        markPresignVerified(requestContext, credential);
    }

    private void markPresignVerified(ContainerRequestContext requestContext, String credential) {
        requestContext.setProperty(PRESIGN_VERIFIED_PROPERTY, Boolean.TRUE);
        if (authPosture.deferCallerAccessKeyUntilVerified() && credential != null && !credential.isBlank()) {
            String accessKeyId = SigV4RequestValidator.parseAccessKeyIdFromCredential(credential);
            if (accessKeyId != null && !accessKeyId.isBlank()) {
                flociRequestContext.setAccessKeyId(accessKeyId);
            }
        }
    }

    private static Map<String, String> collectRequestHeaders(ContainerRequestContext requestContext) {
        Map<String, String> headers = new LinkedHashMap<>();
        for (String name : requestContext.getHeaders().keySet()) {
            String value = requestContext.getHeaderString(name);
            if (value != null) {
                headers.put(name.toLowerCase(Locale.ROOT), value);
            }
        }
        return headers;
    }

    private Optional<String> resolvePresignSecret(String accessKeyId) {
        if (accessKeyId == null) {
            return Optional.empty();
        }
        Optional<String> rootSecret = config.auth().rootAccessKeyId()
                .filter(accessKeyId::equals)
                .flatMap(ignored -> config.auth().resolveRootSecretAccessKey());
        if (rootSecret.isPresent()) {
            return rootSecret;
        }
        return iamService.findSecretKey(accessKeyId);
    }

    private boolean validatePresignSessionToken(ContainerRequestContext requestContext, String accessKeyId) {
        String rawQuery = requestContext.getUriInfo().getRequestUri().getRawQuery();
        String provided = SigV4RequestValidator.queryParam(rawQuery, "X-Amz-Security-Token");
        if (provided == null || provided.isBlank()) {
            provided = requestContext.getHeaderString("x-amz-security-token");
        }
        if (provided == null || provided.isBlank()) {
            requestContext.abortWith(errorResponse(403, "InvalidClientTokenId",
                    "The security token included in the request is invalid."));
            return false;
        }
        Optional<String> expected = iamService.findSessionToken(accessKeyId);
        if (expected.isEmpty() || !expected.get().equals(provided)) {
            requestContext.abortWith(errorResponse(403, "InvalidClientTokenId",
                    "The security token included in the request is invalid."));
            return false;
        }
        return true;
    }

    private Response expiredResponse(Instant signedAt, int expiresSeconds) {
        Instant expiresAt = presignGenerator.expirationTime(signedAt, expiresSeconds);
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", "AccessDenied")
                  .elem("Message", "Request has expired")
                  .elem("Expires", DateTimeFormatter.ISO_INSTANT.format(expiresAt))
                  .elem("ServerTime", DateTimeFormatter.ISO_INSTANT.format(Instant.now()))
                .end("Error")
                .build();
        return Response.status(403).entity(xml).type(MediaType.APPLICATION_XML).build();
    }

    private Response errorResponse(int status, String code, String message) {
        String xml = new XmlBuilder()
                .raw("<?xml version=\"1.0\" encoding=\"UTF-8\"?>")
                .start("Error")
                  .elem("Code", code)
                  .elem("Message", message)
                .end("Error")
                .build();
        return Response.status(status).entity(xml).type(MediaType.APPLICATION_XML).build();
    }
}
