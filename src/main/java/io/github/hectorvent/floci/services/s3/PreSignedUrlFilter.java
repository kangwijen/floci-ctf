package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.XmlBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

@Provider
@ApplicationScoped
public class PreSignedUrlFilter implements ContainerRequestFilter {

    private final PreSignedUrlGenerator presignGenerator;
    private final EmulatorConfig config;

    @Inject
    public PreSignedUrlFilter(PreSignedUrlGenerator presignGenerator, EmulatorConfig config) {
        this.presignGenerator = presignGenerator;
        this.config = config;
    }

    @Override
    public void filter(ContainerRequestContext requestContext) {
        var queryParams = requestContext.getUriInfo().getQueryParameters();

        // Only process if this is a pre-signed URL request
        String algorithm = queryParams.getFirst("X-Amz-Algorithm");
        if (algorithm == null) {
            return;
        }

        if (config.services().iam().strictEnforcementEnabled() && !presignGenerator.shouldValidateSignatures()) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Pre-signed URLs require FLOCI_AUTH_VALIDATE_SIGNATURES when strict IAM enforcement is enabled."));
            return;
        }

        String amzDate = queryParams.getFirst("X-Amz-Date");
        String expiresStr = queryParams.getFirst("X-Amz-Expires");
        String signature = queryParams.getFirst("X-Amz-Signature");

        if (amzDate == null || expiresStr == null || signature == null) {
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

        // Check expiration
        if (presignGenerator.isExpired(amzDate, expires)) {
            requestContext.abortWith(errorResponse(403, "AccessDenied",
                    "Request has expired."));
            return;
        }

        // Optionally verify signature (if validateSignatures is enabled)
        if (presignGenerator.shouldValidateSignatures()) {
            String path = requestContext.getUriInfo().getPath();
            String[] parts = path.split("/", 3);
            if (parts.length < 3) {
                requestContext.abortWith(errorResponse(403, "AccessDenied",
                        "Invalid pre-signed URL path."));
                return;
            }
            String bucket = parts[1];
            String key = parts[2];
            String method = requestContext.getMethod();

            if (!presignGenerator.verifySignature(method, bucket, key, amzDate, expires, signature)) {
                requestContext.abortWith(errorResponse(403, "SignatureDoesNotMatch",
                        "The request signature we calculated does not match the signature you provided."));
            }
        }
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
