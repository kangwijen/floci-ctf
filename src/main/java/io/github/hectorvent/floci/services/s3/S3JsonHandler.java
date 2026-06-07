package io.github.hectorvent.floci.services.s3;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsErrorResponse;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Response;

import java.time.format.DateTimeFormatter;
import java.util.Base64;

/**
 * JSON API handler for S3 actions invoked from in-process integrations (Step Functions, API Gateway).
 */
@ApplicationScoped
public class S3JsonHandler {

    private static final DateTimeFormatter S3_DATE_FORMAT =
            DateTimeFormatter.ofPattern("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'").withZone(java.time.ZoneOffset.UTC);

    private final S3Service service;
    private final ObjectMapper objectMapper;

    @Inject
    public S3JsonHandler(S3Service service, ObjectMapper objectMapper) {
        this.service = service;
        this.objectMapper = objectMapper;
    }

    public Response handle(String action, JsonNode request, String region) {
        return switch (action) {
            case "GetObject" -> handleGetObject(request);
            default -> Response.status(400)
                    .entity(new AwsErrorResponse("UnsupportedOperation", "Operation " + action + " is not supported."))
                    .build();
        };
    }

    private Response handleGetObject(JsonNode request) {
        String bucket = request.path("Bucket").asText(null);
        String key = request.path("Key").asText(null);
        if (bucket == null || bucket.isBlank() || key == null || key.isBlank()) {
            return Response.status(400)
                    .entity(new AwsErrorResponse("InvalidRequest", "Bucket and Key are required."))
                    .build();
        }

        String versionId = request.path("VersionId").asText(null);
        try {
            S3Object obj = service.getObject(bucket, key, versionId);
            ObjectNode response = objectMapper.createObjectNode();
            if (obj.getData() != null) {
                response.put("Body", Base64.getEncoder().encodeToString(obj.getData()));
            }
            response.put("ContentLength", obj.getSize());
            if (obj.getContentType() != null) {
                response.put("ContentType", obj.getContentType());
            }
            if (obj.getETag() != null) {
                response.put("ETag", obj.getETag());
            }
            if (obj.getLastModified() != null) {
                response.put("LastModified", S3_DATE_FORMAT.format(obj.getLastModified()));
            }
            if (obj.getVersionId() != null) {
                response.put("VersionId", obj.getVersionId());
            }
            return Response.ok(response).build();
        } catch (AwsException e) {
            return Response.status(e.getHttpStatus())
                    .entity(new AwsErrorResponse(e.getErrorCode(), e.getMessage()))
                    .build();
        }
    }
}
