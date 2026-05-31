package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;

/**
 * Constructs the target resource ARN for a request so the policy evaluator
 * can match it against Resource patterns in policy documents.
 *
 * Returns {@code *} when the resource cannot be determined, which matches
 * permissive wildcard policies.
 */
@ApplicationScoped
public class ResourceArnBuilder {

    private final ObjectMapper objectMapper;

    @Inject
    public ResourceArnBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
    }

    public String build(String credentialScope, ContainerRequestContext ctx,
                        String region, String accountId) {
        String path = ctx.getUriInfo().getPath();
        return switch (credentialScope) {
            case "s3"             -> buildS3Arn(path);
            case "lambda"         -> buildLambdaArn(path, region, accountId);
            case "sqs"            -> buildSqsArn(ctx, region, accountId);
            case "sns"            -> buildSnsArn(ctx, region, accountId);
            case "dynamodb"       -> buildDynamoDbArn(ctx, region, accountId);
            case "kinesis"        -> buildKinesisArn(ctx, region, accountId);
            case "secretsmanager" -> buildSecretsManagerArn(ctx, region, accountId);
            case "ssm"            -> buildSsmArn(ctx, region, accountId);
            case "kms"            -> buildKmsArn(path, region, accountId);
            case "sts"            -> buildStsArn(ctx);
            default               -> "*";
        };
    }

    // ── S3 ──────────────────────────────────────────────────────────────────────
    private String buildS3Arn(String path) {
        // path: /bucket or /bucket/key
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return AwsArnUtils.Arn.of("s3", "", "", "*").toString();
        }
        int slash = stripped.indexOf('/');
        if (slash < 0) {
            return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
        }
        return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
    }

    // ── Lambda ──────────────────────────────────────────────────────────────────
    private String buildLambdaArn(String path, String region, String accountId) {
        // path: /2015-03-31/functions/name or similar
        String name = extractSegmentAfter(path, "functions");
        if (name == null) return "*";
        // strip qualifier if present
        int colon = name.indexOf(':');
        if (colon > 0) name = name.substring(0, colon);
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + name).toString();
    }

    // ── SQS ─────────────────────────────────────────────────────────────────────
    private String buildSqsArn(ContainerRequestContext ctx, String region, String accountId) {
        String queueUrl = ctx.getUriInfo().getQueryParameters().getFirst("QueueUrl");
        if (queueUrl == null) {
            queueUrl = readFormParam(ctx, "QueueUrl");
        }
        if (queueUrl != null) {
            String queueName = queueUrl.substring(queueUrl.lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────
    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        String topicArn = readFormParam(ctx, "TopicArn");
        return topicArn != null ? topicArn : AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    // ── DynamoDB ─────────────────────────────────────────────────────────────────
    private String buildDynamoDbArn(ContainerRequestContext ctx, String region, String accountId) {
        // TableName comes in the JSON body; use wildcard since we don't parse the body here
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
    }

    // ── Kinesis ──────────────────────────────────────────────────────────────────
    private String buildKinesisArn(ContainerRequestContext ctx, String region, String accountId) {
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    // ── Secrets Manager ──────────────────────────────────────────────────────────
    private String buildSecretsManagerArn(ContainerRequestContext ctx, String region, String accountId) {
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────
    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        String name = readJsonStringField(ctx, "Name");
        if (name == null || name.isBlank()) {
            // GetParameters uses Names array; use first element if present
            name = readJsonFirstArrayElement(ctx, "Names");
        }
        if (name == null || name.isBlank()) {
            return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
        }
        // AWS SSM ARNs strip the leading slash from the parameter name
        if (name.startsWith("/")) {
            name = name.substring(1);
        }
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/" + name).toString();
    }

    // ── STS ──────────────────────────────────────────────────────────────────────
    private String buildStsArn(ContainerRequestContext ctx) {
        // AssumeRole sends RoleArn in form body (Query protocol)
        String roleArn = readFormParam(ctx, "RoleArn");
        return roleArn != null ? roleArn : "*";
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────
    private String buildKmsArn(String path, String region, String accountId) {
        String keyId = extractSegmentAfter(path, "keys");
        if (keyId == null) return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
    }

    // ── Body/param helpers ────────────────────────────────────────────────────────

    /**
     * Reads a form parameter by checking the URL query string first, then the
     * {@code application/x-www-form-urlencoded} request body. The entity stream
     * is fully buffered and restored so downstream handlers still see the body.
     */
    String readFormParam(ContainerRequestContext ctx, String paramName) {
        String v = ctx.getUriInfo().getQueryParameters().getFirst(paramName);
        if (v != null) {
            return v;
        }
        MediaType mt = ctx.getMediaType();
        if (mt == null
                || !"application".equalsIgnoreCase(mt.getType())
                || !"x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype())) {
            return null;
        }
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        Charset charset = resolveCharset(mt);
        String form = new String(body, charset);
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            if (eq < 0) {
                continue;
            }
            try {
                String key = URLDecoder.decode(pair.substring(0, eq), charset);
                if (paramName.equals(key)) {
                    return URLDecoder.decode(pair.substring(eq + 1), charset);
                }
            } catch (IllegalArgumentException ignored) {
            }
        }
        return null;
    }

    /**
     * Reads a top-level string field from the JSON request body. The entity
     * stream is fully buffered and restored so downstream handlers still see the body.
     */
    String readJsonStringField(ContainerRequestContext ctx, String fieldName) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode field = node.get(fieldName);
            if (field != null && field.isTextual()) {
                return field.asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Reads the first string element of a top-level JSON array field. Used for
     * SSM {@code GetParameters} which sends {@code Names} instead of {@code Name}.
     * The entity stream is buffered and restored.
     */
    private String readJsonFirstArrayElement(ContainerRequestContext ctx, String fieldName) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode arr = node.get(fieldName);
            if (arr != null && arr.isArray() && arr.size() > 0 && arr.get(0).isTextual()) {
                return arr.get(0).asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    /**
     * Reads all bytes from the entity stream and restores it so downstream
     * JAX-RS handlers can still read the body. Returns {@code null} on failure.
     */
    private byte[] bufferBody(ContainerRequestContext ctx) {
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return null;
        }
        try {
            byte[] body = in.readAllBytes();
            ctx.setEntityStream(new ByteArrayInputStream(body));
            return body;
        } catch (IOException e) {
            return null;
        }
    }

    private static Charset resolveCharset(MediaType mt) {
        String name = mt.getParameters().get("charset");
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }

    // ── Path helpers ──────────────────────────────────────────────────────────────

    private String extractSegmentAfter(String path, String segment) {
        String marker = "/" + segment + "/";
        int idx = path.indexOf(marker);
        if (idx < 0) return null;
        String after = path.substring(idx + marker.length());
        // take only the first segment (stop at next /)
        int slash = after.indexOf('/');
        return slash > 0 ? after.substring(0, slash) : after;
    }
}
