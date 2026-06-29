package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Constructs the target resource ARN for a request so the policy evaluator
 * can match it against {@code Resource} patterns in identity-based policies.
 *
 * <p>Templates follow the
 * <a href="https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html">AWS Service Authorization Reference</a>.
 * When a specific resource cannot be determined, returns a service-scoped wildcard
 * (for example {@code table/*}) so explicit {@code *} in policies still matches, but
 * scoped ARNs do not.
 */
@ApplicationScoped
public class ResourceArnBuilder {

    private static final Pattern API_GW_REST_API = Pattern.compile("/restapis/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EXECUTE_API = Pattern.compile("/([^/]+)/([^/]+)/", Pattern.CASE_INSENSITIVE);

    /** PartiQL {@code FROM "table"} / {@code FROM table} (SELECT, DELETE). */
    private static final Pattern PARTIQL_FROM_QUOTED =
            Pattern.compile("\\bFROM\\s+\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PARTIQL_FROM_IDENT =
            Pattern.compile("\\bFROM\\s+([A-Za-z_][A-Za-z0-9_]*)", Pattern.CASE_INSENSITIVE);
    /** PartiQL {@code INSERT INTO "table"} / {@code INSERT INTO table}. */
    private static final Pattern PARTIQL_INTO_QUOTED =
            Pattern.compile("\\bINTO\\s+\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PARTIQL_INTO_IDENT =
            Pattern.compile("\\bINTO\\s+([A-Za-z_][A-Za-z0-9_]*)", Pattern.CASE_INSENSITIVE);
    /** PartiQL {@code UPDATE "table"} / {@code UPDATE table SET ...}. */
    private static final Pattern PARTIQL_UPDATE_QUOTED =
            Pattern.compile("\\bUPDATE\\s+\"([^\"]+)\"", Pattern.CASE_INSENSITIVE);
    private static final Pattern PARTIQL_UPDATE_IDENT =
            Pattern.compile("\\bUPDATE\\s+([A-Za-z_][A-Za-z0-9_]*)", Pattern.CASE_INSENSITIVE);

    /** AWS IAM suffix wildcard for the six random ARN characters when the secret is not stored yet. */
    private static final String SECRETS_MANAGER_IAM_SUFFIX_PLACEHOLDER = "-??????";

    private final ObjectMapper objectMapper;
    private final SecretsManagerService secretsManagerService;

    @Inject
    public ResourceArnBuilder(ObjectMapper objectMapper, SecretsManagerService secretsManagerService) {
        this.objectMapper = objectMapper;
        this.secretsManagerService = secretsManagerService;
    }

    /** Unit tests without a backing secret store. */
    ResourceArnBuilder(ObjectMapper objectMapper) {
        this(objectMapper, null);
    }

    public String build(String credentialScope, ContainerRequestContext ctx,
                        String region, String accountId) {
        String path = ctx.getUriInfo().getPath();
        return switch (credentialScope) {
            case "s3"                   -> buildS3Arn(path);
            case "lambda"               -> buildLambdaArn(path, region, accountId);
            case "sqs"                  -> buildSqsArn(ctx, region, accountId);
            case "sns"                  -> buildSnsArn(ctx, region, accountId);
            case "dynamodb"             -> buildDynamoDbArn(ctx, region, accountId);
            case "kinesis"              -> buildKinesisArn(ctx, region, accountId);
            case "secretsmanager"       -> buildSecretsManagerArn(ctx, region, accountId);
            case "ssm"                  -> buildSsmArn(ctx, region, accountId);
            case "kms"                  -> buildKmsArn(ctx, path, region, accountId);
            case "iam"                  -> buildIamArn(ctx, accountId);
            case "sts"                  -> buildStsArn(ctx);
            case "ec2"                  -> buildEc2Arn(ctx, region, accountId);
            case "cloudformation"       -> buildCloudFormationArn(ctx, region, accountId);
            case "elasticache"          -> buildElastiCacheArn(ctx, region, accountId);
            case "rds", "neptune"       -> buildRdsArn(ctx, region, accountId);
            case "email", "ses", "sesv2" -> buildSesArn(ctx, region, accountId);
            case "monitoring"           -> buildCloudWatchArn(ctx, region, accountId);
            case "elasticloadbalancing" -> buildElbArn(ctx, region, accountId);
            case "autoscaling"         -> buildAutoScalingArn(ctx, region, accountId);
            case "logs"                 -> buildLogsArn(ctx, region, accountId);
            case "events"               -> buildEventsArn(ctx, region, accountId);
            case "states"               -> buildStatesArn(ctx, region, accountId);
            case "ecr"                  -> buildEcrArn(ctx, region, accountId);
            case "ecs"                  -> buildEcsArn(ctx, region, accountId);
            case "firehose"             -> buildFirehoseArn(ctx, region, accountId);
            case "cognito-idp"          -> buildCognitoArn(ctx, region, accountId);
            case "apigateway"           -> buildApiGatewayArn(ctx, path, region);
            case "execute-api"          -> buildExecuteApiArn(ctx, path, region, accountId);
            case "glue"                 -> buildGlueArn(ctx, region, accountId);
            case "athena"               -> buildAthenaArn(ctx, region, accountId);
            case "es"                   -> buildOpenSearchArn(path, region, accountId);
            case "servicediscovery"     -> buildServiceDiscoveryArn(ctx, region, accountId);
            case "appsync"              -> buildAppSyncArn(ctx, path, region, accountId);
            case "eks"                  -> buildEksArn(path, region, accountId);
            case "cloudtrail"           -> buildCloudTrailArn(ctx, region, accountId);
            case "guardduty"            -> buildGuardDutyArn(ctx, region, accountId);
            case "config"               -> buildConfigArn(ctx, region, accountId);
            case "rds-data"             -> buildRdsDataArn(ctx, region, accountId);
            case "elasticmapreduce"     -> buildElasticMapReduceArn(ctx, region, accountId);
            case "wafv2"                -> buildWafV2Arn(ctx, region, accountId);
            case "securityhub"          -> buildSecurityHubArn(ctx, region, accountId);
            case "apigatewayv2"         -> buildApiGatewayV2Arn(ctx, region, accountId);
            case "scheduler"            -> buildSchedulerArn(ctx, path, region, accountId);
            case "kafka"                -> buildKafkaArn(ctx, path, region, accountId);
            case "pipes"                -> buildPipesArn(ctx, path, region, accountId);
            case "codebuild"            -> buildCodeBuildArn(ctx, region, accountId);
            case "codedeploy"           -> buildCodeDeployArn(ctx, region, accountId);
            case "acm"                  -> buildAcmArn(ctx, region, accountId);
            case "backup"               -> buildBackupArn(ctx, path, region, accountId);
            case "route53"              -> buildRoute53Arn(ctx, path, region, accountId);
            case "cloudfront"           -> buildCloudFrontArn(ctx, path, accountId);
            case "bedrock", "bedrock-runtime" -> buildBedrockArn(path, region);
            case "cur"                  -> buildCurArn(ctx, region, accountId);
            case "bcm-data-exports"     -> buildBcmDataExportsArn(ctx, region, accountId);
            case "transfer"             -> buildTransferArn(ctx, region, accountId);
            case "transcribe"           -> buildTranscribeArn(ctx, region, accountId);
            case "appconfig"            -> buildAppConfigArn(ctx, path, region, accountId);
            case "appconfigdata"        -> buildAppConfigDataArn(ctx, region, accountId);
            case "textract"             -> buildTextractArn(ctx, region, accountId);
            case "tagging"              -> buildTaggingArn(ctx);
            default                    -> "*";
        };
    }

    public String buildFromQueryParams(String credentialScope,
                                       MultivaluedMap<String, String> params,
                                       String region,
                                       String accountId) {
        if ("sqs".equals(credentialScope)) {
            return sqsArnFromParams(params, region, accountId);
        }
        return "*";
    }

    /**
     * Returns caller-supplied resource ARNs for tagging APIs ({@code ResourceARNList}).
     * AWS IAM uses {@code *} for tagging actions; Floci evaluates listed ARNs for CTF cross-service policies.
     */
    public List<String> buildAllTaggingResources(ContainerRequestContext ctx) {
        String operation = jsonTargetOperation(ctx);
        if ("GetTagKeys".equals(operation) || "GetTagValues".equals(operation)) {
            return List.of("*");
        }
        JsonNode node = readJsonBodyNode(ctx);
        JsonNode arnList = node.get("ResourceARNList");
        if (arnList == null || !arnList.isArray() || arnList.isEmpty()) {
            return List.of("*");
        }
        List<String> out = new ArrayList<>(arnList.size());
        for (JsonNode entry : arnList) {
            if (entry != null && entry.isTextual()) {
                String arn = entry.asText();
                if (arn.startsWith("arn:")) {
                    out.add(arn);
                }
            }
        }
        return out.isEmpty() ? List.of("*") : Collections.unmodifiableList(out);
    }

    private String buildTaggingArn(ContainerRequestContext ctx) {
        List<String> arns = buildAllTaggingResources(ctx);
        return arns.isEmpty() ? "*" : arns.getFirst();
    }

    /**
     * Builds a resource ARN from an in-process JSON request body (Step Functions / API Gateway).
     */
    public String buildFromJsonBody(String credentialScope, JsonNode body,
                                    String region, String accountId) {
        JsonNode node = body != null ? body : objectMapper.createObjectNode();
        return switch (credentialScope) {
            case "dynamodb" -> buildDynamoDbArnFromJson(node, region, accountId);
            case "sqs" -> buildSqsArnFromJson(node, region, accountId);
            case "sns" -> buildSnsArnFromJson(node, region, accountId);
            case "secretsmanager" -> buildSecretsManagerArnFromJson(node, region, accountId);
            case "kms" -> buildKmsArnFromJson(node, region, accountId);
            case "states" -> buildStatesArnFromJson(node, region, accountId);
            case "lambda" -> buildLambdaArnFromJson(node, region, accountId);
            case "ssm" -> buildSsmArnFromJson(node, region, accountId);
            case "kinesis" -> buildKinesisArnFromJson(node, region, accountId);
            case "logs" -> buildLogsArnFromJson(node, region, accountId);
            case "events" -> buildEventsArnFromJson(node, region, accountId);
            case "monitoring" -> buildCloudWatchArnFromJson(node, region, accountId);
            case "cognito-idp" -> buildCognitoArnFromJson(node, region, accountId);
            case "s3" -> buildS3ArnFromJson(node);
            case "acm" -> buildAcmArnFromJson(node, region, accountId);
            default -> "*";
        };
    }

    private String buildAcmArnFromJson(JsonNode node, String region, String accountId) {
        String certArn = firstArn(jsonText(node, "CertificateArn"));
        if (certArn != null) {
            return certArn;
        }
        return AwsArnUtils.Arn.of("acm", region, accountId, "certificate/*").toString();
    }

    private String buildS3ArnFromJson(JsonNode node) {
        String bucket = jsonText(node, "Bucket");
        String key = jsonText(node, "Key");
        if (bucket != null && !bucket.isBlank() && key != null && !key.isBlank()) {
            return AwsArnUtils.Arn.of("s3", "", "", bucket + "/" + key).toString();
        }
        if (bucket != null && !bucket.isBlank()) {
            return AwsArnUtils.Arn.of("s3", "", "", bucket).toString();
        }
        return AwsArnUtils.Arn.of("s3", "", "", "*").toString();
    }

    private String buildDynamoDbArnFromJson(JsonNode node, String region, String accountId) {
        String tableArn = firstArn(jsonText(node, "TableArn"), jsonText(node, "ResourceArn"));
        if (tableArn != null) {
            return appendDynamoDbIndexSuffix(jsonText(node, "IndexName"), tableArn);
        }
        String tableName = firstNonBlank(
                jsonText(node, "TableName"),
                jsonText(node, "GlobalTableName"),
                jsonFirstRequestItemsTableKey(node),
                partiQLTableNameFromJson(node));
        if (tableName != null && !tableName.isBlank()) {
            if (jsonText(node, "GlobalTableName") != null) {
                return AwsArnUtils.Arn.of("dynamodb", "", accountId, "global-table/" + tableName).toString();
            }
            if (tableName.startsWith("arn:")) {
                return appendDynamoDbIndexSuffix(jsonText(node, "IndexName"), tableName);
            }
            String indexName = jsonText(node, "IndexName");
            if (indexName != null && !indexName.isBlank()) {
                return AwsArnUtils.Arn.of("dynamodb", region, accountId,
                        "table/" + tableName + "/index/" + indexName).toString();
            }
            return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
    }

    private String buildSqsArnFromJson(JsonNode node, String region, String accountId) {
        MultivaluedMap<String, String> params = new jakarta.ws.rs.core.MultivaluedHashMap<>();
        String queueUrl = jsonText(node, "QueueUrl");
        if (queueUrl != null && !queueUrl.isBlank()) {
            params.add("QueueUrl", queueUrl);
        }
        String queueName = jsonText(node, "QueueName");
        if (queueName != null && !queueName.isBlank()) {
            params.add("QueueName", queueName);
        }
        return sqsArnFromParams(params, region, accountId);
    }

    private String buildSnsArnFromJson(JsonNode node, String region, String accountId) {
        String topicArn = firstArn(jsonText(node, "TopicArn"), jsonText(node, "TargetArn"));
        if (topicArn != null) {
            return topicArn;
        }
        return AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    private String buildSecretsManagerArnFromJson(JsonNode node, String region, String accountId) {
        String secretId = firstNonBlank(
                jsonText(node, "SecretId"),
                jsonText(node, "Name"),
                jsonText(node, "ARN"),
                jsonFirstArrayElement(node, "SecretIdList"));
        return secretsManagerArnFromSecretId(secretId, region, accountId);
    }

    private String buildKmsArnFromJson(JsonNode node, String region, String accountId) {
        String keyId = jsonText(node, "KeyId");
        if (keyId != null && !keyId.isBlank()) {
            if (keyId.startsWith("arn:aws:kms:")) {
                return keyId;
            }
            if (keyId.startsWith("alias/")) {
                return AwsArnUtils.Arn.of("kms", region, accountId, keyId).toString();
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
        }
        String alias = jsonText(node, "AliasName");
        if (alias != null && !alias.isBlank()) {
            if (!alias.startsWith("alias/")) {
                alias = "alias/" + alias;
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, alias).toString();
        }
        String keyFromBlob = keyIdFromCiphertextBlob(jsonText(node, "CiphertextBlob"));
        if (keyFromBlob != null) {
            if (keyFromBlob.startsWith("arn:aws:kms:")) {
                return keyFromBlob;
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyFromBlob).toString();
        }
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
    }

    private String buildStatesArnFromJson(JsonNode node, String region, String accountId) {
        String smArn = firstArn(jsonText(node, "stateMachineArn"), jsonText(node, "StateMachineArn"));
        if (smArn != null) {
            return smArn;
        }
        String executionArn = jsonText(node, "executionArn");
        if (executionArn != null) {
            return executionArn;
        }
        String activityArn = jsonText(node, "activityArn");
        if (activityArn != null) {
            return activityArn;
        }
        String name = jsonText(node, "name");
        if (name != null && !name.isBlank()) {
            return AwsArnUtils.Arn.of("states", region, accountId, "stateMachine:" + name).toString();
        }
        return AwsArnUtils.Arn.of("states", region, accountId, "stateMachine:*").toString();
    }

    private String buildLambdaArnFromJson(JsonNode node, String region, String accountId) {
        String fn = firstNonBlank(jsonText(node, "FunctionName"), jsonText(node, "functionName"));
        if (fn != null && !fn.isBlank()) {
            if (fn.contains(":")) {
                fn = fn.substring(fn.lastIndexOf(':') + 1);
            }
            return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + fn).toString();
        }
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:*").toString();
    }

    private String buildSsmArnFromJson(JsonNode node, String region, String accountId) {
        String name = firstNonBlank(jsonText(node, "Name"), jsonFirstArrayElement(node, "Names"));
        if (name == null || name.isBlank()) {
            return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
        }
        if (name.startsWith("/")) {
            name = name.substring(1);
        }
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/" + name).toString();
    }

    private String buildKinesisArnFromJson(JsonNode node, String region, String accountId) {
        String streamArn = firstArn(jsonText(node, "StreamARN"), jsonText(node, "StreamArn"));
        if (streamArn != null) {
            return streamArn;
        }
        String streamName = jsonText(node, "StreamName");
        if (streamName != null && !streamName.isBlank()) {
            return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/" + streamName).toString();
        }
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    private String buildLogsArnFromJson(JsonNode node, String region, String accountId) {
        String logGroup = jsonText(node, "logGroupName");
        if (logGroup != null && !logGroup.isBlank()) {
            return AwsArnUtils.Arn.of("logs", region, accountId, "log-group:" + logGroup).toString();
        }
        return AwsArnUtils.Arn.of("logs", region, accountId, "log-group:*").toString();
    }

    private String buildEventsArnFromJson(JsonNode node, String region, String accountId) {
        String bus = jsonText(node, "EventBusName");
        String rule = jsonText(node, "Name");
        if (bus != null && !bus.isBlank()) {
            if (rule != null && !rule.isBlank() && !"default".equals(bus)) {
                return AwsArnUtils.Arn.of("events", region, accountId, "rule/" + bus + "/" + rule).toString();
            }
            if (rule != null && !rule.isBlank()) {
                return AwsArnUtils.Arn.of("events", region, accountId, "rule/" + rule).toString();
            }
            return AwsArnUtils.Arn.of("events", region, accountId, "event-bus/" + bus).toString();
        }
        return AwsArnUtils.Arn.of("events", region, accountId, "event-bus/*").toString();
    }

    private String buildCloudWatchArnFromJson(JsonNode node, String region, String accountId) {
        String namespace = jsonText(node, "Namespace");
        if (namespace != null && !namespace.isBlank()) {
            return AwsArnUtils.Arn.of("cloudwatch", region, accountId, "metric/" + namespace + "/*").toString();
        }
        return AwsArnUtils.Arn.of("cloudwatch", region, accountId, "metric/*").toString();
    }

    private String buildCognitoArnFromJson(JsonNode node, String region, String accountId) {
        String poolId = jsonText(node, "UserPoolId");
        if (poolId != null && !poolId.isBlank()) {
            return AwsArnUtils.Arn.of("cognito-idp", region, accountId, "userpool/" + poolId).toString();
        }
        return AwsArnUtils.Arn.of("cognito-idp", region, accountId, "userpool/*").toString();
    }

    private static String jsonText(JsonNode node, String fieldName) {
        JsonNode field = node.get(fieldName);
        return field != null && field.isTextual() ? field.asText() : null;
    }

    private static String jsonFirstArrayElement(JsonNode node, String fieldName) {
        JsonNode arr = node.get(fieldName);
        if (arr != null && arr.isArray() && !arr.isEmpty() && arr.get(0).isTextual()) {
            return arr.get(0).asText();
        }
        return null;
    }

    private String jsonFirstRequestItemsTableKey(JsonNode node) {
        JsonNode requestItems = node.get("RequestItems");
        if (requestItems != null && requestItems.isObject()) {
            var names = requestItems.fieldNames();
            if (names.hasNext()) {
                return names.next();
            }
        }
        return null;
    }

    // ── S3 ──────────────────────────────────────────────────────────────────────

    private String buildS3Arn(String path) {
        String stripped = path.startsWith("/") ? path.substring(1) : path;
        if (stripped.isEmpty()) {
            return AwsArnUtils.Arn.of("s3", "", "", "*").toString();
        }
        return AwsArnUtils.Arn.of("s3", "", "", stripped).toString();
    }

    // ── Lambda ──────────────────────────────────────────────────────────────────

    private String buildLambdaArn(String path, String region, String accountId) {
        String layer = extractSegmentAfter(path, "layers");
        if (layer != null) {
            int version = layer.indexOf(':');
            String layerName = version > 0 ? layer.substring(0, version) : layer;
            return AwsArnUtils.Arn.of("lambda", region, accountId, "layer:" + layerName).toString();
        }
        String name = extractSegmentAfter(path, "functions");
        if (name == null) {
            return AwsArnUtils.Arn.of("lambda", region, accountId, "function:*").toString();
        }
        int colon = name.indexOf(':');
        if (colon > 0) {
            name = name.substring(0, colon);
        }
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + name).toString();
    }

    // ── SQS ─────────────────────────────────────────────────────────────────────

    private String buildSqsArn(ContainerRequestContext ctx, String region, String accountId) {
        MultivaluedMap<String, String> params = readFormParamMap(ctx);
        if (params.getFirst("QueueUrl") == null && params.getFirst("QueueName") == null) {
            JsonNode node = readJsonBodyNode(ctx);
            String queueUrl = jsonTextFromNode(node, "QueueUrl");
            if (queueUrl != null && !queueUrl.isBlank()) {
                params.add("QueueUrl", queueUrl);
            }
            String queueName = jsonTextFromNode(node, "QueueName");
            if (queueName != null && !queueName.isBlank()) {
                params.add("QueueName", queueName);
            }
        }
        return sqsArnFromParams(params, region, accountId);
    }

    private MultivaluedMap<String, String> readFormParamMap(ContainerRequestContext ctx) {
        MultivaluedMap<String, String> params = new jakarta.ws.rs.core.MultivaluedHashMap<>();
        String queueUrl = readFormParam(ctx, "QueueUrl");
        if (queueUrl != null) {
            params.add("QueueUrl", queueUrl);
        }
        String queueName = readFormParam(ctx, "QueueName");
        if (queueName != null) {
            params.add("QueueName", queueName);
        }
        return params;
    }

    private String sqsArnFromParams(MultivaluedMap<String, String> params, String region, String accountId) {
        String queueUrl = params == null ? null : params.getFirst("QueueUrl");
        if (queueUrl != null && queueUrl.startsWith("arn:aws:sqs:")) {
            return queueUrl.trim();
        }
        String queueName = parseSqsQueueName(queueUrl);
        String queueAccount = parseSqsAccountFromQueueUrl(queueUrl);
        String effectiveAccount = queueAccount != null ? queueAccount : accountId;
        if (queueName == null && params != null) {
            queueName = params.getFirst("QueueName");
        }
        if (queueName != null && !queueName.isBlank()) {
            return AwsArnUtils.Arn.of("sqs", region, effectiveAccount, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    /**
     * Resolves queue name from emulator queue URLs ({@code http://host:4566/account/queue}),
     * AWS queue URLs ({@code https://sqs.region.amazonaws.com/account/queue}), or bare queue
     * names. Hostname variants (localhost vs localhost.localstack.cloud) do not affect the
     * resolved name, matching {@code SqsService} URL layout.
     */
    static String parseSqsQueueName(String queueUrl) {
        if (queueUrl == null || queueUrl.isBlank()) {
            return null;
        }
        String trimmed = queueUrl.trim();
        if (trimmed.startsWith("arn:aws:sqs:")) {
            try {
                return AwsArnUtils.parse(trimmed).resource();
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }
        String path = extractQueuePath(trimmed);
        if (path != null && !path.isEmpty()) {
            String withoutLeading = path.startsWith("/") ? path.substring(1) : path;
            int slash = withoutLeading.indexOf('/');
            if (slash > 0 && slash < withoutLeading.length() - 1) {
                String name = withoutLeading.substring(slash + 1);
                if (!name.isBlank() && !name.contains("?")) {
                    return name;
                }
            }
        }
        int slash = trimmed.lastIndexOf('/');
        if (slash >= 0 && slash < trimmed.length() - 1) {
            String segment = trimmed.substring(slash + 1);
            if (!segment.isBlank() && !segment.contains("?")) {
                return segment;
            }
        }
        return trimmed.contains("/") ? null : trimmed;
    }

    /**
     * Extracts the owning account from a queue URL path ({@code /accountId/queueName}) or
     * SQS ARN, mirroring {@code SqsService} account resolution for IAM resource ARNs.
     */
    static String parseSqsAccountFromQueueUrl(String queueUrl) {
        if (queueUrl == null || queueUrl.isBlank()) {
            return null;
        }
        String trimmed = queueUrl.trim();
        if (trimmed.startsWith("arn:aws:sqs:")) {
            try {
                String account = AwsArnUtils.parse(trimmed).accountId();
                return account.isBlank() ? null : account;
            } catch (IllegalArgumentException ignored) {
                return null;
            }
        }
        String path = extractQueuePath(trimmed);
        if (path == null || path.isEmpty()) {
            return null;
        }
        String withoutLeading = path.startsWith("/") ? path.substring(1) : path;
        int slash = withoutLeading.indexOf('/');
        String candidate = slash > 0 ? withoutLeading.substring(0, slash) : withoutLeading;
        return candidate.matches("\\d{12}") ? candidate : null;
    }

    private static String extractQueuePath(String queueUrl) {
        if (queueUrl == null) {
            return null;
        }
        int schemeEnd = queueUrl.indexOf("://");
        if (schemeEnd < 0) {
            return queueUrl.contains("/") ? queueUrl : null;
        }
        int pathStart = queueUrl.indexOf('/', schemeEnd + 3);
        if (pathStart < 0) {
            return null;
        }
        return queueUrl.substring(pathStart);
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────

    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        // TopicArn first so Subscribe / ConfirmSubscription / Publish scope to the topic.
        String arn = firstArn(
                readFormParam(ctx, "TopicArn"),
                readJsonStringField(ctx, "TopicArn"),
                readFormParam(ctx, "SubscriptionArn"),
                readFormParam(ctx, "TargetArn"),
                readFormParam(ctx, "ResourceArn"),
                readFormParam(ctx, "PlatformApplicationArn"),
                readFormParam(ctx, "EndpointArn"),
                readJsonStringField(ctx, "TargetArn"));
        if (arn != null) {
            return arn;
        }
        String topicName = firstNonBlank(
                readFormParam(ctx, "Name"),
                readJsonStringField(ctx, "Name"));
        if (topicName != null && !topicName.startsWith("arn:")) {
            return AwsArnUtils.Arn.of("sns", region, accountId, topicName).toString();
        }
        return AwsArnUtils.Arn.of("sns", region, accountId, "*").toString();
    }

    // ── DynamoDB ─────────────────────────────────────────────────────────────────

    private String buildDynamoDbArn(ContainerRequestContext ctx, String region, String accountId) {
        String tableArn = firstArn(
                readJsonStringField(ctx, "TableArn"),
                readJsonStringField(ctx, "ResourceArn"));
        if (tableArn != null) {
            return appendDynamoDbIndexSuffix(readJsonStringField(ctx, "IndexName"), tableArn);
        }
        String tableName = firstNonBlank(
                readJsonStringField(ctx, "TableName"),
                readJsonStringField(ctx, "GlobalTableName"),
                readJsonFirstRequestItemsTableKey(ctx),
                partiQLTableNameFromRequest(ctx));
        if (tableName != null && !tableName.isBlank()) {
            if (readJsonStringField(ctx, "GlobalTableName") != null) {
                return AwsArnUtils.Arn.of("dynamodb", "", accountId, "global-table/" + tableName).toString();
            }
            if (tableName.startsWith("arn:")) {
                return appendDynamoDbIndexSuffix(readJsonStringField(ctx, "IndexName"), tableName);
            }
            String indexName = readJsonStringField(ctx, "IndexName");
            if (indexName != null && !indexName.isBlank()) {
                return AwsArnUtils.Arn.of("dynamodb", region, accountId,
                        "table/" + tableName + "/index/" + indexName).toString();
            }
            return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
    }

    /**
     * Extracts the first DynamoDB table name from a PartiQL {@code Statement} string.
     *
     * <p>Supports {@code SELECT}/{@code DELETE} {@code FROM} clauses, {@code INSERT INTO},
     * and {@code UPDATE} table targets per the
     * <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-reference.html">PartiQL reference</a>.
     */
    /**
     * Builds table ARNs for every PartiQL statement in a {@code BatchExecuteStatement} body.
     */
    public List<String> buildAllDynamoDbPartiQLResources(ContainerRequestContext ctx,
                                                         String region, String accountId) {
        List<String> statementTexts = readAllBatchStatementTexts(ctx);
        if (statementTexts.isEmpty()) {
            return List.of();
        }
        List<String> arns = new ArrayList<>(statementTexts.size());
        for (String statement : statementTexts) {
            arns.add(dynamoDbTableArnFromPartiQL(statement, region, accountId));
        }
        return arns;
    }

    static String extractPartiQLTableName(String statement) {
        if (statement == null || statement.isBlank()) {
            return null;
        }
        String trimmed = statement.trim();
        if (trimmed.regionMatches(true, 0, "INSERT", 0, 6)) {
            return firstRegexGroup(PARTIQL_INTO_QUOTED, trimmed, PARTIQL_INTO_IDENT, trimmed);
        }
        if (trimmed.regionMatches(true, 0, "UPDATE", 0, 6)) {
            return firstRegexGroup(PARTIQL_UPDATE_QUOTED, trimmed, PARTIQL_UPDATE_IDENT, trimmed);
        }
        return firstRegexGroup(PARTIQL_FROM_QUOTED, trimmed, PARTIQL_FROM_IDENT, trimmed);
    }

    private String partiQLTableNameFromRequest(ContainerRequestContext ctx) {
        String statement = readJsonStringField(ctx, "Statement");
        if (statement == null) {
            statement = readJsonFirstBatchStatement(ctx);
        }
        return extractPartiQLTableName(statement);
    }

    private String partiQLTableNameFromJson(JsonNode node) {
        String statement = jsonText(node, "Statement");
        if (statement == null) {
            statement = jsonFirstBatchStatement(node);
        }
        return extractPartiQLTableName(statement);
    }

    private String readJsonFirstBatchStatement(ContainerRequestContext ctx) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            return jsonFirstBatchStatement(node);
        } catch (Exception ignored) {
        }
        return null;
    }

    private static String jsonFirstBatchStatement(JsonNode node) {
        List<String> all = jsonAllBatchStatementTexts(node);
        return all.isEmpty() ? null : all.getFirst();
    }

    private List<String> readAllBatchStatementTexts(ContainerRequestContext ctx) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return List.of();
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            return jsonAllBatchStatementTexts(node);
        } catch (Exception ignored) {
        }
        return List.of();
    }

    private static List<String> jsonAllBatchStatementTexts(JsonNode node) {
        JsonNode statements = node.get("Statements");
        if (statements == null || !statements.isArray() || statements.isEmpty()) {
            return List.of();
        }
        List<String> out = new ArrayList<>(statements.size());
        for (JsonNode entry : statements) {
            if (entry != null) {
                String text = jsonText(entry, "Statement");
                if (text != null) {
                    out.add(text);
                }
            }
        }
        return Collections.unmodifiableList(out);
    }

    private static String dynamoDbTableArnFromPartiQL(String statement, String region, String accountId) {
        String tableName = extractPartiQLTableName(statement);
        if (tableName == null || tableName.isBlank()) {
            return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
        }
        if (tableName.startsWith("arn:")) {
            return tableName;
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
    }

    private static String firstRegexGroup(Pattern quoted, String quotedInput,
                                          Pattern ident, String identInput) {
        String quotedMatch = firstRegexGroup(quoted, quotedInput);
        if (quotedMatch != null) {
            return quotedMatch;
        }
        return firstRegexGroup(ident, identInput);
    }

    private static String firstRegexGroup(Pattern pattern, String input) {
        Matcher m = pattern.matcher(input);
        return m.find() ? m.group(1) : null;
    }

    private static String appendDynamoDbIndexSuffix(String indexName, String tableArn) {
        if (indexName == null || indexName.isBlank()) {
            return tableArn;
        }
        int indexMarker = tableArn.indexOf("/index/");
        String baseArn = indexMarker > 0 ? tableArn.substring(0, indexMarker) : tableArn;
        return baseArn + "/index/" + indexName;
    }

    private String readJsonFirstRequestItemsTableKey(ContainerRequestContext ctx) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode requestItems = node.get("RequestItems");
            if (requestItems != null && requestItems.isObject()) {
                var names = requestItems.fieldNames();
                if (names.hasNext()) {
                    return names.next();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    // ── Kinesis ──────────────────────────────────────────────────────────────────

    private String buildKinesisArn(ContainerRequestContext ctx, String region, String accountId) {
        String streamArn = firstArn(
                readJsonStringField(ctx, "StreamARN"),
                readJsonStringField(ctx, "StreamArn"));
        if (streamArn != null) {
            return streamArn;
        }
        String streamName = readJsonStringField(ctx, "StreamName");
        if (streamName != null && !streamName.isBlank()) {
            return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/" + streamName).toString();
        }
        return AwsArnUtils.Arn.of("kinesis", region, accountId, "stream/*").toString();
    }

    // ── Secrets Manager ──────────────────────────────────────────────────────────

    private String buildSecretsManagerArn(ContainerRequestContext ctx, String region, String accountId) {
        String secretId = firstNonBlank(
                readJsonStringField(ctx, "SecretId"),
                readJsonStringField(ctx, "Name"),
                readJsonArnField(ctx, "ARN"),
                readJsonFirstArrayElement(ctx, "SecretIdList"));
        return secretsManagerArnFromSecretId(secretId, region, accountId);
    }

    /**
     * Builds a Secrets Manager secret ARN for IAM evaluation. Uses the stored ARN (with AWS six-character
     * suffix) when the secret exists; otherwise falls back to {@code secret:name-??????} per
     * <a href="https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html">AWS IAM examples</a>.
     */
    private String secretsManagerArnFromSecretId(String secretId, String region, String accountId) {
        if (secretId == null || secretId.isBlank()) {
            return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
        }
        if (secretsManagerService != null) {
            Optional<String> storedArn = secretsManagerService.findSecretArnForIam(secretId, region);
            if (storedArn.isPresent()) {
                return storedArn.get();
            }
        }
        if (secretId.startsWith("arn:aws:secretsmanager:")) {
            return secretId;
        }
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId,
                "secret:" + secretId + SECRETS_MANAGER_IAM_SUFFIX_PLACEHOLDER).toString();
    }

    // ── SSM ──────────────────────────────────────────────────────────────────────

    private String buildSsmArn(ContainerRequestContext ctx, String region, String accountId) {
        String name = firstNonBlank(
                readJsonStringField(ctx, "Name"),
                readJsonFirstArrayElement(ctx, "Names"));
        if (name == null || name.isBlank()) {
            return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/*").toString();
        }
        if (name.startsWith("/")) {
            name = name.substring(1);
        }
        return AwsArnUtils.Arn.of("ssm", region, accountId, "parameter/" + name).toString();
    }

    // ── KMS ──────────────────────────────────────────────────────────────────────

    private String buildKmsArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String keyId = readJsonStringField(ctx, "KeyId");
        if (keyId != null && !keyId.isBlank()) {
            if (keyId.startsWith("arn:aws:kms:")) {
                return keyId;
            }
            if (keyId.startsWith("alias/")) {
                return AwsArnUtils.Arn.of("kms", region, accountId, keyId).toString();
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyId).toString();
        }
        String alias = readJsonStringField(ctx, "AliasName");
        if (alias != null && !alias.isBlank()) {
            if (!alias.startsWith("alias/")) {
                alias = "alias/" + alias;
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, alias).toString();
        }
        String pathKey = extractSegmentAfter(path, "keys");
        if (pathKey != null) {
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + pathKey).toString();
        }
        String keyFromBlob = keyIdFromCiphertextBlob(readJsonStringField(ctx, "CiphertextBlob"));
        if (keyFromBlob != null) {
            if (keyFromBlob.startsWith("arn:aws:kms:")) {
                return keyFromBlob;
            }
            return AwsArnUtils.Arn.of("kms", region, accountId, "key/" + keyFromBlob).toString();
        }
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
    }

    /**
     * Extracts CMK id embedded in Floci KMS ciphertext blobs ({@code kms:v2:KEYID:...}).
     */
    static String keyIdFromCiphertextBlob(String ciphertextBlobBase64) {
        if (ciphertextBlobBase64 == null || ciphertextBlobBase64.isBlank()) {
            return null;
        }
        try {
            String data = new String(Base64.getDecoder().decode(ciphertextBlobBase64), StandardCharsets.UTF_8);
            if (data.startsWith("kms:v2:")) {
                String[] parts = data.substring("kms:v2:".length()).split(":", 4);
                return parts.length > 0 && !parts[0].isBlank() ? parts[0] : null;
            }
            if (data.startsWith("kms:")) {
                String[] parts = data.substring("kms:".length()).split(":", 2);
                return parts.length > 0 && !parts[0].isBlank() ? parts[0] : null;
            }
        } catch (IllegalArgumentException ignored) {
            return null;
        }
        return null;
    }

    // ── IAM ────────────────────────────────────────────────────────────────────────

    private String buildIamArn(ContainerRequestContext ctx, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "PolicyArn"),
                readFormParam(ctx, "PermissionsBoundary"),
                readFormParam(ctx, "SourceArn"),
                readFormParam(ctx, "TargetArn"));
        if (arn != null) {
            return arn;
        }
        String userName = readFormParam(ctx, "UserName");
        if (userName != null && !userName.isBlank()) {
            return AwsArnUtils.Arn.of("iam", "", accountId, "user/" + userName).toString();
        }
        String groupName = readFormParam(ctx, "GroupName");
        if (groupName != null && !groupName.isBlank()) {
            return AwsArnUtils.Arn.of("iam", "", accountId, "group/" + groupName).toString();
        }
        String roleName = readFormParam(ctx, "RoleName");
        if (roleName != null && !roleName.isBlank()) {
            return AwsArnUtils.Arn.of("iam", "", accountId, "role/" + roleName).toString();
        }
        String profile = readFormParam(ctx, "InstanceProfileName");
        if (profile != null && !profile.isBlank()) {
            return AwsArnUtils.Arn.of("iam", "", accountId, "instance-profile/" + profile).toString();
        }
        return AwsArnUtils.Arn.of("iam", "", accountId, "*").toString();
    }

    // ── STS ──────────────────────────────────────────────────────────────────────

    private String buildStsArn(ContainerRequestContext ctx) {
        String roleArn = readFormParam(ctx, "RoleArn");
        return roleArn != null ? roleArn : "*";
    }

    // ── EC2 ───────────────────────────────────────────────────────────────────────

    private String buildEc2Arn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "ResourceArn"),
                readFormParam(ctx, "IamInstanceProfile.Arn"));
        if (arn != null) {
            return arn;
        }
        String resourceId = firstNonBlank(
                readFormParam(ctx, "InstanceId"),
                readFormParamPrefixed(ctx, "InstanceId"),
                readFormParam(ctx, "ResourceId"),
                readFormParamPrefixed(ctx, "ResourceId"));
        String ec2 = ec2ArnFromResourceId(resourceId, region, accountId);
        if (ec2 != null) {
            return ec2;
        }
        String vpcId = readFormParam(ctx, "VpcId");
        if (vpcId != null) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "vpc/" + vpcId).toString();
        }
        String subnetId = readFormParam(ctx, "SubnetId");
        if (subnetId != null) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "subnet/" + subnetId).toString();
        }
        String groupId = firstNonBlank(readFormParam(ctx, "GroupId"), readFormParamPrefixed(ctx, "GroupId"));
        if (groupId != null) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "security-group/" + groupId).toString();
        }
        String volumeId = firstNonBlank(readFormParam(ctx, "VolumeId"), readFormParamPrefixed(ctx, "VolumeId"));
        if (volumeId != null) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "volume/" + volumeId).toString();
        }
        String imageId = readFormParam(ctx, "ImageId");
        if (imageId != null) {
            return AwsArnUtils.Arn.of("ec2", region, "", "image/" + imageId).toString();
        }
        return AwsArnUtils.Arn.of("ec2", region, accountId, "*").toString();
    }

    private static String ec2ArnFromResourceId(String resourceId, String region, String accountId) {
        if (resourceId == null || resourceId.isBlank()) {
            return null;
        }
        if (resourceId.startsWith("arn:")) {
            return resourceId;
        }
        if (resourceId.startsWith("i-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "instance/" + resourceId).toString();
        }
        if (resourceId.startsWith("vol-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "volume/" + resourceId).toString();
        }
        if (resourceId.startsWith("vpc-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "vpc/" + resourceId).toString();
        }
        if (resourceId.startsWith("subnet-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "subnet/" + resourceId).toString();
        }
        if (resourceId.startsWith("sg-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "security-group/" + resourceId).toString();
        }
        if (resourceId.startsWith("eni-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "network-interface/" + resourceId).toString();
        }
        if (resourceId.startsWith("snap-")) {
            return AwsArnUtils.Arn.of("ec2", region, accountId, "snapshot/" + resourceId).toString();
        }
        return null;
    }

    // ── CloudFormation ───────────────────────────────────────────────────────────

    private String buildCloudFormationArn(ContainerRequestContext ctx, String region, String accountId) {
        String stackName = firstNonBlank(
                readFormParam(ctx, "StackName"),
                readFormParam(ctx, "StackId"));
        if (stackName != null && !stackName.isBlank()) {
            if (stackName.startsWith("arn:")) {
                return stackName;
            }
            // IAM policies commonly scope stack/{name}/* (UUID suffix varies per stack).
            return AwsArnUtils.Arn.of("cloudformation", region, accountId,
                    "stack/" + stackName + "/*").toString();
        }
        return AwsArnUtils.Arn.of("cloudformation", region, accountId, "stack/*/*").toString();
    }

    // ── ElastiCache ──────────────────────────────────────────────────────────────

    private String buildElastiCacheArn(ContainerRequestContext ctx, String region, String accountId) {
        String replicationGroupId = readFormParam(ctx, "ReplicationGroupId");
        if (replicationGroupId != null) {
            return AwsArnUtils.Arn.of("elasticache", region, accountId,
                    "replicationgroup:" + replicationGroupId).toString();
        }
        String clusterId = readFormParam(ctx, "CacheClusterId");
        if (clusterId != null) {
            return AwsArnUtils.Arn.of("elasticache", region, accountId, "cluster:" + clusterId).toString();
        }
        String userId = readFormParam(ctx, "UserId");
        if (userId != null) {
            return AwsArnUtils.Arn.of("elasticache", region, accountId, "user:" + userId).toString();
        }
        return AwsArnUtils.Arn.of("elasticache", region, accountId, "*").toString();
    }

    // ── RDS / Neptune ───────────────────────────────────────────────────────────

    private String buildRdsArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = readFormParam(ctx, "DBClusterArn");
        if (arn != null) {
            return arn;
        }
        String clusterId = readFormParam(ctx, "DBClusterIdentifier");
        if (clusterId != null) {
            return AwsArnUtils.Arn.of("rds", region, accountId, "cluster:" + clusterId).toString();
        }
        String instanceId = readFormParam(ctx, "DBInstanceIdentifier");
        if (instanceId != null) {
            return AwsArnUtils.Arn.of("rds", region, accountId, "db:" + instanceId).toString();
        }
        String paramGroup = readFormParam(ctx, "DBParameterGroupName");
        if (paramGroup != null) {
            return AwsArnUtils.Arn.of("rds", region, accountId, "pg:" + paramGroup).toString();
        }
        return AwsArnUtils.Arn.of("rds", region, accountId, "*").toString();
    }

    // ── SES (Query scope "email") ───────────────────────────────────────────────

    private String buildSesArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "TemplateArn"),
                readFormParamPrefixed(ctx, "EventDestination.SNSDestination.TopicARN"),
                readFormParamPrefixed(ctx, "EventDestination.KinesisFirehoseDestination.DeliveryStreamARN"));
        if (arn != null) {
            return arn;
        }
        String configSet = firstNonBlank(
                readFormParam(ctx, "ConfigurationSetName"),
                readFormParamPrefixed(ctx, "ConfigurationSet.Name"));
        if (configSet != null) {
            return AwsArnUtils.Arn.of("ses", region, accountId, "configuration-set/" + configSet).toString();
        }
        String template = firstNonBlank(
                readFormParam(ctx, "TemplateName"),
                readFormParamPrefixed(ctx, "Template.TemplateName"));
        if (template != null) {
            return AwsArnUtils.Arn.of("ses", region, accountId, "template/" + template).toString();
        }
        String identity = firstNonBlank(
                readFormParam(ctx, "Identity"),
                readFormParam(ctx, "EmailAddress"),
                readFormParam(ctx, "Domain"));
        if (identity != null) {
            return AwsArnUtils.Arn.of("ses", region, accountId, "identity/" + identity).toString();
        }
        return AwsArnUtils.Arn.of("ses", region, accountId, "*").toString();
    }

    // ── CloudWatch (monitoring) ──────────────────────────────────────────────────

    private String buildCloudWatchArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "ResourceARN"),
                readFormParamPrefixed(ctx, "ResourceARN"),
                readFormParamPrefixed(ctx, "AlarmActions"),
                readFormParamPrefixed(ctx, "OKActions"));
        if (arn != null) {
            return arn;
        }
        String alarm = firstNonBlank(
                readFormParam(ctx, "AlarmName"),
                readFormParamPrefixed(ctx, "AlarmName"));
        if (alarm != null) {
            return AwsArnUtils.Arn.of("cloudwatch", region, accountId, "alarm:" + alarm).toString();
        }
        return AwsArnUtils.Arn.of("cloudwatch", region, accountId, "alarm:*").toString();
    }

    // ── ELBv2 ────────────────────────────────────────────────────────────────────

    private String buildElbArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "LoadBalancerArn"),
                readFormParamPrefixed(ctx, "LoadBalancerArn"),
                readFormParam(ctx, "TargetGroupArn"),
                readFormParamPrefixed(ctx, "TargetGroupArn"),
                readFormParam(ctx, "ListenerArn"),
                readFormParam(ctx, "RuleArn"),
                readFormParamPrefixed(ctx, "ResourceArn"),
                readFormParam(ctx, "CertificateArn"));
        if (arn != null) {
            return arn;
        }
        return AwsArnUtils.Arn.of("elasticloadbalancing", region, accountId, "*").toString();
    }

    // ── Auto Scaling ───────────────────────────────────────────────────────────

    private String buildAutoScalingArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParamPrefixed(ctx, "TargetGroupARN"),
                readFormParam(ctx, "NotificationTargetARN"));
        if (arn != null) {
            return arn;
        }
        String asg = readFormParam(ctx, "AutoScalingGroupName");
        if (asg != null) {
            return AwsArnUtils.Arn.of("autoscaling", region, accountId,
                    "autoScalingGroup:*:autoScalingGroupName/" + asg).toString();
        }
        String instanceId = firstNonBlank(
                readFormParam(ctx, "InstanceId"),
                readFormParamPrefixed(ctx, "InstanceId"));
        String ec2 = ec2ArnFromResourceId(instanceId, region, accountId);
        if (ec2 != null) {
            return ec2;
        }
        return AwsArnUtils.Arn.of("autoscaling", region, accountId, "*").toString();
    }

    // ── CloudWatch Logs ──────────────────────────────────────────────────────────

    private String buildLogsArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readJsonStringField(ctx, "destinationArn"),
                readJsonStringField(ctx, "DestinationArn"));
        if (arn != null) {
            return arn;
        }
        String logGroup = readJsonStringField(ctx, "logGroupName");
        if (logGroup != null && !logGroup.isBlank()) {
            String stream = readJsonStringField(ctx, "logStreamName");
            if (stream != null && !stream.isBlank()) {
                return AwsArnUtils.Arn.of("logs", region, accountId,
                        "log-group:" + logGroup + ":log-stream:" + stream).toString();
            }
            return AwsArnUtils.Arn.of("logs", region, accountId, "log-group:" + logGroup).toString();
        }
        return AwsArnUtils.Arn.of("logs", region, accountId, "log-group:*").toString();
    }

    // ── EventBridge ───────────────────────────────────────────────────────────────

    private String buildEventsArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readJsonStringField(ctx, "EventBusArn"),
                readJsonArnField(ctx, "EventBusArn"));
        if (arn != null) {
            return arn;
        }
        String bus = firstNonBlank(
                readJsonStringField(ctx, "EventBusName"),
                readJsonStringField(ctx, "Name"));
        String rule = readJsonStringField(ctx, "Rule");
        if (bus != null && !bus.isBlank()) {
            if (rule != null && !rule.isBlank() && !"default".equals(bus)) {
                return AwsArnUtils.Arn.of("events", region, accountId, "rule/" + bus + "/" + rule).toString();
            }
            if (rule != null && !rule.isBlank()) {
                return AwsArnUtils.Arn.of("events", region, accountId, "rule/" + rule).toString();
            }
            return AwsArnUtils.Arn.of("events", region, accountId, "event-bus/" + bus).toString();
        }
        return AwsArnUtils.Arn.of("events", region, accountId, "event-bus/*").toString();
    }

    // ── Step Functions ───────────────────────────────────────────────────────────

    private String buildStatesArn(ContainerRequestContext ctx, String region, String accountId) {
        String smArn = firstArn(
                readJsonStringField(ctx, "stateMachineArn"),
                readJsonStringField(ctx, "StateMachineArn"));
        if (smArn != null) {
            return smArn;
        }
        String executionArn = readJsonStringField(ctx, "executionArn");
        if (executionArn != null) {
            return executionArn;
        }
        String activityArn = readJsonStringField(ctx, "activityArn");
        if (activityArn != null) {
            return activityArn;
        }
        String name = readJsonStringField(ctx, "name");
        if (name != null && !name.isBlank()) {
            return AwsArnUtils.Arn.of("states", region, accountId, "stateMachine:" + name).toString();
        }
        return AwsArnUtils.Arn.of("states", region, accountId, "stateMachine:*").toString();
    }

    // ── ECR ──────────────────────────────────────────────────────────────────────

    private String buildEcrArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(readJsonStringField(ctx, "repositoryArn"));
        if (arn != null) {
            return arn;
        }
        String repo = readJsonStringField(ctx, "repositoryName");
        if (repo != null && !repo.isBlank()) {
            String registryAccount = firstNonBlank(readJsonStringField(ctx, "registryId"), accountId);
            return AwsArnUtils.Arn.of("ecr", region, registryAccount, "repository/" + repo).toString();
        }
        return AwsArnUtils.Arn.of("ecr", region, accountId, "repository/*").toString();
    }

    // ── ECS ──────────────────────────────────────────────────────────────────────

    private String buildEcsArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readJsonStringField(ctx, "taskDefinitionArn"),
                readJsonStringField(ctx, "serviceArn"),
                readJsonArnField(ctx, "taskArn"));
        if (arn != null) {
            return arn;
        }
        String cluster = firstNonBlank(
                readJsonStringField(ctx, "cluster"),
                readJsonStringField(ctx, "clusterName"));
        String service = firstNonBlank(
                readJsonStringField(ctx, "service"),
                readJsonStringField(ctx, "serviceName"));
        if (cluster != null && service != null) {
            return AwsArnUtils.Arn.of("ecs", region, accountId, "service/" + cluster + "/" + service).toString();
        }
        if (cluster != null) {
            return AwsArnUtils.Arn.of("ecs", region, accountId, "cluster/" + cluster).toString();
        }
        String family = readJsonStringField(ctx, "family");
        if (family != null) {
            return AwsArnUtils.Arn.of("ecs", region, accountId, "task-definition/" + family + ":*").toString();
        }
        return AwsArnUtils.Arn.of("ecs", region, accountId, "*").toString();
    }

    // ── Firehose ─────────────────────────────────────────────────────────────────

    private String buildFirehoseArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = readJsonStringField(ctx, "DeliveryStreamARN");
        if (arn != null) {
            return arn;
        }
        String name = readJsonStringField(ctx, "DeliveryStreamName");
        if (name != null && !name.isBlank()) {
            return AwsArnUtils.Arn.of("firehose", region, accountId, "deliverystream/" + name).toString();
        }
        return AwsArnUtils.Arn.of("firehose", region, accountId, "deliverystream/*").toString();
    }

    // ── Cognito ──────────────────────────────────────────────────────────────────

    private String buildCognitoArn(ContainerRequestContext ctx, String region, String accountId) {
        String poolId = readJsonStringField(ctx, "UserPoolId");
        if (poolId != null && !poolId.isBlank()) {
            return AwsArnUtils.Arn.of("cognito-idp", region, accountId, "userpool/" + poolId).toString();
        }
        return AwsArnUtils.Arn.of("cognito-idp", region, accountId, "userpool/*").toString();
    }

    // ── API Gateway (control plane) ─────────────────────────────────────────────

    private String buildApiGatewayArn(ContainerRequestContext ctx, String path, String region) {
        Matcher m = API_GW_REST_API.matcher(path);
        if (m.find()) {
            return "arn:aws:apigateway:" + region + "::/restapis/" + m.group(1);
        }
        String apiId = readJsonStringField(ctx, "restApiId");
        if (apiId != null) {
            return "arn:aws:apigateway:" + region + "::/restapis/" + apiId;
        }
        return "arn:aws:apigateway:" + region + "::/*";
    }

    // ── Glue ─────────────────────────────────────────────────────────────────────

    private String buildGlueArn(ContainerRequestContext ctx, String region, String accountId) {
        String catalogId = firstNonBlank(
                readJsonStringField(ctx, "CatalogId"),
                accountId);
        String database = readJsonStringField(ctx, "DatabaseName");
        String table = readJsonStringField(ctx, "TableName");
        if (database != null && table != null) {
            return AwsArnUtils.Arn.of("glue", region, accountId,
                    "table/" + table + "/" + database).toString();
        }
        if (database != null) {
            return AwsArnUtils.Arn.of("glue", region, accountId, "database/" + database).toString();
        }
        return AwsArnUtils.Arn.of("glue", region, catalogId, "catalog").toString();
    }

    // ── Athena ───────────────────────────────────────────────────────────────────

    private String buildAthenaArn(ContainerRequestContext ctx, String region, String accountId) {
        String executionId = readJsonStringField(ctx, "QueryExecutionId");
        if (executionId != null) {
            return AwsArnUtils.Arn.of("athena", region, accountId,
                    "query-execution/" + executionId).toString();
        }
        String workGroup = firstNonBlank(
                readJsonStringField(ctx, "WorkGroup"),
                readJsonStringField(ctx, "Name"));
        if (workGroup != null && !workGroup.isBlank()) {
            return AwsArnUtils.Arn.of("athena", region, accountId, "workgroup/" + workGroup).toString();
        }
        return AwsArnUtils.Arn.of("athena", region, accountId, "workgroup/*").toString();
    }

    // ── OpenSearch (SigV4 scope "es") ────────────────────────────────────────────

    private String buildOpenSearchArn(String path, String region, String accountId) {
        String domain = extractSegmentAfter(path, "domain");
        if (domain != null) {
            return AwsArnUtils.Arn.of("es", region, accountId, "domain/" + domain).toString();
        }
        return AwsArnUtils.Arn.of("es", region, accountId, "domain/*").toString();
    }

    // ── EKS ──────────────────────────────────────────────────────────────────────

    private static final Pattern EKS_CLUSTER =
            Pattern.compile("/clusters/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern EKS_NODEGROUP =
            Pattern.compile("/clusters/([^/]+)/node-groups/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildEksArn(String path, String region, String accountId) {
        if (path == null || path.isBlank()) {
            return AwsArnUtils.Arn.of("eks", region, accountId, "cluster/*").toString();
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        Matcher ng = EKS_NODEGROUP.matcher(normalized);
        if (ng.find()) {
            return AwsArnUtils.Arn.of("eks", region, accountId,
                    "nodegroup/" + ng.group(1) + "/" + ng.group(2) + "/*").toString();
        }
        if (normalized.matches(".*/node-groups/?$")) {
            Matcher clusterForNg = EKS_CLUSTER.matcher(normalized);
            if (clusterForNg.find()) {
                return AwsArnUtils.Arn.of("eks", region, accountId,
                        "nodegroup/" + clusterForNg.group(1) + "/*").toString();
            }
        }
        Matcher cluster = EKS_CLUSTER.matcher(normalized);
        if (cluster.find()) {
            return AwsArnUtils.Arn.of("eks", region, accountId, "cluster/" + cluster.group(1)).toString();
        }
        return AwsArnUtils.Arn.of("eks", region, accountId, "cluster/*").toString();
    }

    // ── AppSync ──────────────────────────────────────────────────────────────────

    private static final Pattern APPSYNC_API = Pattern.compile("/v1/apis/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildAppSyncArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        if (path == null || path.isBlank()) {
            return AwsArnUtils.Arn.of("appsync", region, accountId, "apis/*").toString();
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        Matcher m = APPSYNC_API.matcher(normalized);
        if (m.find()) {
            return AwsArnUtils.Arn.of("appsync", region, accountId, "apis/" + m.group(1)).toString();
        }
        return AwsArnUtils.Arn.of("appsync", region, accountId, "apis/*").toString();
    }

    // ── CloudTrail ───────────────────────────────────────────────────────────────

    private String buildCloudTrailArn(ContainerRequestContext ctx, String region, String accountId) {
        String trailArn = firstArn(
                readJsonStringField(ctx, "TrailARN"),
                readJsonArnField(ctx, "TrailARN"));
        if (trailArn != null) {
            return trailArn;
        }
        String name = firstNonBlank(
                readJsonStringField(ctx, "Name"),
                readJsonStringField(ctx, "TrailName"));
        if (name != null && !name.isBlank()) {
            return AwsArnUtils.Arn.of("cloudtrail", region, accountId, "trail/" + name).toString();
        }
        return AwsArnUtils.Arn.of("cloudtrail", region, accountId, "trail/*").toString();
    }

    // ── GuardDuty ────────────────────────────────────────────────────────────────

    private String buildGuardDutyArn(ContainerRequestContext ctx, String region, String accountId) {
        String detectorId = readJsonStringField(ctx, "DetectorId");
        if (detectorId != null && !detectorId.isBlank()) {
            return AwsArnUtils.Arn.of("guardduty", region, accountId, "detector/" + detectorId).toString();
        }
        return AwsArnUtils.Arn.of("guardduty", region, accountId, "detector/*").toString();
    }

    // ── AWS Config ───────────────────────────────────────────────────────────────

    private String buildConfigArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readJsonStringField(ctx, "ResourceArn"),
                readJsonStringField(ctx, "resourceArn"));
        if (arn != null) {
            return arn;
        }
        String ruleName = firstNonBlank(
                readJsonStringField(ctx, "ConfigRuleName"),
                readNestedJsonStringField(ctx, "ConfigRule", "ConfigRuleName"));
        if (ruleName != null && !ruleName.isBlank()) {
            return AwsArnUtils.Arn.of("config", region, accountId, "config-rule/" + ruleName).toString();
        }
        return AwsArnUtils.Arn.of("config", region, accountId, "config-rule/*").toString();
    }

    private String readNestedJsonStringField(ContainerRequestContext ctx, String objectField, String fieldName) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode parent = node.get(objectField);
            if (parent != null && parent.isObject()) {
                JsonNode field = parent.get(fieldName);
                if (field != null && field.isTextual()) {
                    return field.asText();
                }
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    // ── RDS Data API (IAM resource uses rds:cluster/db prefix) ───────────────────

    private String buildRdsDataArn(ContainerRequestContext ctx, String region, String accountId) {
        String resourceArn = readJsonStringField(ctx, "resourceArn");
        if (resourceArn != null && resourceArn.startsWith("arn:")) {
            return resourceArn;
        }
        if (resourceArn != null && !resourceArn.isBlank()) {
            return AwsArnUtils.Arn.of("rds", region, accountId, "cluster:" + resourceArn).toString();
        }
        return AwsArnUtils.Arn.of("rds", region, accountId, "cluster:*").toString();
    }

    // ── EMR (elasticmapreduce) ───────────────────────────────────────────────────

    private String buildElasticMapReduceArn(ContainerRequestContext ctx, String region, String accountId) {
        List<String> all = buildAllEmrClusterResources(ctx, region, accountId);
        if (all.isEmpty()) {
            return "*";
        }
        return all.getFirst();
    }

    /**
     * Builds cluster ARNs for every {@code JobFlowIds[]} entry (TerminateJobFlows, Set*).
     */
    public List<String> buildAllEmrClusterResources(ContainerRequestContext ctx,
                                                    String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        if ("RunJobFlow".equals(operation)
                || "CreateSecurityConfiguration".equals(operation)
                || "ListClusters".equals(operation)
                || "ListSecurityConfigurations".equals(operation)) {
            return List.of("*");
        }

        JsonNode jobFlowIds = node.get("JobFlowIds");
        if (jobFlowIds != null && jobFlowIds.isArray() && !jobFlowIds.isEmpty()) {
            List<String> arns = new ArrayList<>(jobFlowIds.size());
            for (JsonNode id : jobFlowIds) {
                if (id != null && id.isTextual()) {
                    arns.add(emrClusterArn(id.asText(), region, accountId));
                }
            }
            return arns.isEmpty()
                    ? List.of(AwsArnUtils.Arn.of("elasticmapreduce", region, accountId, "cluster/*").toString())
                    : Collections.unmodifiableList(arns);
        }

        String arn = firstArn(
                jsonTextFromNode(node, "ClusterArn"),
                jsonTextFromNode(node, "ResourceArn"));
        if (arn != null) {
            return List.of(arn);
        }

        String clusterId = firstNonBlank(
                jsonTextFromNode(node, "ClusterId"),
                jsonTextFromNode(node, "JobFlowId"),
                jsonTextFromNode(node, "ResourceId"));
        if (clusterId != null && !clusterId.isBlank()) {
            if (clusterId.startsWith("arn:")) {
                return List.of(clusterId);
            }
            return List.of(emrClusterArn(clusterId, region, accountId));
        }

        if ("DescribeSecurityConfiguration".equals(operation)
                || "DeleteSecurityConfiguration".equals(operation)) {
            return List.of("*");
        }

        return List.of(AwsArnUtils.Arn.of("elasticmapreduce", region, accountId, "cluster/*").toString());
    }

    private static String emrClusterArn(String clusterId, String region, String accountId) {
        return AwsArnUtils.Arn.of("elasticmapreduce", region, accountId, "cluster/" + clusterId).toString();
    }

    // ── WAFv2 ───────────────────────────────────────────────────────────────────

    private String buildWafV2Arn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        String directArn = firstArn(
                jsonTextFromNode(node, "ARN"),
                jsonTextFromNode(node, "Arn"),
                jsonTextFromNode(node, "WebACLArn"),
                jsonTextFromNode(node, "ResourceArn"),
                jsonTextFromNode(node, "ResourceARN"));
        if (directArn != null) {
            return directArn;
        }

        JsonNode logging = node.get("LoggingConfiguration");
        if (logging != null && logging.isObject()) {
            String logResource = jsonTextFromNode(logging, "ResourceArn");
            if (logResource != null && logResource.startsWith("arn:")) {
                return logResource;
            }
        }

        if (operation != null && (operation.startsWith("List") || "CheckCapacity".equals(operation))) {
            return "*";
        }

        String scope = jsonTextFromNode(node, "Scope");
        String scopePrefix = wafV2ScopePrefix(scope);
        String arnRegion = wafV2ArnRegion(scope, region);

        if (operation != null) {
            String wafType = wafV2ResourceType(operation);
            if (wafType != null) {
                String name = jsonTextFromNode(node, "Name");
                String id = jsonTextFromNode(node, "Id");
                if (name != null && !name.isBlank() && id != null && !id.isBlank()) {
                    return AwsArnUtils.Arn.of("wafv2", arnRegion, accountId,
                            scopePrefix + "/" + wafType + "/" + name + "/" + id).toString();
                }
                if (id != null && !id.isBlank()) {
                    return AwsArnUtils.Arn.of("wafv2", arnRegion, accountId,
                            scopePrefix + "/" + wafType + "/*/" + id).toString();
                }
                if (name != null && !name.isBlank()) {
                    return AwsArnUtils.Arn.of("wafv2", arnRegion, accountId,
                            scopePrefix + "/" + wafType + "/" + name + "/*").toString();
                }
                return AwsArnUtils.Arn.of("wafv2", arnRegion, accountId,
                        scopePrefix + "/" + wafType + "/*").toString();
            }
        }

        return AwsArnUtils.Arn.of("wafv2", region, accountId, "*").toString();
    }

    private static String wafV2ScopePrefix(String scope) {
        if (scope == null || scope.isBlank()) {
            return "regional";
        }
        return "CLOUDFRONT".equalsIgnoreCase(scope) ? "global" : "regional";
    }

    private static String wafV2ArnRegion(String scope, String region) {
        return "CLOUDFRONT".equalsIgnoreCase(scope) ? "us-east-1" : region;
    }

    private static String wafV2ResourceType(String operation) {
        if (operation.contains("WebACL")) {
            return "webacl";
        }
        if (operation.contains("IPSet")) {
            return "ipset";
        }
        if (operation.contains("RuleGroup")) {
            return "rulegroup";
        }
        if (operation.contains("RegexPatternSet")) {
            return "regexpatternset";
        }
        return null;
    }

    // ── Security Hub ─────────────────────────────────────────────────────────────

    private String buildSecurityHubArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        if ("BatchImportFindings".equals(operation) || "BatchUpdateFindings".equals(operation)) {
            JsonNode findings = node.get("Findings");
            if (findings != null && findings.isArray() && !findings.isEmpty()) {
                String productArn = jsonTextFromNode(findings.get(0), "ProductArn");
                if (productArn != null && productArn.startsWith("arn:")) {
                    return productArn;
                }
            }
        }

        return AwsArnUtils.Arn.of("securityhub", region, accountId, "hub/default").toString();
    }

    // ── API Gateway v2 ───────────────────────────────────────────────────────────

    private String buildApiGatewayV2Arn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String apiId = jsonTextFromNode(node, "ApiId");
        if (apiId != null && !apiId.isBlank()) {
            return "arn:aws:apigateway:" + region + "::/apis/" + apiId;
        }
        return "arn:aws:apigateway:" + region + "::/apis/*";
    }

    // ── EventBridge Scheduler ────────────────────────────────────────────────────

    private static final Pattern SCHEDULER_SCHEDULE =
            Pattern.compile("/schedules/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern SCHEDULER_GROUP =
            Pattern.compile("/schedule-groups/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildSchedulerArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String scheduleName = firstNonBlank(
                jsonTextFromNode(node, "Name"),
                extractPathSegment(path, SCHEDULER_SCHEDULE));
        String groupName = firstNonBlank(
                jsonTextFromNode(node, "GroupName"),
                ctx.getUriInfo().getQueryParameters().getFirst("groupName"),
                "default");
        if (scheduleName != null && !scheduleName.isBlank()) {
            return AwsArnUtils.Arn.of("scheduler", region, accountId,
                    "schedule/" + groupName + "/" + scheduleName).toString();
        }
        String groupOnly = extractPathSegment(path, SCHEDULER_GROUP);
        if (groupOnly != null && !groupOnly.isBlank()) {
            return AwsArnUtils.Arn.of("scheduler", region, accountId,
                    "schedule-group/" + groupOnly).toString();
        }
        return AwsArnUtils.Arn.of("scheduler", region, accountId, "schedule/*").toString();
    }

    // ── MSK (kafka) ──────────────────────────────────────────────────────────────

    private String buildKafkaArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String clusterArn = extractMskClusterArn(path);
        if (clusterArn != null) {
            return clusterArn;
        }
        String clusterName = readJsonStringField(ctx, "clusterName");
        if (clusterName != null && !clusterName.isBlank()) {
            return AwsArnUtils.Arn.of("kafka", region, accountId, "cluster/" + clusterName + "/*").toString();
        }
        return AwsArnUtils.Arn.of("kafka", region, accountId, "cluster/*").toString();
    }

    private static String extractMskClusterArn(String path) {
        if (path == null || path.isBlank()) {
            return null;
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        for (String marker : List.of("/v1/clusters/", "/api/v2/clusters/")) {
            int idx = normalized.indexOf(marker);
            if (idx >= 0) {
                String rest = normalized.substring(idx + marker.length());
                if (rest.startsWith("arn:")) {
                    int bootstrap = rest.indexOf("/bootstrap-brokers");
                    String arn = bootstrap > 0 ? rest.substring(0, bootstrap) : rest;
                    if (arn.endsWith("/")) {
                        arn = arn.substring(0, arn.length() - 1);
                    }
                    try {
                        return URLDecoder.decode(arn, StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException e) {
                        return arn;
                    }
                }
                int slash = rest.indexOf('/');
                String candidate = slash > 0 ? rest.substring(0, slash) : rest;
                if (candidate.startsWith("arn:")) {
                    try {
                        return URLDecoder.decode(candidate, StandardCharsets.UTF_8);
                    } catch (IllegalArgumentException e) {
                        return candidate;
                    }
                }
            }
        }
        return null;
    }

    // ── EventBridge Pipes ────────────────────────────────────────────────────────

    private static final Pattern PIPES_NAME =
            Pattern.compile("/v1/pipes/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildPipesArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String name = firstNonBlank(
                readJsonStringField(ctx, "Name"),
                extractPathSegment(path, PIPES_NAME));
        if (name != null && !name.isBlank()) {
            return AwsArnUtils.Arn.of("pipes", region, accountId, "pipe/" + name).toString();
        }
        return AwsArnUtils.Arn.of("pipes", region, accountId, "pipe/*").toString();
    }

    // ── CodeBuild ────────────────────────────────────────────────────────────────

    private String buildCodeBuildArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String project = firstNonBlank(
                jsonTextFromNode(node, "projectName"),
                jsonTextFromNode(node, "ProjectName"));
        if (project != null && !project.isBlank()) {
            return AwsArnUtils.Arn.of("codebuild", region, accountId, "project/" + project).toString();
        }
        return AwsArnUtils.Arn.of("codebuild", region, accountId, "project/*").toString();
    }

    // ── CodeDeploy ───────────────────────────────────────────────────────────────

    private String buildCodeDeployArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String app = jsonTextFromNode(node, "applicationName");
        String group = jsonTextFromNode(node, "deploymentGroupName");
        if (app != null && group != null) {
            return AwsArnUtils.Arn.of("codedeploy", region, accountId,
                    "deploymentgroup:" + app + "/" + group).toString();
        }
        if (app != null && !app.isBlank()) {
            return AwsArnUtils.Arn.of("codedeploy", region, accountId, "application:" + app).toString();
        }
        return AwsArnUtils.Arn.of("codedeploy", region, accountId, "*").toString();
    }

    // ── ACM ──────────────────────────────────────────────────────────────────────

    private String buildAcmArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(readJsonStringField(ctx, "CertificateArn"));
        if (arn != null) {
            return arn;
        }
        return AwsArnUtils.Arn.of("acm", region, accountId, "certificate/*").toString();
    }

    // ── AWS Backup ───────────────────────────────────────────────────────────────

    private static final Pattern BACKUP_VAULT =
            Pattern.compile("/backup-vaults/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildBackupArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String vaultArn = firstArn(
                jsonTextFromNode(node, "BackupVaultArn"),
                jsonTextFromNode(node, "DestinationBackupVaultArn"));
        if (vaultArn != null) {
            return vaultArn;
        }
        String resourceArn = jsonTextFromNode(node, "ResourceArn");
        if (resourceArn != null && resourceArn.startsWith("arn:")) {
            return resourceArn;
        }
        String vaultName = firstNonBlank(
                jsonTextFromNode(node, "BackupVaultName"),
                extractPathSegment(path, BACKUP_VAULT));
        if (vaultName != null && !vaultName.isBlank()) {
            return AwsArnUtils.Arn.of("backup", region, accountId, "backup-vault:" + vaultName).toString();
        }
        return AwsArnUtils.Arn.of("backup", region, accountId, "backup-vault:*").toString();
    }

    // ── CloudFront ───────────────────────────────────────────────────────────────

    private static final Pattern CF_DISTRIBUTION =
            Pattern.compile("/distribution/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CF_CACHE_POLICY =
            Pattern.compile("/cache-policy/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CF_ORIGIN_REQUEST_POLICY =
            Pattern.compile("/origin-request-policy/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CF_RESPONSE_HEADERS_POLICY =
            Pattern.compile("/response-headers-policy/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CF_ORIGIN_ACCESS_CONTROL =
            Pattern.compile("/origin-access-control/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern CF_FUNCTION =
            Pattern.compile("/function/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildCloudFrontArn(ContainerRequestContext ctx, String path, String accountId) {
        if (path != null && path.contains("/tagging")) {
            String resource = ctx.getUriInfo().getQueryParameters().getFirst("Resource");
            if (resource != null && !resource.isBlank() && resource.startsWith("arn:")) {
                return resource;
            }
        }

        String distributionId = extractPathSegment(path, CF_DISTRIBUTION);
        if (distributionId != null && !distributionId.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "distribution/" + distributionId).toString();
        }
        String cachePolicyId = extractPathSegment(path, CF_CACHE_POLICY);
        if (cachePolicyId != null && !cachePolicyId.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "cache-policy/" + cachePolicyId).toString();
        }
        String orpId = extractPathSegment(path, CF_ORIGIN_REQUEST_POLICY);
        if (orpId != null && !orpId.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "origin-request-policy/" + orpId).toString();
        }
        String rhpId = extractPathSegment(path, CF_RESPONSE_HEADERS_POLICY);
        if (rhpId != null && !rhpId.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "response-headers-policy/" + rhpId).toString();
        }
        String oacId = extractPathSegment(path, CF_ORIGIN_ACCESS_CONTROL);
        if (oacId != null && !oacId.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "origin-access-control/" + oacId).toString();
        }
        String functionName = extractPathSegment(path, CF_FUNCTION);
        if (functionName != null && !functionName.isBlank()) {
            return AwsArnUtils.Arn.of("cloudfront", "", accountId, "function/" + functionName).toString();
        }

        if (path != null) {
            String lower = path.toLowerCase();
            if (lower.contains("/cache-policy")) {
                return AwsArnUtils.Arn.of("cloudfront", "", accountId, "cache-policy/*").toString();
            }
            if (lower.contains("/origin-request-policy")) {
                return AwsArnUtils.Arn.of("cloudfront", "", accountId, "origin-request-policy/*").toString();
            }
            if (lower.contains("/response-headers-policy")) {
                return AwsArnUtils.Arn.of("cloudfront", "", accountId, "response-headers-policy/*").toString();
            }
            if (lower.contains("/origin-access-control")) {
                return AwsArnUtils.Arn.of("cloudfront", "", accountId, "origin-access-control/*").toString();
            }
            if (lower.contains("/function")) {
                return AwsArnUtils.Arn.of("cloudfront", "", accountId, "function/*").toString();
            }
        }
        return AwsArnUtils.Arn.of("cloudfront", "", accountId, "distribution/*").toString();
    }

    // ── Bedrock Runtime ──────────────────────────────────────────────────────────

    private static final Pattern BEDROCK_MODEL =
            Pattern.compile("/model/(.+)/(converse|invoke)", Pattern.CASE_INSENSITIVE);

    private String buildBedrockArn(String path, String region) {
        String normalized = path == null || path.isBlank()
                ? "/"
                : (path.startsWith("/") ? path : "/" + path);
        Matcher m = BEDROCK_MODEL.matcher(normalized);
        if (m.find()) {
            String modelId = decodeUrlPathSegment(m.group(1));
            if (modelId.startsWith("arn:")) {
                return modelId;
            }
            return AwsArnUtils.Arn.of("bedrock", region, "", "foundation-model/" + modelId).toString();
        }
        return AwsArnUtils.Arn.of("bedrock", region, "", "foundation-model/*").toString();
    }

    private static String decodeUrlPathSegment(String segment) {
        try {
            return URLDecoder.decode(segment, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return segment;
        }
    }

    // ── Transfer Family ──────────────────────────────────────────────────────────

    private String buildTransferArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        String directArn = firstArn(
                jsonTextFromNode(node, "Arn"),
                jsonTextFromNode(node, "ResourceArn"));
        if (directArn != null) {
            return directArn;
        }

        String serverId = jsonTextFromNode(node, "ServerId");
        String userName = jsonTextFromNode(node, "UserName");
        if (serverId != null && !serverId.isBlank() && userName != null && !userName.isBlank()) {
            return AwsArnUtils.Arn.of("transfer", region, accountId,
                    "user/" + serverId + "/" + userName).toString();
        }
        if (serverId != null && !serverId.isBlank()) {
            return AwsArnUtils.Arn.of("transfer", region, accountId, "server/" + serverId).toString();
        }

        if (operation != null && (operation.startsWith("List") || "CreateServer".equals(operation))) {
            return AwsArnUtils.Arn.of("transfer", region, accountId, "server/*").toString();
        }

        return AwsArnUtils.Arn.of("transfer", region, accountId, "server/*").toString();
    }

    // ── Transcribe ───────────────────────────────────────────────────────────────

    private String buildTranscribeArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        String jobName = jsonTextFromNode(node, "TranscriptionJobName");
        if (jobName != null && !jobName.isBlank()) {
            return AwsArnUtils.Arn.of("transcribe", region, accountId,
                    "transcription-job/" + jobName).toString();
        }

        String vocabularyName = jsonTextFromNode(node, "VocabularyName");
        if (vocabularyName != null && !vocabularyName.isBlank()) {
            return AwsArnUtils.Arn.of("transcribe", region, accountId,
                    "vocabulary/" + vocabularyName).toString();
        }

        if (operation != null && operation.startsWith("List")) {
            if (operation.contains("Vocabular")) {
                return AwsArnUtils.Arn.of("transcribe", region, accountId, "vocabulary/*").toString();
            }
            return AwsArnUtils.Arn.of("transcribe", region, accountId, "transcription-job/*").toString();
        }
        if ("StartTranscriptionJob".equals(operation)) {
            return AwsArnUtils.Arn.of("transcribe", region, accountId, "transcription-job/*").toString();
        }
        if ("CreateVocabulary".equals(operation)) {
            return AwsArnUtils.Arn.of("transcribe", region, accountId, "vocabulary/*").toString();
        }

        return "*";
    }

    // ── AppConfig ────────────────────────────────────────────────────────────────

    private static final Pattern APPCONFIG_DEPLOYMENT_STRATEGY =
            Pattern.compile("/deploymentstrategies(?:/([^/]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern APPCONFIG_DEPLOYMENT =
            Pattern.compile("/applications/([^/]+)/environments/([^/]+)/deployments(?:/([^/]+))?",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern APPCONFIG_HOSTED_VERSION =
            Pattern.compile("/applications/([^/]+)/configurationprofiles/([^/]+)/hostedconfigurationversions(?:/([^/]+))?",
                    Pattern.CASE_INSENSITIVE);
    private static final Pattern APPCONFIG_PROFILE =
            Pattern.compile("/applications/([^/]+)/configurationprofiles(?:/([^/]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern APPCONFIG_ENVIRONMENT =
            Pattern.compile("/applications/([^/]+)/environments(?:/([^/]+))?", Pattern.CASE_INSENSITIVE);
    private static final Pattern APPCONFIG_APPLICATION =
            Pattern.compile("/applications(?:/([^/]+))?", Pattern.CASE_INSENSITIVE);

    private String buildAppConfigArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String normalized = path != null && path.startsWith("/") ? path : "/" + (path != null ? path : "");

        Matcher strategy = APPCONFIG_DEPLOYMENT_STRATEGY.matcher(normalized);
        if (strategy.find()) {
            String strategyId = strategy.group(1);
            if (strategyId != null && !strategyId.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId,
                        "deploymentstrategy/" + strategyId).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId, "deploymentstrategy/*").toString();
        }

        Matcher deployment = APPCONFIG_DEPLOYMENT.matcher(normalized);
        if (deployment.find()) {
            String appId = deployment.group(1);
            String envId = deployment.group(2);
            String deploymentNumber = deployment.group(3);
            if (deploymentNumber != null && !deploymentNumber.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId,
                        "application/" + appId + "/environment/" + envId + "/deployment/" + deploymentNumber).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId,
                    "application/" + appId + "/environment/" + envId + "/deployment/*").toString();
        }

        Matcher hostedVersion = APPCONFIG_HOSTED_VERSION.matcher(normalized);
        if (hostedVersion.find()) {
            String appId = hostedVersion.group(1);
            String profileId = hostedVersion.group(2);
            String versionNumber = hostedVersion.group(3);
            String prefix = "application/" + appId + "/configurationprofile/" + profileId
                    + "/hostedconfigurationversion/";
            if (versionNumber != null && !versionNumber.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId, prefix + versionNumber).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId, prefix + "*").toString();
        }

        Matcher profile = APPCONFIG_PROFILE.matcher(normalized);
        if (profile.find()) {
            String appId = profile.group(1);
            String profileId = profile.group(2);
            if (profileId != null && !profileId.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId,
                        "application/" + appId + "/configurationprofile/" + profileId).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId,
                    "application/" + appId + "/configurationprofile/*").toString();
        }

        Matcher environment = APPCONFIG_ENVIRONMENT.matcher(normalized);
        if (environment.find()) {
            String appId = environment.group(1);
            String envId = environment.group(2);
            if (envId != null && !envId.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId,
                        "application/" + appId + "/environment/" + envId).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId,
                    "application/" + appId + "/environment/*").toString();
        }

        Matcher application = APPCONFIG_APPLICATION.matcher(normalized);
        if (application.find()) {
            String appId = application.group(1);
            if (appId != null && !appId.isBlank()) {
                return AwsArnUtils.Arn.of("appconfig", region, accountId, "application/" + appId).toString();
            }
            return AwsArnUtils.Arn.of("appconfig", region, accountId, "application/*").toString();
        }

        return AwsArnUtils.Arn.of("appconfig", region, accountId, "application/*").toString();
    }

    // ── AppConfig Data ───────────────────────────────────────────────────────────

    private String buildAppConfigDataArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String appId = firstNonBlank(
                jsonTextFromNode(node, "ApplicationIdentifier"),
                jsonTextFromNode(node, "ApplicationId"));
        String envId = firstNonBlank(
                jsonTextFromNode(node, "EnvironmentIdentifier"),
                jsonTextFromNode(node, "EnvironmentId"));
        String profileId = firstNonBlank(
                jsonTextFromNode(node, "ConfigurationProfileIdentifier"),
                jsonTextFromNode(node, "ConfigurationProfileId"));

        if (appId != null && !appId.isBlank()
                && envId != null && !envId.isBlank()
                && profileId != null && !profileId.isBlank()) {
            return AwsArnUtils.Arn.of("appconfig", region, accountId,
                    "application/" + appId + "/environment/" + envId + "/configuration/" + profileId).toString();
        }

        return AwsArnUtils.Arn.of("appconfig", region, accountId,
                "application/*/environment/*/configuration/*").toString();
    }

    // ── Textract ─────────────────────────────────────────────────────────────────

    private String buildTextractArn(ContainerRequestContext ctx, String region, String accountId) {
        JsonNode node = readJsonBodyNode(ctx);
        String operation = jsonTargetOperation(ctx);

        String jobId = jsonTextFromNode(node, "JobId");
        if (jobId != null && !jobId.isBlank()) {
            return AwsArnUtils.Arn.of("textract", region, accountId, "job/" + jobId).toString();
        }

        if (operation != null
                && (operation.startsWith("Get") || operation.startsWith("Start"))
                && operation.contains("Document")) {
            return AwsArnUtils.Arn.of("textract", region, accountId, "job/*").toString();
        }

        return "*";
    }

    // ── Route 53 ─────────────────────────────────────────────────────────────────

    private static final Pattern ROUTE53_HOSTED_ZONE =
            Pattern.compile("/hostedzone/([^/]+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern ROUTE53_HEALTH_CHECK =
            Pattern.compile("/healthcheck/([^/]+)", Pattern.CASE_INSENSITIVE);

    private String buildRoute53Arn(ContainerRequestContext ctx, String path, String region, String accountId) {
        String zoneId = extractPathSegment(path, ROUTE53_HOSTED_ZONE);
        if (zoneId != null && !zoneId.isBlank()) {
            return AwsArnUtils.Arn.of("route53", "", "", "hostedzone/" + zoneId).toString();
        }
        String healthCheckId = extractPathSegment(path, ROUTE53_HEALTH_CHECK);
        if (healthCheckId != null && !healthCheckId.isBlank()) {
            return AwsArnUtils.Arn.of("route53", "", "", "healthcheck/" + healthCheckId).toString();
        }
        return AwsArnUtils.Arn.of("route53", "", "", "hostedzone/*").toString();
    }

    // ── CUR (Cost and Usage Reports) ─────────────────────────────────────────────

    private String buildCurArn(ContainerRequestContext ctx, String region, String accountId) {
        String operation = jsonTargetOperation(ctx);
        if ("DescribeReportDefinitions".equals(operation)) {
            return AwsArnUtils.Arn.of("cur", region, accountId, "definition/*").toString();
        }
        String reportName = firstNonBlank(
                readJsonStringField(ctx, "ReportName"),
                readNestedJsonStringField(ctx, "ReportDefinition", "ReportName"));
        if (reportName != null && !reportName.isBlank()) {
            return AwsArnUtils.Arn.of("cur", region, accountId, "definition/" + reportName).toString();
        }
        return AwsArnUtils.Arn.of("cur", region, accountId, "definition/*").toString();
    }

    // ── BCM Data Exports ─────────────────────────────────────────────────────────

    private String buildBcmDataExportsArn(ContainerRequestContext ctx, String region, String accountId) {
        String operation = jsonTargetOperation(ctx);
        if ("ListExports".equals(operation)) {
            return AwsArnUtils.Arn.of("bcm-data-exports", region, accountId, "export/*").toString();
        }
        String exportArn = firstArn(readJsonStringField(ctx, "ExportArn"));
        if (exportArn != null) {
            return exportArn;
        }
        String exportName = readNestedJsonStringField(ctx, "Export", "Name");
        if (exportName != null && !exportName.isBlank()) {
            return AwsArnUtils.Arn.of("bcm-data-exports", region, accountId, "export/" + exportName).toString();
        }
        return AwsArnUtils.Arn.of("bcm-data-exports", region, accountId, "export/*").toString();
    }

    // ── Cloud Map (servicediscovery) ─────────────────────────────────────────────

    private String buildServiceDiscoveryArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(readJsonStringField(ctx, "ResourceArn"));
        if (arn != null) {
            return arn;
        }

        String serviceId = readJsonStringField(ctx, "ServiceId");
        if (serviceId != null && !serviceId.isBlank()) {
            return AwsArnUtils.Arn.of("servicediscovery", region, accountId, "service/" + serviceId).toString();
        }

        String id = readJsonStringField(ctx, "Id");
        if (id != null && !id.isBlank()) {
            if (id.startsWith("srv-")) {
                return AwsArnUtils.Arn.of("servicediscovery", region, accountId, "service/" + id).toString();
            }
            return AwsArnUtils.Arn.of("servicediscovery", region, accountId, "namespace/" + id).toString();
        }

        String target = ctx.getHeaderString("X-Amz-Target");
        String operation = target != null && target.contains(".")
                ? target.substring(target.lastIndexOf('.') + 1)
                : null;
        if ("CreateService".equals(operation) || "ListServices".equals(operation)) {
            return AwsArnUtils.Arn.of("servicediscovery", region, accountId, "service/*").toString();
        }

        return AwsArnUtils.Arn.of("servicediscovery", region, accountId, "namespace/*").toString();
    }

    // ── API Gateway (execute-api) ────────────────────────────────────────────────

    private String buildExecuteApiArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        Matcher m = EXECUTE_API.matcher(path.startsWith("/") ? path : "/" + path);
        if (m.find()) {
            return "arn:aws:execute-api:" + region + ":" + accountId + ":" + m.group(1) + "/" + m.group(2) + "/*";
        }
        return "arn:aws:execute-api:" + region + ":" + accountId + ":*";
    }

    // ── Shared helpers ────────────────────────────────────────────────────────────

    private JsonNode readJsonBodyNode(ContainerRequestContext ctx) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return objectMapper.createObjectNode();
        }
        try {
            return objectMapper.readTree(body);
        } catch (Exception ignored) {
            return objectMapper.createObjectNode();
        }
    }

    private static String jsonTextFromNode(JsonNode node, String fieldName) {
        if (node == null) {
            return null;
        }
        JsonNode field = node.get(fieldName);
        return field != null && field.isTextual() ? field.asText() : null;
    }

    private static String jsonTargetOperation(ContainerRequestContext ctx) {
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target == null || target.isBlank()) {
            return null;
        }
        int dot = target.lastIndexOf('.');
        return dot >= 0 ? target.substring(dot + 1) : target;
    }

    private static String extractPathSegment(String path, Pattern pattern) {
        if (path == null || path.isBlank()) {
            return null;
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        Matcher m = pattern.matcher(normalized);
        return m.find() ? m.group(1) : null;
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }

    private static String firstArn(String... candidates) {
        for (String c : candidates) {
            if (c != null && c.startsWith("arn:")) {
                return c;
            }
        }
        return null;
    }

    private String readJsonArnField(ContainerRequestContext ctx, String fieldName) {
        String v = readJsonStringField(ctx, fieldName);
        return v != null && v.startsWith("arn:") ? v : null;
    }

    /**
     * Reads the first form value whose key equals {@code prefix} or starts with {@code prefix.}.
     */
    String readFormParamPrefixed(ContainerRequestContext ctx, String prefix) {
        Map<String, String> pairs = parseFormParams(ctx);
        for (Map.Entry<String, String> e : pairs.entrySet()) {
            String key = e.getKey();
            if (key.equals(prefix) || key.startsWith(prefix + ".")) {
                String v = e.getValue();
                if (v != null && !v.isBlank()) {
            return v;
                }
            }
        }
        return null;
    }

    private Map<String, String> parseFormParams(ContainerRequestContext ctx) {
        Map<String, String> out = new LinkedHashMap<>();
        MediaType mt = ctx.getMediaType();
        if (mt == null
                || !"application".equalsIgnoreCase(mt.getType())
                || !"x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype())) {
            return out;
        }
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return out;
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
                String value = URLDecoder.decode(pair.substring(eq + 1), charset);
                out.putIfAbsent(key, value);
            } catch (IllegalArgumentException ignored) {
            }
        }
        return out;
    }

    String readFormParam(ContainerRequestContext ctx, String paramName) {
        String v = ctx.getUriInfo().getQueryParameters().getFirst(paramName);
        if (v != null) {
            return v;
        }
        return parseFormParams(ctx).get(paramName);
    }

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

    private String readJsonFirstArrayElement(ContainerRequestContext ctx, String fieldName) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return null;
        }
        try {
            JsonNode node = objectMapper.readTree(body);
            JsonNode arr = node.get(fieldName);
            if (arr != null && arr.isArray() && !arr.isEmpty() && arr.get(0).isTextual()) {
                return arr.get(0).asText();
            }
        } catch (Exception ignored) {
        }
        return null;
    }

    private byte[] bufferBody(ContainerRequestContext ctx) {
        byte[] body = RequestBodyBuffer.buffer(ctx);
        return body.length == 0 && ctx.getEntityStream() == null ? null : body;
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

    private static String extractSegmentAfter(String path, String segment) {
        String marker = "/" + segment + "/";
        int idx = path.indexOf(marker);
        if (idx < 0) {
            return null;
        }
        String after = path.substring(idx + marker.length());
        int slash = after.indexOf('/');
        return slash > 0 ? after.substring(0, slash) : after;
    }
}
