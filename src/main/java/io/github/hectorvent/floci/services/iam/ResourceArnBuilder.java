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
import java.util.LinkedHashMap;
import java.util.Map;
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

    private final ObjectMapper objectMapper;

    @Inject
    public ResourceArnBuilder(ObjectMapper objectMapper) {
        this.objectMapper = objectMapper;
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
            default                    -> "*";
        };
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
        String arn = firstArn(
                readFormParam(ctx, "QueueUrl"),
                readJsonStringField(ctx, "QueueUrl"));
        if (arn != null) {
            String queueName = arn.substring(arn.lastIndexOf('/') + 1);
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        String queueName = firstNonBlank(
                readFormParam(ctx, "QueueName"),
                readJsonStringField(ctx, "QueueName"));
        if (queueName != null) {
            return AwsArnUtils.Arn.of("sqs", region, accountId, queueName).toString();
        }
        return AwsArnUtils.Arn.of("sqs", region, accountId, "*").toString();
    }

    // ── SNS ─────────────────────────────────────────────────────────────────────

    private String buildSnsArn(ContainerRequestContext ctx, String region, String accountId) {
        String arn = firstArn(
                readFormParam(ctx, "TopicArn"),
                readFormParam(ctx, "SubscriptionArn"),
                readFormParam(ctx, "TargetArn"),
                readFormParam(ctx, "ResourceArn"),
                readFormParam(ctx, "PlatformApplicationArn"),
                readFormParam(ctx, "EndpointArn"),
                readJsonStringField(ctx, "TopicArn"),
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
        String tableArn = firstArn(readJsonStringField(ctx, "TableArn"));
        if (tableArn != null) {
            return tableArn;
        }
        String tableName = firstNonBlank(
                readJsonStringField(ctx, "TableName"),
                readJsonStringField(ctx, "GlobalTableName"));
        if (tableName != null && !tableName.isBlank()) {
            if (readJsonStringField(ctx, "GlobalTableName") != null) {
                return AwsArnUtils.Arn.of("dynamodb", "", accountId, "global-table/" + tableName).toString();
            }
            return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/" + tableName).toString();
        }
        return AwsArnUtils.Arn.of("dynamodb", region, accountId, "table/*").toString();
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
                readJsonArnField(ctx, "ARN"),
                readJsonFirstArrayElement(ctx, "SecretIdList"));
        if (secretId == null || secretId.isBlank()) {
            return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:*").toString();
        }
        if (secretId.startsWith("arn:aws:secretsmanager:")) {
            return secretId;
        }
        return AwsArnUtils.Arn.of("secretsmanager", region, accountId, "secret:" + secretId + "-000000").toString();
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
        return AwsArnUtils.Arn.of("kms", region, accountId, "key/*").toString();
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
        String stackName = readFormParam(ctx, "StackName");
        if (stackName != null && !stackName.isBlank()) {
            return AwsArnUtils.Arn.of("cloudformation", region, accountId,
                    "stack/" + stackName + "/00000000-0000-0000-0000-000000000000").toString();
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
        String workGroup = readJsonStringField(ctx, "WorkGroup");
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

    // ── API Gateway (execute-api) ────────────────────────────────────────────────

    private String buildExecuteApiArn(ContainerRequestContext ctx, String path, String region, String accountId) {
        Matcher m = EXECUTE_API.matcher(path.startsWith("/") ? path : "/" + path);
        if (m.find()) {
            return "arn:aws:execute-api:" + region + ":" + accountId + ":" + m.group(1) + "/" + m.group(2) + "/*";
        }
        return "arn:aws:execute-api:" + region + ":" + accountId + ":*";
    }

    // ── Shared helpers ────────────────────────────────────────────────────────────

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
