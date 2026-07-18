package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.AwsException;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * IAM authorization for asynchronous and service-to-service invocations that bypass HTTP
 * {@link io.github.hectorvent.floci.core.common.IamEnforcementFilter}.
 *
 * <p>AWS patterns (Service Authorization Reference and service integration guides):
 * <ul>
 *   <li>Pipes and Scheduler: execution role identity policies on each downstream API</li>
 *   <li>EventBridge (no role): destination resource policies for {@code events.amazonaws.com}</li>
 *   <li>SNS, S3, SES, Logs, ELB, API Gateway, Cognito, CodeDeploy, CodePipeline,
 *       CloudFormation custom resources: destination resource policies</li>
 *   <li>Lambda event source mappings: function execution role on polled sources</li>
 *   <li>CloudTrail: service principal {@code s3:GetBucketAcl} + {@code s3:PutObject}</li>
 *   <li>Config: service principal {@code s3:GetBucketAcl}, {@code s3:ListBucket}, {@code s3:PutObject}</li>
 *   <li>Firehose S3 flush: delivery stream {@code RoleARN} identity policy on {@code s3:PutObject}</li>
 *   <li>VPC flow logs: {@code delivery.logs.amazonaws.com} on bucket (same ACL + PutObject pattern as CloudTrail)</li>
 *   <li>BCM Data Exports: {@code bcm-data-exports.amazonaws.com} {@code s3:PutObject} only</li>
 *   <li>Legacy CUR: {@code billingreports.amazonaws.com} {@code s3:PutObject} + {@code s3:GetBucketPolicy}</li>
 *   <li>IoT topic rules: {@code iot.amazonaws.com} on Lambda/SQS/SNS/Kinesis/DynamoDB/S3 destinations</li>
 *   <li>Secrets Manager rotation: {@code secretsmanager.amazonaws.com} on rotation Lambda</li>
 * </ul>
 */
@ApplicationScoped
public class InProcessTargetAuthorizer {

    public static final String EVENTS_SERVICE = "events.amazonaws.com";
    public static final String SNS_SERVICE = "sns.amazonaws.com";
    public static final String S3_SERVICE = "s3.amazonaws.com";
    public static final String SES_SERVICE = "ses.amazonaws.com";
    public static final String LOGS_SERVICE = "logs.amazonaws.com";
    public static final String ELB_SERVICE = "elasticloadbalancing.amazonaws.com";
    public static final String APIGW_SERVICE = "apigateway.amazonaws.com";
    public static final String COGNITO_SERVICE = "cognito-idp.amazonaws.com";
    public static final String CODEDEPLOY_SERVICE = "codedeploy.amazonaws.com";
    public static final String CODEPIPELINE_SERVICE = "codepipeline.amazonaws.com";
    public static final String CLOUDFORMATION_SERVICE = "cloudformation.amazonaws.com";
    public static final String CONFIG_SERVICE = "config.amazonaws.com";
    public static final String CLOUDTRAIL_SERVICE = "cloudtrail.amazonaws.com";
    /** AWS CloudTrail S3 delivery canned ACL for trail log objects. */
    public static final String CLOUDTRAIL_DELIVERY_OBJECT_ACL = "bucket-owner-full-control";
    public static final String FIREHOSE_SERVICE = "firehose.amazonaws.com";
    public static final String EC2_SERVICE = "ec2.amazonaws.com";
    public static final String BCM_DATA_EXPORTS_SERVICE = "bcm-data-exports.amazonaws.com";
    public static final String BILLING_REPORTS_SERVICE = "billingreports.amazonaws.com";
    public static final String DELIVERY_LOGS_SERVICE = "delivery.logs.amazonaws.com";
    public static final String LOGGING_SERVICE = "logging.s3.amazonaws.com";
    public static final String IOT_SERVICE = "iot.amazonaws.com";
    public static final String SECRETS_MANAGER_SERVICE = "secretsmanager.amazonaws.com";

    private final InProcessIamAuthorizer iamAuthorizer;
    private final EmulatorConfig config;

    @Inject
    public InProcessTargetAuthorizer(InProcessIamAuthorizer iamAuthorizer, EmulatorConfig config) {
        this.iamAuthorizer = iamAuthorizer;
        this.config = config;
    }

    public void authorizePipeSource(String pipeRoleArn, String sourceArn, String region) {
        if (sourceArn == null || sourceArn.isBlank()) {
            return;
        }
        if (sourceArn.contains(":sqs:")) {
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "sqs", "ReceiveMessage", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "sqs", "GetQueueAttributes", sourceArn, region);
            return;
        }
        if (sourceArn.contains(":kinesis:")) {
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "kinesis", "DescribeStream", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "kinesis", "GetRecords", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "kinesis", "GetShardIterator", sourceArn, region);
            return;
        }
        if (sourceArn.contains(":dynamodb:") && sourceArn.contains("/stream/")) {
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "dynamodb", "DescribeStream", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "dynamodb", "GetRecords", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "dynamodb", "GetShardIterator", sourceArn, region);
            return;
        }
        if (sourceArn.contains(":kafka:")) {
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "kafka", "DescribeCluster", sourceArn, region);
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "kafka", "GetBootstrapBrokers", sourceArn, region);
            return;
        }
        if (sourceArn.startsWith("smk://") || sourceArn.contains(":mq:")) {
            denyUnmappedTarget(pipeRoleArn, sourceArn);
        }
    }

    public void authorizePipeSourceDelete(String pipeRoleArn, String sourceArn, String region) {
        if (sourceArn != null && sourceArn.contains(":sqs:")) {
            iamAuthorizer.authorizeWithResource(pipeRoleArn, "sqs", "DeleteMessage", sourceArn, region);
        }
    }

    public void authorizePipeTarget(String pipeRoleArn, String targetArn, String region) {
        authorizeRoleTarget(pipeRoleArn, targetArn, region);
    }

    public void authorizeSchedulerTarget(String scheduleRoleArn, String targetArn, String region) {
        authorizeRoleTarget(scheduleRoleArn, targetArn, region);
    }

    public void authorizeEventBridgeTarget(String ruleRoleArn, String targetArn, String region) {
        if (ruleRoleArn != null && !ruleRoleArn.isBlank()) {
            authorizeRoleTarget(ruleRoleArn, targetArn, region);
        } else {
            authorizeServiceTarget(EVENTS_SERVICE, targetArn, region);
        }
    }

    public void authorizeEventBridgeReplay(String destinationBusArn, String region) {
        // AWS replays archived events internally; no destination bus resource policy gate.
    }

    public void authorizeSnsDelivery(String endpointArn, String protocol, String region) {
        authorizeSnsDelivery(endpointArn, protocol, region, null);
    }

    public void authorizeSnsDelivery(String endpointArn, String protocol, String region, String sourceTopicArn) {
        if (endpointArn == null || endpointArn.isBlank()) {
            return;
        }
        if ("lambda".equalsIgnoreCase(protocol)) {
            iamAuthorizer.authorizeServicePrincipal(
                    SNS_SERVICE, "lambda", "InvokeFunction", endpointArn, region);
            return;
        }
        if ("sqs".equalsIgnoreCase(protocol)) {
            String queueArn = AwsArnUtils.queueUrlToArn(
                    endpointArn, region, config.defaultAccountId());
            iamAuthorizer.authorizeServicePrincipal(
                    SNS_SERVICE, "sqs", "SendMessage", queueArn, region, sourceTopicArn);
        }
    }

    public void authorizeS3ToSqs(String queueArn, String region) {
        iamAuthorizer.authorizeServicePrincipal(S3_SERVICE, "sqs", "SendMessage", queueArn, region);
    }

    public void authorizeS3ToSns(String topicArn, String region) {
        iamAuthorizer.authorizeServicePrincipal(S3_SERVICE, "sns", "Publish", topicArn, region);
    }

    public void authorizeS3ToLambda(String functionArn, String region) {
        iamAuthorizer.authorizeServicePrincipal(S3_SERVICE, "lambda", "InvokeFunction", functionArn, region);
    }

    public void authorizeS3ToEventBridge(String eventBusArn, String region) {
        // AWS: S3 does not require permissions to deliver events to EventBridge.
    }

    public void authorizeSesToSns(String topicArn, String region) {
        iamAuthorizer.authorizeServicePrincipal(SES_SERVICE, "sns", "Publish", topicArn, region);
    }

    public void authorizeSesToFirehose(String roleArn, String deliveryStreamArn, String region) {
        if (roleArn != null && !roleArn.isBlank()) {
            iamAuthorizer.authorizeWithResource(roleArn, "firehose", "PutRecordBatch", deliveryStreamArn, region);
        } else {
            iamAuthorizer.authorizeServicePrincipal(SES_SERVICE, "firehose", "PutRecord", deliveryStreamArn, region);
        }
    }

    public void authorizeSesToEventBridge(String eventBusArn, String region) {
        // AWS: SES EventBridge destinations use service integration without bus resource policy.
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String region) {
        authorizeServiceS3Put(servicePrincipal, bucketName, null, region, null);
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String objectKey, String region) {
        authorizeServiceS3Put(servicePrincipal, bucketName, objectKey, region, null);
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String objectKey,
                                      String region, String sourceArn) {
        authorizeServiceS3Put(servicePrincipal, bucketName, objectKey, region, sourceArn, null);
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String objectKey,
                                      String region, String sourceArn, String sourceAccountId) {
        authorizeServiceS3Put(servicePrincipal, bucketName, objectKey, region, sourceArn, sourceAccountId, null);
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String objectKey,
                                      String region, String sourceArn, String sourceAccountId, String cannedAcl) {
        if (bucketName == null || bucketName.isBlank()) {
            return;
        }
        String bucketArn = AwsArnUtils.Arn.of("s3", "", "", bucketName).toString();
        String objectResource = objectKey != null && !objectKey.isBlank()
                ? AwsArnUtils.Arn.of("s3", "", "", bucketName + "/" + objectKey).toString()
                : bucketArn + "/*";
        if (BCM_DATA_EXPORTS_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "s3", "PutObject", objectResource, region, sourceArn, null, cannedAcl);
            return;
        }
        if (BILLING_REPORTS_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "s3", "PutObject", objectResource, region, sourceArn, null, cannedAcl);
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "s3", "GetBucketPolicy", bucketArn, region);
            return;
        }
        if (LOGGING_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "s3", "PutObject", objectResource, region, sourceArn, sourceAccountId, cannedAcl);
            return;
        }
        if (CONFIG_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "GetBucketAcl", bucketArn, region);
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "ListBucket", bucketArn, region);
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "s3", "PutObject", objectResource, region, sourceArn, sourceAccountId, cannedAcl);
            return;
        }
        iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "GetBucketAcl", bucketArn, region);
        String putObjectAcl = CLOUDTRAIL_SERVICE.equals(servicePrincipal)
                ? (cannedAcl != null && !cannedAcl.isBlank() ? cannedAcl : CLOUDTRAIL_DELIVERY_OBJECT_ACL)
                : cannedAcl;
        iamAuthorizer.authorizeServicePrincipal(
                servicePrincipal, "s3", "PutObject", objectResource, region, sourceArn, sourceAccountId, putObjectAcl);
    }

    public void authorizeFirehoseS3Put(String roleArn, String bucketName, String objectKey, String region) {
        if (bucketName == null || bucketName.isBlank()) {
            return;
        }
        String objectResource = objectKey != null && !objectKey.isBlank()
                ? AwsArnUtils.Arn.of("s3", "", "", bucketName + "/" + objectKey).toString()
                : AwsArnUtils.Arn.of("s3", "", "", bucketName).toString() + "/*";
        iamAuthorizer.authorizeWithResource(roleArn, "s3", "PutObject", objectResource, region);
    }

    public void authorizeVpcFlowLogsS3Put(String bucketName, String objectKey, String region) {
        authorizeServiceS3Put(DELIVERY_LOGS_SERVICE, bucketName, objectKey, region);
    }

    /**
     * S3 server access log delivery uses {@code logging.s3.amazonaws.com} with destination bucket
     * policies conditioned on {@code aws:SourceArn} / {@code aws:SourceAccount} of the source bucket.
     */
    public void authorizeS3AccessLogDelivery(String sourceBucketName,
                                            String targetBucketName,
                                            String objectKey,
                                            String region,
                                            String sourceAccountId) {
        if (targetBucketName == null || targetBucketName.isBlank()) {
            return;
        }
        String sourceArn = AwsArnUtils.Arn.of("s3", "", "", sourceBucketName).toString();
        authorizeServiceS3Put(LOGGING_SERVICE, targetBucketName, objectKey, region, sourceArn, sourceAccountId);
    }

    public void authorizeLambdaEventSourcePoll(String executionRoleArn, String eventSourceArn, String region) {
        if (eventSourceArn == null || eventSourceArn.isBlank()) {
            return;
        }
        if (eventSourceArn.contains(":sqs:")) {
            iamAuthorizer.authorizeWithResource(executionRoleArn, "sqs", "ReceiveMessage", eventSourceArn, region);
            iamAuthorizer.authorizeWithResource(executionRoleArn, "sqs", "GetQueueAttributes", eventSourceArn, region);
            return;
        }
        if (eventSourceArn.contains(":kinesis:")) {
            iamAuthorizer.authorizeWithResource(executionRoleArn, "kinesis", "DescribeStream", eventSourceArn, region);
            iamAuthorizer.authorizeWithResource(executionRoleArn, "kinesis", "GetShardIterator", eventSourceArn, region);
            iamAuthorizer.authorizeWithResource(executionRoleArn, "kinesis", "GetRecords", eventSourceArn, region);
            return;
        }
        if (eventSourceArn.contains(":dynamodb:") && eventSourceArn.contains("/stream/")) {
            iamAuthorizer.authorizeWithResource(executionRoleArn, "dynamodb", "DescribeStream", eventSourceArn, region);
            iamAuthorizer.authorizeWithResource(executionRoleArn, "dynamodb", "GetShardIterator", eventSourceArn, region);
            iamAuthorizer.authorizeWithResource(executionRoleArn, "dynamodb", "GetRecords", eventSourceArn, region);
        }
    }

    public void authorizeLambdaEventSourceDelete(String executionRoleArn, String eventSourceArn, String region) {
        if (eventSourceArn != null && eventSourceArn.contains(":sqs:")) {
            iamAuthorizer.authorizeWithResource(executionRoleArn, "sqs", "DeleteMessage", eventSourceArn, region);
        }
    }

    public void authorizeLogsSubscription(String roleArn, String destinationArn, String region) {
        if (destinationArn == null || destinationArn.isBlank()) {
            return;
        }
        AwsArnUtils.Arn arn = AwsArnUtils.parse(destinationArn);
        switch (arn.service()) {
            case "lambda" -> iamAuthorizer.authorizeServicePrincipal(
                    LOGS_SERVICE, "lambda", "InvokeFunction", destinationArn, region);
            case "firehose" -> authorizeLogsStreamDestination(
                    roleArn, "firehose", "PutRecord", destinationArn, region);
            case "kinesis" -> authorizeLogsStreamDestination(
                    roleArn, "kinesis", "PutRecord", destinationArn, region);
            default -> denyUnmappedTarget(LOGS_SERVICE, destinationArn);
        }
    }

    private void authorizeLogsStreamDestination(String roleArn, String service, String action,
                                                  String destinationArn, String region) {
        if (roleArn == null || roleArn.isBlank()) {
            denyUnmappedTarget(LOGS_SERVICE, destinationArn);
            return;
        }
        iamAuthorizer.authorizeWithResource(roleArn, service, action, destinationArn, region);
    }

    public void authorizeElbLambdaTarget(String functionArn, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                ELB_SERVICE, "lambda", "InvokeFunction", functionArn, region);
    }

    public void authorizeApigwLambdaInvoke(String functionArnOrName, String region) {
        authorizeApigwLambdaInvoke(functionArnOrName, region, null);
    }

    public void authorizeApigwLambdaInvoke(String functionArnOrName, String region, String sourceArn) {
        iamAuthorizer.authorizeServicePrincipal(
                APIGW_SERVICE, "lambda", "InvokeFunction",
                resolveLambdaArn(functionArnOrName, region), region, sourceArn);
    }

    public void authorizeCognitoLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                COGNITO_SERVICE, "lambda", "InvokeFunction", resolveLambdaArn(functionArnOrName, region), region);
    }

    public void authorizeSecretsManagerLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                SECRETS_MANAGER_SERVICE, "lambda", "InvokeFunction",
                resolveLambdaArn(functionArnOrName, region), region);
    }

    public void authorizeCodeDeployLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                CODEDEPLOY_SERVICE, "lambda", "InvokeFunction", resolveLambdaArn(functionArnOrName, region), region);
    }

    /**
     * CodePipeline Lambda invoke action. Prefers an action (or pipeline) execution role identity
     * policy when {@code roleArn} is present; otherwise requires a Lambda resource policy Allow for
     * {@code codepipeline.amazonaws.com}.
     */
    public void authorizeCodePipelineLambdaInvoke(String functionArnOrName, String region) {
        authorizeCodePipelineLambdaInvoke(functionArnOrName, region, null);
    }

    public void authorizeCodePipelineLambdaInvoke(String functionArnOrName, String region, String roleArn) {
        String lambdaArn = resolveLambdaArn(functionArnOrName, region);
        if (roleArn != null && !roleArn.isBlank()) {
            iamAuthorizer.authorizeWithResource(roleArn, "lambda", "InvokeFunction", lambdaArn, region);
        } else {
            iamAuthorizer.authorizeServicePrincipal(
                    CODEPIPELINE_SERVICE, "lambda", "InvokeFunction", lambdaArn, region);
        }
    }

    /** CodePipeline S3 Source action: pipeline role needs {@code s3:GetObject}. */
    public void authorizeCodePipelineS3Get(String roleArn, String bucket, String key, String region) {
        if (bucket == null || bucket.isBlank() || key == null || key.isBlank()) {
            return;
        }
        String objectArn = AwsArnUtils.Arn.of("s3", "", "", bucket + "/" + key).toString();
        iamAuthorizer.authorizeWithResource(roleArn, "s3", "GetObject", objectArn, region);
    }

    /** CodePipeline S3 Deploy action: pipeline role needs {@code s3:PutObject}. */
    public void authorizeCodePipelineS3Put(String roleArn, String bucket, String key, String region) {
        if (bucket == null || bucket.isBlank() || key == null || key.isBlank()) {
            return;
        }
        String objectArn = AwsArnUtils.Arn.of("s3", "", "", bucket + "/" + key).toString();
        iamAuthorizer.authorizeWithResource(roleArn, "s3", "PutObject", objectArn, region);
    }

    /** CodePipeline CodeBuild action: pipeline role needs {@code codebuild:StartBuild}. */
    public void authorizeCodePipelineCodeBuild(String roleArn, String projectName, String region,
                                               String accountId) {
        if (projectName == null || projectName.isBlank()) {
            return;
        }
        String account = accountId != null && !accountId.isBlank() ? accountId : defaultAccountId();
        String projectArn = "arn:aws:codebuild:" + region + ":" + account + ":project/" + projectName;
        iamAuthorizer.authorizeWithResource(roleArn, "codebuild", "StartBuild", projectArn, region);
    }

    /** CodePipeline CodeDeploy action: pipeline role needs {@code codedeploy:CreateDeployment}. */
    public void authorizeCodePipelineCodeDeploy(String roleArn, String applicationName,
                                                String deploymentGroupName, String region,
                                                String accountId) {
        if (applicationName == null || applicationName.isBlank()) {
            return;
        }
        String account = accountId != null && !accountId.isBlank() ? accountId : defaultAccountId();
        String resource = deploymentGroupName != null && !deploymentGroupName.isBlank()
                ? "arn:aws:codedeploy:" + region + ":" + account + ":deploymentgroup:"
                + applicationName + "/" + deploymentGroupName
                : "arn:aws:codedeploy:" + region + ":" + account + ":application:" + applicationName;
        iamAuthorizer.authorizeWithResource(roleArn, "codedeploy", "CreateDeployment", resource, region);
    }

    /** Nested CodePipeline invoke: pipeline role needs {@code codepipeline:StartPipelineExecution}. */
    public void authorizeCodePipelineStartNested(String roleArn, String pipelineName, String region,
                                                 String accountId) {
        if (pipelineName == null || pipelineName.isBlank()) {
            return;
        }
        String account = accountId != null && !accountId.isBlank() ? accountId : defaultAccountId();
        String pipelineArn = "arn:aws:codepipeline:" + region + ":" + account + ":" + pipelineName;
        iamAuthorizer.authorizeWithResource(
                roleArn, "codepipeline", "StartPipelineExecution", pipelineArn, region);
    }

    public void authorizeCloudFormationLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                CLOUDFORMATION_SERVICE, "lambda", "InvokeFunction",
                resolveLambdaArn(functionArnOrName, region), region);
    }

    /**
     * IoT topic-rule delivery to Lambda, SQS, SNS, Kinesis, DynamoDB, or S3.
     * Uses destination resource policies for {@code iot.amazonaws.com}, matching SNS/S3 notification gates.
     *
     * @param actionType one of {@code lambda}, {@code sqs}, {@code sns}, {@code kinesis},
     *                   {@code dynamodb}, {@code s3}
     * @param resourceArnOrUrl destination ARN, SQS queue URL, Kinesis stream name, DynamoDB table name,
     *                         or {@code bucket/key} for S3
     */
    public void authorizeIotDelivery(String actionType, String resourceArnOrUrl, String region) {
        if (actionType == null || actionType.isBlank() || resourceArnOrUrl == null || resourceArnOrUrl.isBlank()) {
            return;
        }
        switch (actionType.toLowerCase()) {
            case "lambda" -> iamAuthorizer.authorizeServicePrincipal(
                    IOT_SERVICE, "lambda", "InvokeFunction",
                    resolveLambdaArn(resourceArnOrUrl, region), region);
            case "sqs" -> {
                String queueArn = AwsArnUtils.queueUrlToArn(
                        resourceArnOrUrl, region, config.defaultAccountId());
                iamAuthorizer.authorizeServicePrincipal(
                        IOT_SERVICE, "sqs", "SendMessage", queueArn, region);
            }
            case "sns" -> iamAuthorizer.authorizeServicePrincipal(
                    IOT_SERVICE, "sns", "Publish", resourceArnOrUrl, region);
            case "kinesis" -> {
                String streamArn = resourceArnOrUrl.startsWith("arn:")
                        ? resourceArnOrUrl
                        : "arn:aws:kinesis:" + region + ":" + defaultAccountId() + ":stream/" + resourceArnOrUrl;
                iamAuthorizer.authorizeServicePrincipal(
                        IOT_SERVICE, "kinesis", "PutRecord", streamArn, region);
            }
            case "dynamodb" -> {
                String tableArn = resourceArnOrUrl.startsWith("arn:")
                        ? resourceArnOrUrl
                        : "arn:aws:dynamodb:" + region + ":" + defaultAccountId() + ":table/" + resourceArnOrUrl;
                iamAuthorizer.authorizeServicePrincipal(
                        IOT_SERVICE, "dynamodb", "PutItem", tableArn, region);
            }
            case "s3" -> {
                String bucketName;
                String objectKey = null;
                if (resourceArnOrUrl.startsWith("arn:aws:s3:::")) {
                    String path = resourceArnOrUrl.substring("arn:aws:s3:::".length());
                    int slash = path.indexOf('/');
                    if (slash < 0) {
                        bucketName = path;
                    } else {
                        bucketName = path.substring(0, slash);
                        objectKey = path.substring(slash + 1);
                    }
                } else {
                    int slash = resourceArnOrUrl.indexOf('/');
                    if (slash < 0) {
                        bucketName = resourceArnOrUrl;
                    } else {
                        bucketName = resourceArnOrUrl.substring(0, slash);
                        objectKey = resourceArnOrUrl.substring(slash + 1);
                    }
                }
                String objectResource = objectKey != null && !objectKey.isBlank()
                        ? AwsArnUtils.Arn.of("s3", "", "", bucketName + "/" + objectKey).toString()
                        : AwsArnUtils.Arn.of("s3", "", "", bucketName).toString() + "/*";
                iamAuthorizer.authorizeServicePrincipal(
                        IOT_SERVICE, "s3", "PutObject", objectResource, region);
            }
            default -> denyUnmappedTarget(IOT_SERVICE, resourceArnOrUrl);
        }
    }

    private String defaultAccountId() {
        return config.defaultAccountId() != null ? config.defaultAccountId() : "000000000000";
    }

    private void authorizeRoleTarget(String roleArn, String targetArn, String region) {
        if (targetArn == null || targetArn.isBlank()) {
            return;
        }
        if (targetArn.contains(":lambda:") || targetArn.contains(":function:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "lambda", "InvokeFunction", targetArn, region);
        } else if (targetArn.contains(":sqs:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "sqs", "SendMessage", targetArn, region);
        } else if (targetArn.contains(":sns:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "sns", "Publish", targetArn, region);
        } else if (targetArn.contains(":events:") && targetArn.contains(":event-bus/")) {
            iamAuthorizer.authorizeWithResource(roleArn, "events", "PutEvents", targetArn, region);
        } else if (targetArn.contains(":states:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "states", "StartExecution", targetArn, region);
        } else if (targetArn.contains(":kinesis:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "kinesis", "PutRecord", targetArn, region);
        } else if (targetArn.contains(":firehose:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "firehose", "PutRecord", targetArn, region);
        } else if (targetArn.contains(":batch:") && targetArn.contains(":job-queue/")) {
            iamAuthorizer.authorizeWithResource(roleArn, "batch", "SubmitJob", targetArn, region);
        } else if (targetArn.contains(":ecs:")) {
            iamAuthorizer.authorizeWithResource(roleArn, "ecs", "RunTask", targetArn, region);
        } else {
            denyUnmappedTarget(roleArn, targetArn);
        }
    }

    private void authorizeServiceTarget(String servicePrincipal, String targetArn, String region) {
        if (targetArn == null || targetArn.isBlank()) {
            return;
        }
        if (targetArn.contains(":lambda:") || targetArn.contains(":function:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "lambda", "InvokeFunction", targetArn, region);
        } else if (targetArn.contains(":sqs:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "sqs", "SendMessage", targetArn, region);
        } else if (targetArn.contains(":sns:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "sns", "Publish", targetArn, region);
        } else if (targetArn.contains(":kinesis:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "kinesis", "PutRecord", targetArn, region);
        } else if (targetArn.contains(":states:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "states", "StartExecution", targetArn, region);
        } else if (targetArn.contains(":events:") && targetArn.contains(":event-bus/")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "events", "PutEvents", targetArn, region);
        } else if (targetArn.contains(":firehose:")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "firehose", "PutRecord", targetArn, region);
        } else if (targetArn.contains(":batch:") && targetArn.contains(":job-queue/")) {
            iamAuthorizer.authorizeServicePrincipal(
                    servicePrincipal, "batch", "SubmitJob", targetArn, region);
        } else {
            denyUnmappedTarget(servicePrincipal, targetArn);
        }
    }

    private String resolveLambdaArn(String functionArnOrName, String region) {
        if (functionArnOrName != null && functionArnOrName.startsWith("arn:")) {
            return functionArnOrName;
        }
        String accountId = config.defaultAccountId() != null ? config.defaultAccountId() : "000000000000";
        return "arn:aws:lambda:" + region + ":" + accountId + ":function:" + functionArnOrName;
    }

    private String defaultEventBusArn(String region) {
        String accountId = config.defaultAccountId() != null ? config.defaultAccountId() : "000000000000";
        return "arn:aws:events:" + region + ":" + accountId + ":event-bus/default";
    }

    private void denyUnmappedTarget(String principal, String targetArn) {
        if (!config.services().iam().enforcementEnabled()) {
            return;
        }
        throw new AwsException("AccessDeniedException",
                "Principal " + principal + " is not authorized for in-process target: " + targetArn, 403);
    }
}
