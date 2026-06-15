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
 *   <li>SNS, S3, SES, Logs, ELB, API Gateway, Cognito, CodeDeploy: destination resource policies</li>
 *   <li>Lambda event source mappings: function execution role on polled sources</li>
 *   <li>CloudTrail: service principal {@code s3:GetBucketAcl} + {@code s3:PutObject}</li>
 *   <li>Config: service principal {@code s3:GetBucketAcl}, {@code s3:ListBucket}, {@code s3:PutObject}</li>
 *   <li>Firehose S3 flush: delivery stream {@code RoleARN} identity policy on {@code s3:PutObject}</li>
 *   <li>VPC flow logs: {@code delivery.logs.amazonaws.com} on bucket (same ACL + PutObject pattern as CloudTrail)</li>
 *   <li>BCM Data Exports: {@code bcm-data-exports.amazonaws.com} {@code s3:PutObject} only</li>
 *   <li>Legacy CUR: {@code billingreports.amazonaws.com} {@code s3:PutObject} + {@code s3:GetBucketPolicy}</li>
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
    public static final String CONFIG_SERVICE = "config.amazonaws.com";
    public static final String CLOUDTRAIL_SERVICE = "cloudtrail.amazonaws.com";
    public static final String FIREHOSE_SERVICE = "firehose.amazonaws.com";
    public static final String EC2_SERVICE = "ec2.amazonaws.com";
    public static final String BCM_DATA_EXPORTS_SERVICE = "bcm-data-exports.amazonaws.com";
    public static final String BILLING_REPORTS_SERVICE = "billingreports.amazonaws.com";
    public static final String DELIVERY_LOGS_SERVICE = "delivery.logs.amazonaws.com";

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
        if (sourceArn.contains(":mq:")) {
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
        authorizeServiceS3Put(servicePrincipal, bucketName, null, region);
    }

    public void authorizeServiceS3Put(String servicePrincipal, String bucketName, String objectKey, String region) {
        if (bucketName == null || bucketName.isBlank()) {
            return;
        }
        String bucketArn = AwsArnUtils.Arn.of("s3", "", "", bucketName).toString();
        String objectResource = objectKey != null && !objectKey.isBlank()
                ? AwsArnUtils.Arn.of("s3", "", "", bucketName + "/" + objectKey).toString()
                : bucketArn + "/*";
        if (BCM_DATA_EXPORTS_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "PutObject", objectResource, region);
            return;
        }
        if (BILLING_REPORTS_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "PutObject", objectResource, region);
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "GetBucketPolicy", bucketArn, region);
            return;
        }
        if (CONFIG_SERVICE.equals(servicePrincipal)) {
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "GetBucketAcl", bucketArn, region);
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "ListBucket", bucketArn, region);
            iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "PutObject", objectResource, region);
            return;
        }
        iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "GetBucketAcl", bucketArn, region);
        iamAuthorizer.authorizeServicePrincipal(servicePrincipal, "s3", "PutObject", objectResource, region);
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
        iamAuthorizer.authorizeServicePrincipal(
                APIGW_SERVICE, "lambda", "InvokeFunction", resolveLambdaArn(functionArnOrName, region), region);
    }

    public void authorizeCognitoLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                COGNITO_SERVICE, "lambda", "InvokeFunction", resolveLambdaArn(functionArnOrName, region), region);
    }

    public void authorizeCodeDeployLambdaInvoke(String functionArnOrName, String region) {
        iamAuthorizer.authorizeServicePrincipal(
                CODEDEPLOY_SERVICE, "lambda", "InvokeFunction", resolveLambdaArn(functionArnOrName, region), region);
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
