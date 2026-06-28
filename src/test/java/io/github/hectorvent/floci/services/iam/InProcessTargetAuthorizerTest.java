package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class InProcessTargetAuthorizerTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String ROLE_ARN = "arn:aws:iam::" + ACCOUNT + ":role/inprocess-exec";

    private static final String SQS_ARN =
            "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":example-queue";
    private static final String KINESIS_ARN =
            "arn:aws:kinesis:" + REGION + ":" + ACCOUNT + ":stream/example-stream";
    private static final String DYNAMODB_STREAM_ARN =
            "arn:aws:dynamodb:" + REGION + ":" + ACCOUNT + ":table/example-table/stream/2024-01-01";
    private static final String MQ_ARN =
            "arn:aws:mq:" + REGION + ":" + ACCOUNT + ":broker:example-broker:b-abc";
    private static final String LAMBDA_ARN =
            "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:example-fn";
    private static final String SNS_ARN =
            "arn:aws:sns:" + REGION + ":" + ACCOUNT + ":example-topic";
    private static final String EVENT_BUS_ARN =
            "arn:aws:events:" + REGION + ":" + ACCOUNT + ":event-bus/default";
    private static final String STATE_MACHINE_ARN =
            "arn:aws:states:" + REGION + ":" + ACCOUNT + ":stateMachine:example-sm";
    private static final String FIREHOSE_ARN =
            "arn:aws:firehose:" + REGION + ":" + ACCOUNT + ":deliverystream/example-stream";
    private static final String BUCKET_ARN = "arn:aws:s3:::delivery-bucket";

    private InProcessIamAuthorizer iamAuthorizer;
    private EmulatorConfig config;
    private InProcessTargetAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        config = mock(EmulatorConfig.class, org.mockito.Mockito.RETURNS_DEEP_STUBS);
        when(config.services().iam().enforcementEnabled()).thenReturn(false);
        when(config.defaultAccountId()).thenReturn(ACCOUNT);
        when(config.defaultAccountId()).thenReturn(ACCOUNT);
        authorizer = new InProcessTargetAuthorizer(iamAuthorizer, config);
    }

    @Test
    void pipeSourceMapsSqsToReceiveMessage() {
        authorizer.authorizePipeSource(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("ReceiveMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void pipeSourceMapsKinesisToGetRecords() {
        authorizer.authorizePipeSource(ROLE_ARN, KINESIS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("kinesis"), eq("GetRecords"), eq(KINESIS_ARN), eq(REGION));
    }

    @Test
    void pipeSourceMapsDynamoDbStreamToGetRecords() {
        authorizer.authorizePipeSource(ROLE_ARN, DYNAMODB_STREAM_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("dynamodb"), eq("GetRecords"), eq(DYNAMODB_STREAM_ARN), eq(REGION));
    }

    @Test
    void pipeSourceMapsSqsToGetQueueAttributes() {
        authorizer.authorizePipeSource(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("GetQueueAttributes"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void pipeSourceMapsKinesisToDescribeStream() {
        authorizer.authorizePipeSource(ROLE_ARN, KINESIS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("kinesis"), eq("DescribeStream"), eq(KINESIS_ARN), eq(REGION));
    }

    @Test
    void pipeSourceMapsDynamoDbStreamToDescribeStream() {
        authorizer.authorizePipeSource(ROLE_ARN, DYNAMODB_STREAM_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("dynamodb"), eq("DescribeStream"), eq(DYNAMODB_STREAM_ARN), eq(REGION));
    }

    @Test
    void pipeSourceDeniesMqWhenEnforcementEnabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        assertThrows(AwsException.class, () -> authorizer.authorizePipeSource(ROLE_ARN, MQ_ARN, REGION));

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void pipeSourceSkipsBlankArn() {
        authorizer.authorizePipeSource(ROLE_ARN, "  ", REGION);

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void pipeSourceDeleteMapsSqsToDeleteMessage() {
        authorizer.authorizePipeSourceDelete(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("DeleteMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void pipeTargetMapsLambdaToInvokeFunction() {
        authorizer.authorizePipeTarget(ROLE_ARN, LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("lambda"), eq("InvokeFunction"), eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void pipeTargetMapsSqsToSendMessage() {
        authorizer.authorizePipeTarget(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("SendMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void pipeTargetMapsSnsToPublish() {
        authorizer.authorizePipeTarget(ROLE_ARN, SNS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sns"), eq("Publish"), eq(SNS_ARN), eq(REGION));
    }

    @Test
    void pipeTargetMapsEventBusToPutEvents() {
        authorizer.authorizePipeTarget(ROLE_ARN, EVENT_BUS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("events"), eq("PutEvents"), eq(EVENT_BUS_ARN), eq(REGION));
    }

    @Test
    void pipeTargetMapsStateMachineToStartExecution() {
        authorizer.authorizePipeTarget(ROLE_ARN, STATE_MACHINE_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("states"), eq("StartExecution"), eq(STATE_MACHINE_ARN), eq(REGION));
    }

    @Test
    void schedulerTargetMapsSqsToSendMessage() {
        authorizer.authorizeSchedulerTarget(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("SendMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void eventBridgeTargetWithRoleMapsLambdaToInvokeFunction() {
        authorizer.authorizeEventBridgeTarget(ROLE_ARN, LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("lambda"), eq("InvokeFunction"), eq(LAMBDA_ARN), eq(REGION));
        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.EVENTS_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void eventBridgeTargetWithoutRoleUsesServicePrincipalForLambda() {
        authorizer.authorizeEventBridgeTarget(null, LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.EVENTS_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
        verify(iamAuthorizer, never()).authorizeWithResource(
                eq(ROLE_ARN), eq("lambda"), eq("InvokeFunction"), eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void eventBridgeTargetWithoutRoleUsesServicePrincipalForSqs() {
        authorizer.authorizeEventBridgeTarget("", SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.EVENTS_SERVICE), eq("sqs"), eq("SendMessage"),
                eq(SQS_ARN), eq(REGION));
    }

    @Test
    void snsDeliveryMapsLambdaEndpointToInvokeFunction() {
        authorizer.authorizeSnsDelivery(LAMBDA_ARN, "lambda", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.SNS_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void snsDeliveryMapsSqsEndpointToSendMessage() {
        authorizer.authorizeSnsDelivery(SQS_ARN, "sqs", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.SNS_SERVICE), eq("sqs"), eq("SendMessage"),
                eq(SQS_ARN), eq(REGION), isNull());
    }

    @Test
    void snsDeliverySkipsBlankEndpoint() {
        authorizer.authorizeSnsDelivery(null, "lambda", REGION);

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void esmPollMapsSqsToReceiveMessage() {
        authorizer.authorizeLambdaEventSourcePoll(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("ReceiveMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void esmPollMapsKinesisToGetRecords() {
        authorizer.authorizeLambdaEventSourcePoll(ROLE_ARN, KINESIS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("kinesis"), eq("GetRecords"), eq(KINESIS_ARN), eq(REGION));
    }

    @Test
    void esmPollMapsDynamoDbStreamToGetRecords() {
        authorizer.authorizeLambdaEventSourcePoll(ROLE_ARN, DYNAMODB_STREAM_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("dynamodb"), eq("GetRecords"), eq(DYNAMODB_STREAM_ARN), eq(REGION));
    }

    @Test
    void esmDeleteMapsSqsToDeleteMessage() {
        authorizer.authorizeLambdaEventSourceDelete(ROLE_ARN, SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("sqs"), eq("DeleteMessage"), eq(SQS_ARN), eq(REGION));
    }

    @Test
    void eventBridgeReplayDoesNotEvaluatePolicies() {
        authorizer.authorizeEventBridgeReplay(EVENT_BUS_ARN, REGION);
        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void eventBridgeReplaySkipsBlankDestination() {
        authorizer.authorizeEventBridgeReplay("  ", REGION);
        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void s3ToLambdaUsesS3ServicePrincipal() {
        authorizer.authorizeS3ToLambda(LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.S3_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void s3ToSqsUsesS3ServicePrincipal() {
        authorizer.authorizeS3ToSqs(SQS_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.S3_SERVICE), eq("sqs"), eq("SendMessage"),
                eq(SQS_ARN), eq(REGION));
    }

    @Test
    void s3ToSnsUsesS3ServicePrincipal() {
        authorizer.authorizeS3ToSns(SNS_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.S3_SERVICE), eq("sns"), eq("Publish"),
                eq(SNS_ARN), eq(REGION));
    }

    @Test
    void s3ToEventBridgeDoesNotEvaluatePolicies() {
        authorizer.authorizeS3ToEventBridge(null, REGION);
        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void sesToSnsUsesSesServicePrincipal() {
        authorizer.authorizeSesToSns(SNS_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.SES_SERVICE), eq("sns"), eq("Publish"),
                eq(SNS_ARN), eq(REGION));
    }

    @Test
    void sesToFirehoseUsesRoleWhenPresent() {
        authorizer.authorizeSesToFirehose(ROLE_ARN, FIREHOSE_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("firehose"), eq("PutRecordBatch"), eq(FIREHOSE_ARN), eq(REGION));
        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.SES_SERVICE), eq("firehose"), eq("PutRecord"),
                eq(FIREHOSE_ARN), eq(REGION));
    }

    @Test
    void sesToFirehoseFallsBackWithoutRole() {
        authorizer.authorizeSesToFirehose(null, FIREHOSE_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.SES_SERVICE), eq("firehose"), eq("PutRecord"),
                eq(FIREHOSE_ARN), eq(REGION));
    }

    @Test
    void sesToEventBridgeDoesNotEvaluatePolicies() {
        authorizer.authorizeSesToEventBridge(EVENT_BUS_ARN, REGION);
        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void apigwLambdaInvokeResolvesFunctionName() {
        authorizer.authorizeApigwLambdaInvoke("example-fn", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.APIGW_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void cognitoLambdaInvokeUsesServicePrincipal() {
        authorizer.authorizeCognitoLambdaInvoke(LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.COGNITO_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void codeDeployLambdaInvokeUsesServicePrincipal() {
        authorizer.authorizeCodeDeployLambdaInvoke(LAMBDA_ARN, REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CODEDEPLOY_SERVICE), eq("lambda"), eq("InvokeFunction"),
                eq(LAMBDA_ARN), eq(REGION));
    }

    @Test
    void serviceS3PutChecksAclAndObjectKey() {
        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE, "delivery-bucket", "AWSLogs/key.json", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE), eq("s3"), eq("GetBucketAcl"),
                eq(BUCKET_ARN), eq(REGION));
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/AWSLogs/key.json"), eq(REGION), isNull(), isNull());
    }

    @Test
    void serviceS3PutPassesSourceArnToPutObjectOnly() {
        String trailArn = "arn:aws:cloudtrail:" + REGION + ":" + ACCOUNT + ":trail/audit-trail";

        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE,
                "delivery-bucket",
                "AWSLogs/key.json",
                REGION,
                trailArn);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE), eq("s3"), eq("GetBucketAcl"),
                eq(BUCKET_ARN), eq(REGION));
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/AWSLogs/key.json"), eq(REGION), eq(trailArn), isNull());
    }

    @Test
    void serviceS3PutSkipsBlankBucketName() {
        authorizer.authorizeServiceS3Put(InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE, null, REGION);

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void configS3PutChecksAclListBucketAndObjectKey() {
        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.CONFIG_SERVICE, "delivery-bucket", "AWSLogs/key.json", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CONFIG_SERVICE), eq("s3"), eq("GetBucketAcl"),
                eq(BUCKET_ARN), eq(REGION));
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CONFIG_SERVICE), eq("s3"), eq("ListBucket"),
                eq(BUCKET_ARN), eq(REGION));
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.CONFIG_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/AWSLogs/key.json"), eq(REGION), isNull(), isNull());
    }

    @Test
    void s3AccessLogDeliveryChecksPutObjectWithSourceArnAndAccount() {
        authorizer.authorizeS3AccessLogDelivery(
                "source-bucket", "delivery-bucket", "access-logs/key.log", REGION, ACCOUNT);

        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.LOGGING_SERVICE), eq("s3"), eq("GetBucketAcl"),
                any(), any());
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.LOGGING_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/access-logs/key.log"), eq(REGION),
                eq("arn:aws:s3:::source-bucket"), eq(ACCOUNT));
    }

    @Test
    void bcmDataExportsS3PutChecksPutObjectOnly() {
        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.BCM_DATA_EXPORTS_SERVICE, "delivery-bucket", "billing/out.parquet", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.BCM_DATA_EXPORTS_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/billing/out.parquet"), eq(REGION), isNull());
        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.BCM_DATA_EXPORTS_SERVICE), eq("s3"), eq("GetBucketAcl"),
                eq(BUCKET_ARN), eq(REGION));
    }

    @Test
    void billingReportsS3PutChecksPutObjectAndGetBucketPolicy() {
        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.BILLING_REPORTS_SERVICE, "delivery-bucket", "cur/out.parquet", REGION);

        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.BILLING_REPORTS_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/cur/out.parquet"), eq(REGION), isNull());
        verify(iamAuthorizer).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.BILLING_REPORTS_SERVICE), eq("s3"), eq("GetBucketPolicy"),
                eq(BUCKET_ARN), eq(REGION));
    }

    @Test
    void firehoseS3PutUsesStreamRoleArn() {
        authorizer.authorizeFirehoseS3Put(ROLE_ARN, "delivery-bucket", "stream/out.json", REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/stream/out.json"), eq(REGION));
        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.FIREHOSE_SERVICE), eq("s3"), eq("PutObject"),
                eq("arn:aws:s3:::delivery-bucket/stream/out.json"), eq(REGION));
    }

    @Test
    void logsSubscriptionUsesRoleForFirehose() {
        authorizer.authorizeLogsSubscription(ROLE_ARN, FIREHOSE_ARN, REGION);

        verify(iamAuthorizer).authorizeWithResource(
                eq(ROLE_ARN), eq("firehose"), eq("PutRecord"), eq(FIREHOSE_ARN), eq(REGION));
        verify(iamAuthorizer, never()).authorizeServicePrincipal(
                eq(InProcessTargetAuthorizer.LOGS_SERVICE), eq("firehose"), eq("PutRecord"),
                eq(FIREHOSE_ARN), eq(REGION));
    }

    @Test
    void logsSubscriptionDeniesFirehoseWithoutRoleWhenEnforcementEnabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        assertThrows(AwsException.class,
                () -> authorizer.authorizeLogsSubscription(null, FIREHOSE_ARN, REGION));

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void logsSubscriptionDeniesKinesisWithoutRoleWhenEnforcementEnabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        assertThrows(AwsException.class,
                () -> authorizer.authorizeLogsSubscription("", KINESIS_ARN, REGION));

        verifyNoInteractions(iamAuthorizer);
    }
}
