package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link ResourceArnBuilder} covering SSM and STS resource ARN extraction.
 * Verifies that account-scoped policy ARNs can match request resource ARNs when using
 * a non-default account ID.
 */
class ResourceArnBuilderTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";

    private final ResourceArnBuilder builder = new ResourceArnBuilder(new ObjectMapper());

    // ── SSM ───────────────────────────────────────────────────────────────────

    @Test
    void ssmGetParameterBuildsExactArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"/nimbus/challenge/escalation\"}");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/nimbus/challenge/escalation", arn);
    }

    @Test
    void ssmParameterNameWithoutLeadingSlash() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"my/param\"}");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/my/param", arn);
    }

    @Test
    void ssmGetParametersUsesFirstName() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Names\":[\"/a/b\",\"/c/d\"]}");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/a/b", arn);
    }

    @Test
    void ssmEmptyBodyFallsBackToWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/*", arn);
    }

    @Test
    void ssmMalformedBodyFallsBackToWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("not-json");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/*", arn);
    }

    @Test
    void ssmBodyIsRestoredForDownstreamHandlers() throws Exception {
        String body = "{\"Name\":\"/my/param\"}";
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        ContainerRequestContext ctx = ctxWithStream(
                new MultivaluedHashMap<>(),
                MediaType.valueOf("application/x-amz-json-1.1"),
                streamRef);

        builder.build("ssm", ctx, REGION, ACCOUNT);

        byte[] remaining = streamRef.get().readAllBytes();
        assertEquals(body, new String(remaining, StandardCharsets.UTF_8));
    }

    // ── STS ───────────────────────────────────────────────────────────────────

    @Test
    void stsAssumeRoleExtractsRoleArnFromFormBody() {
        String roleArn = "arn:aws:iam::222222222222:role/nimbus-flag-reader";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=AssumeRole&RoleArn=" + roleArn + "&RoleSessionName=s");
        String arn = builder.build("sts", ctx, REGION, ACCOUNT);
        assertEquals(roleArn, arn);
    }

    @Test
    void stsGetCallerIdentityReturnsWildcard() {
        ContainerRequestContext ctx = formBodyCtx("Action=GetCallerIdentity");
        String arn = builder.build("sts", ctx, REGION, ACCOUNT);
        assertEquals("*", arn);
    }

    @Test
    void stsRoleArnFromQueryParamTakesPrecedence() {
        String roleArn = "arn:aws:iam::222222222222:role/my-role";
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("RoleArn", roleArn);
        ContainerRequestContext ctx = ctxWithStream(
                query,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                new AtomicReference<>(new ByteArrayInputStream("Action=AssumeRole".getBytes())));
        String arn = builder.build("sts", ctx, REGION, ACCOUNT);
        assertEquals(roleArn, arn);
    }

    @Test
    void stsFormBodyIsRestoredForDownstreamHandlers() throws Exception {
        String body = "Action=AssumeRole&RoleArn=arn:aws:iam::222222222222:role/r&RoleSessionName=s";
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        ContainerRequestContext ctx = ctxWithStream(
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                streamRef);

        builder.build("sts", ctx, REGION, ACCOUNT);

        byte[] remaining = streamRef.get().readAllBytes();
        assertEquals(body, new String(remaining, StandardCharsets.UTF_8));
    }

    // ── IAM ───────────────────────────────────────────────────────────────────

    @Test
    void iamCreateAccessKeyBuildsUserArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=CreateAccessKey&UserName=broker-clerk");
        String arn = builder.build("iam", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:iam::222222222222:user/broker-clerk", arn);
    }

    @Test
    void sqsReceiveMessageBuildsArnFromHttpQueueUrl() {
        String queueUrl = "http://localhost:4566/000000000000/ctf-lab-queue";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=ReceiveMessage&QueueUrl=" + java.net.URLEncoder.encode(queueUrl, java.nio.charset.StandardCharsets.UTF_8));
        String arn = builder.build("sqs", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:sqs:us-east-1:222222222222:ctf-lab-queue", arn);
    }

    @Test
    void iamCreatePolicyVersionBuildsPolicyArn() {
        ContainerRequestContext ctx = formBodyCtx(
                "Action=CreatePolicyVersion&PolicyArn=arn:aws:iam::222222222222:policy/PathfindingPolicy");
        String arn = builder.build("iam", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:iam::222222222222:policy/PathfindingPolicy", arn);
    }

    // ── DynamoDB ──────────────────────────────────────────────────────────────

    @Test
    void dynamodbGetItemBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"TableName\":\"smoke-settlements\"}");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/smoke-settlements", arn);
    }

    // ── Secrets Manager ───────────────────────────────────────────────────────

    @Test
    void secretsGetSecretValueBuildsSecretArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"SecretId\":\"market/relay/scanner-hint\"}");
        String arn = builder.build("secretsmanager", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:secretsmanager:us-east-1:222222222222:secret:market/relay/scanner-hint-000000", arn);
    }

    // ── Kinesis ───────────────────────────────────────────────────────────────

    @Test
    void kinesisGetRecordsBuildsStreamArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"StreamName\":\"orders\"}");
        String arn = builder.build("kinesis", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kinesis:us-east-1:222222222222:stream/orders", arn);
    }

    @Test
    void kinesisPutRecordUsesStreamArnField() {
        String streamArn = "arn:aws:kinesis:us-east-1:222222222222:stream/existing";
        ContainerRequestContext ctx = jsonBodyCtx("{\"StreamARN\":\"" + streamArn + "\"}");
        String arn = builder.build("kinesis", ctx, REGION, ACCOUNT);
        assertEquals(streamArn, arn);
    }

    // ── KMS ───────────────────────────────────────────────────────────────────

    @Test
    void kmsDecryptBuildsKeyArnFromBody() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"KeyId\":\"550e8400-e29b-41d4-a716-446655440000\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kms:us-east-1:222222222222:key/550e8400-e29b-41d4-a716-446655440000", arn);
    }

    @Test
    void kmsAliasNameBuildsAliasArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"AliasName\":\"alias/nimbus\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kms:us-east-1:222222222222:alias/nimbus", arn);
    }

    @Test
    void kmsDecryptBuildsKeyArnFromCiphertextBlob() {
        String blob = java.util.Base64.getEncoder().encodeToString("kms:v2:550e8400-e29b-41d4-a716-446655440000:iv:cipher".getBytes());
        ContainerRequestContext ctx = jsonBodyCtx("{\"CiphertextBlob\":\"" + blob + "\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kms:us-east-1:222222222222:key/550e8400-e29b-41d4-a716-446655440000", arn);
    }

    // ── EC2 ───────────────────────────────────────────────────────────────────

    @Test
    void ec2TerminateInstancesBuildsInstanceArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=TerminateInstances&InstanceId.1=i-0abc123");
        String arn = builder.build("ec2", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ec2:us-east-1:222222222222:instance/i-0abc123", arn);
    }

    @Test
    void ec2DescribeSecurityGroupsBuildsGroupArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=DescribeSecurityGroups&GroupId.1=sg-0deadbeef");
        String arn = builder.build("ec2", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ec2:us-east-1:222222222222:security-group/sg-0deadbeef", arn);
    }

    // ── CloudFormation ────────────────────────────────────────────────────────

    @Test
    void cloudFormationDescribeStacksBuildsStackArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=DescribeStacks&StackName=my-stack");
        String arn = builder.build("cloudformation", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudformation:us-east-1:222222222222:stack/my-stack/*", arn);
    }

    // ── SQS / SNS ─────────────────────────────────────────────────────────────

    @Test
    void sqsCreateQueueBuildsQueueArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=CreateQueue&QueueName=orders.fifo");
        String arn = builder.build("sqs", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:sqs:us-east-1:222222222222:orders.fifo", arn);
    }

    @Test
    void snsCreateTopicBuildsTopicArn() {
        ContainerRequestContext ctx = formBodyCtx("Action=CreateTopic&Name=alerts");
        String arn = builder.build("sns", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:sns:us-east-1:222222222222:alerts", arn);
    }

    // ── Logs / Events / States ────────────────────────────────────────────────

    @Test
    void logsPutLogEventsBuildsLogGroupArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"logGroupName\":\"/aws/lambda/my-fn\"}");
        String arn = builder.build("logs", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:logs:us-east-1:222222222222:log-group:/aws/lambda/my-fn", arn);
    }

    @Test
    void eventsPutRuleBuildsRuleArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"default\",\"Rule\":\"cron-rule\"}");
        String arn = builder.build("events", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:events:us-east-1:222222222222:rule/cron-rule", arn);
    }

    @Test
    void statesStartExecutionUsesStateMachineArn() {
        String smArn = "arn:aws:states:us-east-1:222222222222:stateMachine:MyFlow";
        ContainerRequestContext ctx = jsonBodyCtx("{\"stateMachineArn\":\"" + smArn + "\"}");
        String arn = builder.build("states", ctx, REGION, ACCOUNT);
        assertEquals(smArn, arn);
    }

    // ── ECR / ECS / Firehose / Cognito ────────────────────────────────────────

    @Test
    void ecrDescribeRepositoriesBuildsRepoArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"repositoryName\":\"nimbus/app\"}");
        String arn = builder.build("ecr", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ecr:us-east-1:222222222222:repository/nimbus/app", arn);
    }

    @Test
    void ecsDescribeServicesBuildsServiceArn() {
        ContainerRequestContext ctx = jsonBodyCtx(
                "{\"cluster\":\"prod\",\"service\":\"api\"}");
        String arn = builder.build("ecs", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ecs:us-east-1:222222222222:service/prod/api", arn);
    }

    @Test
    void firehosePutRecordBuildsDeliveryStreamArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"DeliveryStreamName\":\"audit\"}");
        String arn = builder.build("firehose", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:firehose:us-east-1:222222222222:deliverystream/audit", arn);
    }

    @Test
    void cognitoDescribeUserPoolBuildsPoolArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"UserPoolId\":\"us-east-1_ABC123\"}");
        String arn = builder.build("cognito-idp", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cognito-idp:us-east-1:222222222222:userpool/us-east-1_ABC123", arn);
    }

    // ── API Gateway ───────────────────────────────────────────────────────────

    @Test
    void apiGatewayRestApiFromPath() {
        ContainerRequestContext ctx = pathCtx("/restapis/abc123/stages/dev", jsonBodyCtx("{}"));
        String arn = builder.build("apigateway", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:apigateway:us-east-1::/restapis/abc123", arn);
    }

    @Test
    void secretsScopedPolicyMatchesSuffixWildcard() {
        String policy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"secretsmanager:GetSecretValue",
               "Resource":"arn:aws:secretsmanager:us-east-1:222222222222:secret:market/relay/scanner-hint-*"}
            ]}""";
        String resource = "arn:aws:secretsmanager:us-east-1:222222222222:secret:market/relay/scanner-hint-000000";
        IamPolicyEvaluator eval = new IamPolicyEvaluator(new ObjectMapper());
        assertEquals(IamPolicyEvaluator.Decision.ALLOW,
                eval.evaluate(java.util.List.of(policy), "secretsmanager:GetSecretValue", resource));
    }

    // ── Helpers ───────────────────────────────────────────────────────────────

    private static ContainerRequestContext jsonBodyCtx(String json) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        return ctxWithStream(
                new MultivaluedHashMap<>(),
                MediaType.valueOf("application/x-amz-json-1.1"),
                streamRef);
    }

    private static ContainerRequestContext formBodyCtx(String body) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return ctxWithStream(
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                streamRef);
    }

    private static ContainerRequestContext pathCtx(String path, ContainerRequestContext base) {
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(uriInfo.getPath()).thenReturn(path);
        when(base.getUriInfo()).thenReturn(uriInfo);
        return base;
    }

    private static ContainerRequestContext ctxWithStream(MultivaluedMap<String, String> queryParams,
                                                         MediaType mediaType,
                                                         AtomicReference<InputStream> streamRef) {
        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(uriInfo.getPath()).thenReturn("/");
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMediaType()).thenReturn(mediaType);
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
        return ctx;
    }
}
