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
import static org.junit.jupiter.api.Assertions.assertNull;
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
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"/app/test/parameter\"}");
        String arn = builder.build("ssm", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ssm:us-east-1:222222222222:parameter/app/test/parameter", arn);
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
        String roleArn = "arn:aws:iam::222222222222:role/app-reader-role";
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
        assertEquals("arn:aws:sqs:us-east-1:000000000000:ctf-lab-queue", arn);
    }

    @Test
    void sqsReceiveMessageBuildsArnFromLocalstackHostVariant() {
        String queueUrl = "http://localhost.localstack.cloud:4566/000000000000/orders";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=ReceiveMessage&QueueUrl=" + java.net.URLEncoder.encode(queueUrl, java.nio.charset.StandardCharsets.UTF_8));
        String arn = builder.build("sqs", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:sqs:us-east-1:000000000000:orders", arn);
    }

    @Test
    void sqsReceiveMessageUsesQueueArnWhenQueueUrlIsArn() {
        String queueArn = "arn:aws:sqs:us-east-1:000000000000:orders";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=ReceiveMessage&QueueUrl=" + java.net.URLEncoder.encode(queueArn, java.nio.charset.StandardCharsets.UTF_8));
        String arn = builder.build("sqs", ctx, REGION, ACCOUNT);
        assertEquals(queueArn, arn);
    }

    @Test
    void sqsReceiveMessageUsesAccountFromQueueUrlPath() {
        assertEquals("000000000000", ResourceArnBuilder.parseSqsAccountFromQueueUrl(
                "https://sqs.us-east-1.amazonaws.com/000000000000/my-queue"));
        assertEquals("my-queue.fifo", ResourceArnBuilder.parseSqsQueueName(
                "https://sqs.us-east-1.amazonaws.com/000000000000/my-queue.fifo"));
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

    @Test
    void dynamodbPutItemBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"TableName\":\"ledger\",\"Item\":{\"pk\":{\"S\":\"x\"}}}");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/ledger", arn);
    }

    @Test
    void dynamodbQueryBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"TableName":"events","KeyConditionExpression":"pk = :pk",
                 "ExpressionAttributeValues":{":pk":{"S":"a"}}}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/events", arn);
    }

    @Test
    void dynamodbQueryWithIndexBuildsIndexArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"TableName":"events","IndexName":"by-sk",
                 "KeyConditionExpression":"pk = :pk",
                 "ExpressionAttributeValues":{":pk":{"S":"a"}}}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/events/index/by-sk", arn);
    }

    @Test
    void dynamodbTableNameAsArnReturnsTableArn() {
        String tableArn = "arn:aws:dynamodb:us-east-1:222222222222:table/Users";
        ContainerRequestContext ctx = jsonBodyCtx("{\"TableName\":\"" + tableArn + "\"}");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals(tableArn, arn);
    }

    @Test
    void dynamodbBatchGetItemBuildsTableArnFromRequestItems() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"RequestItems":{"Orders":{"Keys":[{"pk":{"S":"1"}}]}}}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Orders", arn);
    }

    @Test
    void dynamodbTagResourceUsesResourceArnField() {
        String tableArn = "arn:aws:dynamodb:us-east-1:222222222222:table/tagged";
        ContainerRequestContext ctx = jsonBodyCtx("{\"ResourceArn\":\"" + tableArn + "\"}");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals(tableArn, arn);
    }

    @Test
    void dynamodbMissingTableNameFallsBackToWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Limit\":10}");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/*", arn);
    }

    @Test
    void dynamodbExecuteStatementSelectFromQuotedTableBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statement":"SELECT * FROM \\"Music\\" WHERE Artist = ?"}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Music", arn);
    }

    @Test
    void dynamodbExecuteStatementSelectFromUnquotedTableBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statement":"SELECT pk FROM events WHERE pk = ?"}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/events", arn);
    }

    @Test
    void dynamodbExecuteStatementInsertIntoQuotedTableBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statement":"INSERT INTO \\"Flowers\\" VALUE {'Name': ?}"}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Flowers", arn);
    }

    @Test
    void dynamodbExecuteStatementUpdateTableBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statement":"UPDATE EyeColors SET IsRecessive = ? WHERE Color = ?"}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/EyeColors", arn);
    }

    @Test
    void dynamodbExecuteStatementDeleteFromQuotedTableBuildsTableArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statement":"DELETE FROM \\"Music\\" WHERE Artist = ?"}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Music", arn);
    }

    @Test
    void dynamodbBatchExecuteStatementUsesFirstStatementTable() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statements":[
                  {"Statement":"SELECT * FROM \\"Orders\\""},
                  {"Statement":"SELECT * FROM \\"Other\\""}
                ]}""");
        String arn = builder.build("dynamodb", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Orders", arn);
    }

    @Test
    void dynamodbBatchExecuteStatementBuildsAllTableArns() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Statements":[
                  {"Statement":"SELECT * FROM \\"Orders\\""},
                  {"Statement":"INSERT INTO \\"Other\\" VALUE {'pk': ?}"}
                ]}""");
        var arns = builder.buildAllDynamoDbPartiQLResources(ctx, REGION, ACCOUNT);
        assertEquals(2, arns.size());
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Orders", arns.get(0));
        assertEquals("arn:aws:dynamodb:us-east-1:222222222222:table/Other", arns.get(1));
    }

    @Test
    void extractPartiQLTableNameReturnsNullForBlankStatement() {
        assertNull(ResourceArnBuilder.extractPartiQLTableName("  "));
    }

    // ── Secrets Manager ───────────────────────────────────────────────────────

    @Test
    void secretsGetSecretValueBuildsSecretArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"SecretId\":\"market/relay/scanner-hint\"}");
        String arn = builder.build("secretsmanager", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:secretsmanager:us-east-1:222222222222:secret:market/relay/scanner-hint-000000", arn);
    }

    @Test
    void secretsBatchGetSecretValueUsesFirstSecretId() {
        ContainerRequestContext ctx = jsonBodyCtx(
                "{\"SecretIdList\":[\"allowed/secret\",\"other/secret\"]}");
        String arn = builder.build("secretsmanager", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:secretsmanager:us-east-1:222222222222:secret:allowed/secret-000000", arn);
    }

    @Test
    void secretsGetSecretValuePassesThroughFullArn() {
        String fullArn = "arn:aws:secretsmanager:us-east-1:222222222222:secret:my/full-arn-ABC123";
        ContainerRequestContext ctx = jsonBodyCtx("{\"SecretId\":\"" + fullArn + "\"}");
        String arn = builder.build("secretsmanager", ctx, REGION, ACCOUNT);
        assertEquals(fullArn, arn);
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
        ContainerRequestContext ctx = jsonBodyCtx("{\"AliasName\":\"alias/test-key\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kms:us-east-1:222222222222:alias/test-key", arn);
    }

    @Test
    void kmsDecryptBuildsKeyArnFromCiphertextBlob() {
        String blob = java.util.Base64.getEncoder().encodeToString("kms:v2:550e8400-e29b-41d4-a716-446655440000:iv:cipher".getBytes());
        ContainerRequestContext ctx = jsonBodyCtx("{\"CiphertextBlob\":\"" + blob + "\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:kms:us-east-1:222222222222:key/550e8400-e29b-41d4-a716-446655440000", arn);
    }

    @Test
    void kmsDecryptPreservesAliasArnFromKeyId() {
        String aliasArn = "arn:aws:kms:us-east-1:222222222222:alias/lab-key";
        ContainerRequestContext ctx = jsonBodyCtx("{\"KeyId\":\"" + aliasArn + "\"}");
        String arn = builder.build("kms", ctx, REGION, ACCOUNT);
        assertEquals(aliasArn, arn);
    }

    @Test
    void kmsDecryptBuildsKeyArnFromLegacyCiphertextBlob() {
        String blob = java.util.Base64.getEncoder().encodeToString(
                "kms:550e8400-e29b-41d4-a716-446655440000:cGF5bG9hZA==".getBytes());
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

    @Test
    void snsSubscribeUsesTopicArnNotSubscriptionArn() {
        String topicArn = "arn:aws:sns:us-east-1:222222222222:dispatch";
        String subscriptionArn = topicArn + ":sub-id";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=Subscribe&TopicArn=" + topicArn
                        + "&SubscriptionArn=" + subscriptionArn
                        + "&Protocol=sqs&Endpoint=arn:aws:sqs:us-east-1:222222222222:q");
        String arn = builder.build("sns", ctx, REGION, ACCOUNT);
        assertEquals(topicArn, arn);
    }

    @Test
    void snsConfirmSubscriptionUsesTopicArn() {
        String topicArn = "arn:aws:sns:us-east-1:222222222222:alerts";
        ContainerRequestContext ctx = formBodyCtx(
                "Action=ConfirmSubscription&TopicArn=" + topicArn + "&Token=abc123");
        String arn = builder.build("sns", ctx, REGION, ACCOUNT);
        assertEquals(topicArn, arn);
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
        ContainerRequestContext ctx = jsonBodyCtx("{\"repositoryName\":\"test/app\"}");
        String arn = builder.build("ecr", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:ecr:us-east-1:222222222222:repository/test/app", arn);
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

    // ── Cloud Map (servicediscovery) ────────────────────────────────────────────

    @Test
    void serviceDiscoveryCreateHttpNamespaceBuildsNamespaceWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Name":"demo-ns","Description":"test"}""");
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn("Route53AutoNaming_v20170314.CreateHttpNamespace");
        String arn = builder.build("servicediscovery", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:servicediscovery:us-east-1:222222222222:namespace/*", arn);
    }

    @Test
    void serviceDiscoveryGetNamespaceBuildsNamespaceArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Id\":\"ns-abc123\"}");
        String arn = builder.build("servicediscovery", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:servicediscovery:us-east-1:222222222222:namespace/ns-abc123", arn);
    }

    @Test
    void serviceDiscoveryCreateServiceBuildsServiceWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Name":"demo-svc","NamespaceId":"ns-abc123"}""");
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn("Route53AutoNaming_v20170314.CreateService");
        String arn = builder.build("servicediscovery", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:servicediscovery:us-east-1:222222222222:service/*", arn);
    }

    @Test
    void serviceDiscoveryRegisterInstanceBuildsServiceArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ServiceId":"srv-abc123","InstanceId":"i-1"}""");
        String arn = builder.build("servicediscovery", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:servicediscovery:us-east-1:222222222222:service/srv-abc123", arn);
    }

    @Test
    void eksCreateNodegroupBuildsClusterScopedNodegroupWildcard() {
        ContainerRequestContext ctx = pathCtx("/clusters/my-cluster/node-groups", jsonBodyCtx("{}"));
        String arn = builder.build("eks", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:eks:us-east-1:222222222222:nodegroup/my-cluster/*", arn);
    }

    @Test
    void eksDescribeNodegroupBuildsNodegroupArnFromPath() {
        ContainerRequestContext ctx = pathCtx("/clusters/my-cluster/node-groups/workers", jsonBodyCtx("{}"));
        String arn = builder.build("eks", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:eks:us-east-1:222222222222:nodegroup/my-cluster/workers/*", arn);
    }

    @Test
    void athenaCreateWorkGroupBuildsWorkgroupArnFromName() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"analytics\"}");
        String arn = builder.build("athena", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:athena:us-east-1:222222222222:workgroup/analytics", arn);
    }

    @Test
    void appSyncCreateGraphqlApiBuildsApisWildcard() {
        ContainerRequestContext ctx = pathCtx("/v1/apis", jsonBodyCtx("{}"));
        String arn = builder.build("appsync", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appsync:us-east-1:222222222222:apis/*", arn);
    }

    @Test
    void appSyncGetGraphqlApiBuildsApiArn() {
        ContainerRequestContext ctx = pathCtx("/v1/apis/abc123", jsonBodyCtx("{}"));
        String arn = builder.build("appsync", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appsync:us-east-1:222222222222:apis/abc123", arn);
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

    // ── CloudTrail ────────────────────────────────────────────────────────────

    @Test
    void cloudTrailStopLoggingBuildsTrailArnFromName() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"Name\":\"forensic-trail\"}");
        String arn = builder.build("cloudtrail", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudtrail:us-east-1:222222222222:trail/forensic-trail", arn);
    }

    @Test
    void cloudTrailUsesTrailArnFieldWhenPresent() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"TrailARN":"arn:aws:cloudtrail:us-east-1:222222222222:trail/explicit"}
                """);
        String arn = builder.build("cloudtrail", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudtrail:us-east-1:222222222222:trail/explicit", arn);
    }

    @Test
    void cloudTrailLookupEventsWithoutNameUsesTrailWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"MaxResults\":10}");
        String arn = builder.build("cloudtrail", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudtrail:us-east-1:222222222222:trail/*", arn);
    }

    // ── GuardDuty ─────────────────────────────────────────────────────────────

    @Test
    void guardDutyBuildsDetectorArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"DetectorId\":\"abc123detector\"}");
        String arn = builder.build("guardduty", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:guardduty:us-east-1:222222222222:detector/abc123detector", arn);
    }

    // ── AWS Config ────────────────────────────────────────────────────────────

    @Test
    void configPutConfigRuleBuildsRuleArnFromNestedName() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ConfigRule":{"ConfigRuleName":"rule-crud-test"}}
                """);
        String arn = builder.build("config", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:config:us-east-1:222222222222:config-rule/rule-crud-test", arn);
    }

    @Test
    void configUsesResourceArnWhenPresent() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ResourceArn":"arn:aws:s3:::my-bucket"}
                """);
        String arn = builder.build("config", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:s3:::my-bucket", arn);
    }

    // ── RDS Data API ────────────────────────────────────────────────────────────

    @Test
    void rdsDataExecuteUsesResourceArnFromBody() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"resourceArn":"arn:aws:rds:us-east-1:222222222222:cluster:lab-db"}
                """);
        String arn = builder.build("rds-data", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:rds:us-east-1:222222222222:cluster:lab-db", arn);
    }

    @Test
    void rdsDataMissingResourceArnFallsBackToClusterWildcard() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        String arn = builder.build("rds-data", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:rds:us-east-1:222222222222:cluster:*", arn);
    }

    // ── EMR ─────────────────────────────────────────────────────────────────────

    @Test
    void emrDescribeClusterBuildsClusterArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"ClusterId\":\"j-ABCDEFGHIJK1\"}");
        String arn = builder.build("elasticmapreduce", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:elasticmapreduce:us-east-1:222222222222:cluster/j-ABCDEFGHIJK1", arn);
    }

    @Test
    void emrJobFlowIdsBuildsAllClusterArns() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"JobFlowIds":["j-CLUSTERONE123","j-CLUSTERTWO456"]}
                """);
        var arns = builder.buildAllEmrClusterResources(ctx, REGION, ACCOUNT);
        assertEquals(2, arns.size());
        assertEquals("arn:aws:elasticmapreduce:us-east-1:222222222222:cluster/j-CLUSTERONE123", arns.get(0));
        assertEquals("arn:aws:elasticmapreduce:us-east-1:222222222222:cluster/j-CLUSTERTWO456", arns.get(1));
    }

    // ── WAFv2 ─────────────────────────────────────────────────────────────────

    @Test
    void wafV2GetWebAclBuildsScopedArnFromNameAndId() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget("""
                {"Scope":"REGIONAL","Name":"ctf-acl","Id":"abc12345-6789-0123-4567-890abcdef012"}
                """, "AWSWAF_20190729.GetWebACL");
        String arn = builder.build("wafv2", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:wafv2:us-east-1:222222222222:regional/webacl/ctf-acl/abc12345-6789-0123-4567-890abcdef012", arn);
    }

    @Test
    void wafV2CreateWebAclBuildsNameWildcardArn() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget("""
                {"Scope":"REGIONAL","Name":"ctf-acl"}
                """, "AWSWAF_20190729.CreateWebACL");
        String arn = builder.build("wafv2", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:wafv2:us-east-1:222222222222:regional/webacl/ctf-acl/*", arn);
    }

    // ── Security Hub ──────────────────────────────────────────────────────────

    @Test
    void securityHubDefaultsToHubArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        String arn = builder.build("securityhub", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:securityhub:us-east-1:222222222222:hub/default", arn);
    }

    // ── API Gateway v2 ────────────────────────────────────────────────────────

    @Test
    void apiGatewayV2UsesApiIdFromBody() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"ApiId\":\"abc123xyz0\"}");
        String arn = builder.build("apigatewayv2", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:apigateway:us-east-1::/apis/abc123xyz0", arn);
    }

    // ── CloudFront ────────────────────────────────────────────────────────────

    @Test
    void cloudFrontGetDistributionBuildsDistributionArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        ctx = pathCtx("2020-05-31/distribution/E1Z2X3C4V5B6N7", ctx);
        String arn = builder.build("cloudfront", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudfront::222222222222:distribution/E1Z2X3C4V5B6N7", arn);
    }

    @Test
    void cloudFrontCreateInvalidationUsesParentDistributionArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        ctx = pathCtx("2020-05-31/distribution/E1Z2X3C4V5B6N7/invalidation", ctx);
        String arn = builder.build("cloudfront", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cloudfront::222222222222:distribution/E1Z2X3C4V5B6N7", arn);
    }

    @Test
    void cloudFrontTaggingUsesResourceQueryParam() {
        String resourceArn = "arn:aws:cloudfront::222222222222:cache-policy/abcd1234-5678-90ab-cdef";
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("Resource", resourceArn);
        ContainerRequestContext ctx = ctxWithStream(
                query,
                MediaType.APPLICATION_XML_TYPE,
                new AtomicReference<>(new ByteArrayInputStream(new byte[0])));
        ctx = pathCtx("2020-05-31/tagging", query, ctx);
        String arn = builder.build("cloudfront", ctx, REGION, ACCOUNT);
        assertEquals(resourceArn, arn);
    }

    // ── Bedrock Runtime ───────────────────────────────────────────────────────

    @Test
    void bedrockConverseBuildsFoundationModelArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"messages":[{"role":"user","content":[{"text":"hi"}]}]}
                """);
        ctx = pathCtx("model/anthropic.claude-3-haiku-20240307-v1:0/converse", ctx);
        String arn = builder.build("bedrock-runtime", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:bedrock:us-east-1::foundation-model/anthropic.claude-3-haiku-20240307-v1:0", arn);
    }

    @Test
    void bedrockInvokePreservesFullModelArnFromPath() {
        String modelArn = "arn:aws:bedrock:us-east-1:123456789012:inference-profile/"
                + "us.anthropic.claude-3-5-sonnet-20241022-v2:0";
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        ctx = pathCtx("model/" + modelArn + "/invoke", ctx);
        String arn = builder.build("bedrock", ctx, REGION, ACCOUNT);
        assertEquals(modelArn, arn);
    }

    // ── Scheduler / Pipes / Kafka ─────────────────────────────────────────────

    @Test
    void schedulerBuildsScheduleArnFromPath() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        ctx = pathCtx("schedules/nightly-sync", ctx);
        String arn = builder.build("scheduler", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:scheduler:us-east-1:222222222222:schedule/default/nightly-sync", arn);
    }

    @Test
    void pipesBuildsPipeArnFromPath() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        ctx = pathCtx("v1/pipes/ingest-pipe", ctx);
        String arn = builder.build("pipes", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:pipes:us-east-1:222222222222:pipe/ingest-pipe", arn);
    }

    @Test
    void kafkaDescribeUsesClusterArnFromPath() {
        ContainerRequestContext ctx = jsonBodyCtx("{}");
        String clusterArn = "arn:aws:kafka:us-east-1:222222222222:cluster/demo/uuid";
        ctx = pathCtx("v1/clusters/" + clusterArn, ctx);
        String arn = builder.build("kafka", ctx, REGION, ACCOUNT);
        assertEquals(clusterArn, arn);
    }

    // ── CUR ───────────────────────────────────────────────────────────────────

    @Test
    void curDeleteReportDefinitionBuildsDefinitionArnFromReportName() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"ReportName\":\"monthly-report\"}");
        String arn = builder.build("cur", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cur:us-east-1:222222222222:definition/monthly-report", arn);
    }

    @Test
    void curPutReportDefinitionBuildsDefinitionArnFromNestedReportName() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ReportDefinition":{"ReportName":"daily-cost","TimeUnit":"DAILY"}}
                """);
        String arn = builder.build("cur", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cur:us-east-1:222222222222:definition/daily-cost", arn);
    }

    @Test
    void curDescribeReportDefinitionsBuildsDefinitionWildcard() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget(
                "{}",
                "AWSOrigamiServiceGatewayService.DescribeReportDefinitions");
        String arn = builder.build("cur", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:cur:us-east-1:222222222222:definition/*", arn);
    }

    // ── Transfer ────────────────────────────────────────────────────────────────

    @Test
    void transferDescribeServerBuildsServerArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"ServerId\":\"s-abc12345\"}");
        String arn = builder.build("transfer", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:transfer:us-east-1:222222222222:server/s-abc12345", arn);
    }

    @Test
    void transferDescribeUserBuildsUserArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ServerId":"s-abc12345","UserName":"player1"}
                """);
        String arn = builder.build("transfer", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:transfer:us-east-1:222222222222:user/s-abc12345/player1", arn);
    }

    // ── Transcribe ────────────────────────────────────────────────────────────

    @Test
    void transcribeGetTranscriptionJobBuildsJobArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"TranscriptionJobName\":\"interview-audio\"}");
        String arn = builder.build("transcribe", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:transcribe:us-east-1:222222222222:transcription-job/interview-audio", arn);
    }

    @Test
    void transcribeGetVocabularyBuildsVocabularyArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"VocabularyName\":\"ctf-terms\"}");
        String arn = builder.build("transcribe", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:transcribe:us-east-1:222222222222:vocabulary/ctf-terms", arn);
    }

    // ── AppConfig ───────────────────────────────────────────────────────────────

    @Test
    void appConfigGetApplicationBuildsApplicationArn() {
        ContainerRequestContext ctx = pathCtx("applications/app12345", jsonBodyCtx("{}"));
        String arn = builder.build("appconfig", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appconfig:us-east-1:222222222222:application/app12345", arn);
    }

    @Test
    void appConfigGetEnvironmentBuildsEnvironmentArn() {
        ContainerRequestContext ctx = pathCtx("applications/app12345/environments/env67890", jsonBodyCtx("{}"));
        String arn = builder.build("appconfig", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appconfig:us-east-1:222222222222:application/app12345/environment/env67890", arn);
    }

    @Test
    void appConfigGetConfigurationProfileBuildsProfileArn() {
        ContainerRequestContext ctx = pathCtx("applications/app12345/configurationprofiles/prof11111", jsonBodyCtx("{}"));
        String arn = builder.build("appconfig", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appconfig:us-east-1:222222222222:application/app12345/configurationprofile/prof11111", arn);
    }

    // ── AppConfig Data ──────────────────────────────────────────────────────────

    @Test
    void appConfigDataStartSessionBuildsConfigurationArn() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ApplicationIdentifier":"app12345","EnvironmentIdentifier":"env67890","ConfigurationProfileIdentifier":"prof11111"}
                """);
        String arn = builder.build("appconfigdata", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:appconfig:us-east-1:222222222222:application/app12345/environment/env67890/configuration/prof11111", arn);
    }

    // ── Textract ────────────────────────────────────────────────────────────────

    @Test
    void textractGetDocumentAnalysisBuildsJobArn() {
        ContainerRequestContext ctx = jsonBodyCtx("{\"JobId\":\"abc123job456\"}");
        String arn = builder.build("textract", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:textract:us-east-1:222222222222:job/abc123job456", arn);
    }

    // ── BCM Data Exports ──────────────────────────────────────────────────────

    @Test
    void bcmDataExportsGetExportUsesExportArnField() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"ExportArn":"arn:aws:bcm-data-exports:us-east-1:222222222222:export/focus-monthly"}
                """);
        String arn = builder.build("bcm-data-exports", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:bcm-data-exports:us-east-1:222222222222:export/focus-monthly", arn);
    }

    @Test
    void bcmDataExportsCreateExportBuildsExportArnFromNestedName() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget("""
                {"Export":{"Name":"focus-monthly","Description":"FOCUS export"}}
                """, "AWSBillingAndCostManagementDataExports.CreateExport");
        String arn = builder.build("bcm-data-exports", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:bcm-data-exports:us-east-1:222222222222:export/focus-monthly", arn);
    }

    @Test
    void bcmDataExportsListExportsBuildsExportWildcard() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget(
                "{}",
                "AWSBillingAndCostManagementDataExports.ListExports");
        String arn = builder.build("bcm-data-exports", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:bcm-data-exports:us-east-1:222222222222:export/*", arn);
    }

    @Test
    void taggingTagResourcesUsesFirstResourceArn() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget("""
                {"ResourceARNList":["arn:aws:s3:::allowed-bucket","arn:aws:s3:::decoy-bucket"],
                 "Tags":{"env":"ctf"}}
                """, "ResourceGroupsTaggingAPI_20170126.TagResources");
        String arn = builder.build("tagging", ctx, REGION, ACCOUNT);
        assertEquals("arn:aws:s3:::allowed-bucket", arn);
    }

    @Test
    void taggingBuildsAllResourceArns() {
        ContainerRequestContext ctx = jsonBodyCtxWithTarget("""
                {"ResourceARNList":["arn:aws:s3:::a","arn:aws:s3:::b"]}
                """, "ResourceGroupsTaggingAPI_20170126.UntagResources");
        var arns = builder.buildAllTaggingResources(ctx);
        assertEquals(2, arns.size());
        assertEquals("arn:aws:s3:::a", arns.get(0));
        assertEquals("arn:aws:s3:::b", arns.get(1));
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

    private static ContainerRequestContext jsonBodyCtxWithTarget(String json, String target) {
        ContainerRequestContext ctx = jsonBodyCtx(json);
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn(target);
        return ctx;
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
        return pathCtx(path, new MultivaluedHashMap<>(), base);
    }

    private static ContainerRequestContext pathCtx(String path,
                                                   MultivaluedMap<String, String> queryParams,
                                                   ContainerRequestContext base) {
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
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
