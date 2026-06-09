package io.github.hectorvent.floci.services.iam;

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
 * Unit tests for {@link IamActionRegistry}, focused on the protocol-aware
 * {@code Action} extraction. The HTTP filter path is covered by SDK
 * compatibility tests; these tests pin the resolver behavior directly.
 */
class IamActionRegistryTest {

    private final IamActionRegistry registry = new IamActionRegistry();

    @Test
    void resolvesActionFromFormEncodedBody() {
        // AWS SDKs send Query-protocol calls as POST with
        // application/x-www-form-urlencoded body — Action=ListUsers&Version=...
        ContainerRequestContext ctx = mockCtx(
                "POST", "/",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                "Action=ListUsers&Version=2010-05-08&UserName=alice");
        assertEquals("iam:ListUsers", registry.resolve("iam", ctx));
    }

    @Test
    void resolvesUrlEncodedActionValueFromFormBody() {
        ContainerRequestContext ctx = mockCtx(
                "POST", "/",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                "Action=Get%2BCallerIdentity");
        assertEquals("sts:GetCallerIdentity", registry.resolve("sts", ctx));
    }

    @Test
    void prefersUrlQueryActionOverFormBody() {
        // Some clients (older AWS CLI, curl) send Query-protocol requests with
        // Action in the URL query string; that path must keep working.
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("Action", "ListUsers");
        ContainerRequestContext ctx = mockCtx(
                "POST", "/",
                query,
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                "Action=DeleteUser");
        assertEquals("iam:ListUsers", registry.resolve("iam", ctx));
    }

    @Test
    void s3ListObjectVersionsMapsToListBucketVersions() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("versions", "");
        ContainerRequestContext ctx = mockCtx("GET", "/my-bucket", query, null, "");
        assertEquals("s3:ListBucketVersions", registry.resolve("s3", ctx));
    }

    @Test
    void s3GetObjectWithVersionIdMapsToGetObjectVersion() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("versionId", "abc-version");
        ContainerRequestContext ctx = mockCtx("GET", "/my-bucket/my-key", query, null, "");
        assertEquals("s3:GetObjectVersion", registry.resolve("s3", ctx));
    }

    @Test
    void s3PutBucketVersioningMapsCorrectly() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("versioning", "");
        ContainerRequestContext ctx = mockCtx("PUT", "/my-bucket", query, null, "");
        assertEquals("s3:PutBucketVersioning", registry.resolve("s3", ctx));
    }

    @Test
    void formBodyIsRestoredForDownstreamConsumers() throws Exception {
        String body = "Action=ListUsers&Version=2010-05-08";
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        ContainerRequestContext ctx = mockCtxWithStream(
                "POST", "/",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE,
                streamRef);

        registry.resolve("iam", ctx);

        // Downstream resource method must still see the full form body.
        byte[] remaining = streamRef.get().readAllBytes();
        assertEquals(body, new String(remaining, StandardCharsets.UTF_8));
    }

    @Test
    void resolvesJson11ActionFromXAmzTarget() {
        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(uriInfo.getPath()).thenReturn("/");
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMediaType()).thenReturn(MediaType.valueOf("application/x-amz-json-1.0"));
        when(ctx.getMethod()).thenReturn("POST");
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn("DynamoDB_20120810.PutItem");
        assertEquals("dynamodb:PutItem", registry.resolve("dynamodb", ctx));
    }

    @Test
    void resolvesJson11GetItemFromXAmzTarget() {
        ContainerRequestContext ctx = dynamodbTargetCtx("DynamoDB_20120810.GetItem");
        assertEquals("dynamodb:GetItem", registry.resolve("dynamodb", ctx));
    }

    @Test
    void resolvesJson11QueryFromXAmzTarget() {
        ContainerRequestContext ctx = dynamodbTargetCtx("DynamoDB_20120810.Query");
        assertEquals("dynamodb:Query", registry.resolve("dynamodb", ctx));
    }

    @Test
    void executeStatementSelectMapsToPartiQLSelect() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.ExecuteStatement",
                "{\"Statement\":\"SELECT * FROM \\\"Music\\\" WHERE Artist = ?\"}");
        assertEquals("dynamodb:PartiQLSelect", registry.resolve("dynamodb", ctx));
    }

    @Test
    void executeStatementInsertMapsToPartiQLInsert() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.ExecuteStatement",
                "{\"Statement\":\"INSERT INTO Flowers VALUE {'Name': ?}\"}");
        assertEquals("dynamodb:PartiQLInsert", registry.resolve("dynamodb", ctx));
    }

    @Test
    void executeStatementUpdateMapsToPartiQLUpdate() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.ExecuteStatement",
                "{\"Statement\":\"UPDATE EyeColors SET IsRecessive = ? WHERE Color = ?\"}");
        assertEquals("dynamodb:PartiQLUpdate", registry.resolve("dynamodb", ctx));
    }

    @Test
    void executeStatementDeleteMapsToPartiQLDelete() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.ExecuteStatement",
                "{\"Statement\":\"DELETE FROM \\\"Music\\\" WHERE Artist = ?\"}");
        assertEquals("dynamodb:PartiQLDelete", registry.resolve("dynamodb", ctx));
    }

    @Test
    void batchExecuteStatementUsesFirstStatementForAction() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.BatchExecuteStatement",
                "{\"Statements\":[{\"Statement\":\"UPDATE Eggs SET Style = ? WHERE Variety = ?\"}]}");
        assertEquals("dynamodb:PartiQLUpdate", registry.resolve("dynamodb", ctx));
    }

    @Test
    void batchExecuteStatementResolvesAllStatementActions() {
        ContainerRequestContext ctx = dynamodbTargetWithBody(
                "DynamoDB_20120810.BatchExecuteStatement",
                """
                {"Statements":[
                  {"Statement":"SELECT * FROM \\"Orders\\""},
                  {"Statement":"INSERT INTO \\"Other\\" VALUE {'pk': ?}"}
                ]}""");
        var actions = registry.resolveAllDynamoDbBatchActions(ctx);
        assertEquals(2, actions.size());
        assertEquals("dynamodb:PartiQLSelect", actions.get(0));
        assertEquals("dynamodb:PartiQLInsert", actions.get(1));
    }

    @Test
    void resolvesAppSyncCreateGraphqlApiFromRestPath() {
        ContainerRequestContext ctx = mockCtx(
                "POST", "/v1/apis",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_JSON_TYPE,
                "{\"name\":\"demo\",\"authenticationType\":\"API_KEY\"}");
        assertEquals("appsync:CreateGraphqlApi", registry.resolve("appsync", ctx));
    }

    @Test
    void resolvesEksCreateNodegroupFromRestPath() {
        ContainerRequestContext ctx = mockCtx(
                "POST", "/clusters/my-cluster/node-groups",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_JSON_TYPE,
                "{\"nodegroupName\":\"ng1\"}");
        assertEquals("eks:CreateNodegroup", registry.resolve("eks", ctx));
    }

    @Test
    void resolvesAppSyncGetGraphqlApiFromRestPath() {
        ContainerRequestContext ctx = mockCtx(
                "GET", "/v1/apis/abc123",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_JSON_TYPE,
                "");
        assertEquals("appsync:GetGraphqlApi", registry.resolve("appsync", ctx));
    }

    @Test
    void returnsNullForUnknownRestJsonRoute() {
        ContainerRequestContext ctx = mockCtx(
                "POST", "/some/unknown/path",
                new MultivaluedHashMap<>(),
                MediaType.APPLICATION_JSON_TYPE,
                "");
        assertNull(registry.resolve("kms", ctx));
    }

    // -------------------------------------------------------------------------

    private static ContainerRequestContext dynamodbTargetCtx(String target) {
        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(uriInfo.getPath()).thenReturn("/");
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMediaType()).thenReturn(MediaType.valueOf("application/x-amz-json-1.0"));
        when(ctx.getMethod()).thenReturn("POST");
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn(target);
        return ctx;
    }

    private static ContainerRequestContext dynamodbTargetWithBody(String target, String body) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        ContainerRequestContext ctx = dynamodbTargetCtx(target);
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
        return ctx;
    }

    private static ContainerRequestContext mockCtx(String method, String path,
                                                   MultivaluedMap<String, String> queryParams,
                                                   MediaType mediaType, String body) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        return mockCtxWithStream(method, path, queryParams, mediaType, streamRef);
    }

    private static ContainerRequestContext mockCtxWithStream(String method, String path,
                                                             MultivaluedMap<String, String> queryParams,
                                                             MediaType mediaType,
                                                             AtomicReference<InputStream> streamRef) {
        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(uriInfo.getPath()).thenReturn(path);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMediaType()).thenReturn(mediaType);
        when(ctx.getMethod()).thenReturn(method);
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
        return ctx;
    }
}