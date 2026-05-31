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
