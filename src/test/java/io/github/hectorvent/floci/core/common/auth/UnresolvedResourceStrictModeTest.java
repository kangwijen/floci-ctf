package io.github.hectorvent.floci.core.common.auth;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.AnonymousAccessGate;
import io.github.hectorvent.floci.core.common.CtfHideInternalEndpointsMode;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver;
import io.github.hectorvent.floci.core.common.IamEnforcementFilter;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.lambda.LambdaAliasStore;
import io.github.hectorvent.floci.services.lambda.LambdaFunctionStore;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * B.2 / O11 / O12: UNRESOLVED resources and bare-{@code *} multi-resource skips must not
 * authorize under CTF/strict. Unmapped actions deny when enforcement is on.
 */
@Tag("security-regression")
class UnresolvedResourceStrictModeTest {

    private static final String AKID = "AKIAUNRESOLVED01";
    private static final String ACCOUNT = "222222222222";

    @Test
    void strictDeniesWhenBuilderReturnsUnresolved() {
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ContainerRequestContext ctx = authCtx("lambda", "/2015-03-31/functions/fn/invocations");
        when(arnBuilder.build("lambda", ctx, "us-east-1", ACCOUNT))
                .thenReturn(ResourceRef.unresolvedToken("lambda-url-unknown-urlId"));

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolveRestRouteScope(ctx)).thenReturn(null);
        when(actionRegistry.resolve("lambda", ctx)).thenReturn("lambda:InvokeFunction");

        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext(AKID))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"*","Resource":"*"}
                        ]}""")));

        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamEnforcementFilter filter = buildFilter(
                ctx, actionRegistry, arnBuilder, evaluator, iamService, true);

        filter.filter(ctx);

        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(responseCaptor.capture());
        assertEquals(403, responseCaptor.getValue().getStatus());
        verify(evaluator, never()).evaluate(any(), any(), anyString(), anyString(), any());
    }

    @Test
    void strictStopsBareStarSkipInMultiResourceLoop() {
        // Historical bug: evaluateEmrMultiCluster skipped "*" entries, so a Deny on "*" never ran.
        ResourceArnBuilder stubBuilder = mock(ResourceArnBuilder.class);
        ContainerRequestContext multiCtx = jsonBodyAuthCtx(
                "elasticmapreduce",
                """
                        {"JobFlowIds":["j-1","j-2"]}
                        """);
        when(multiCtx.getHeaderString("X-Amz-Target")).thenReturn("ElasticMapReduce.TerminateJobFlows");
        when(stubBuilder.buildAllEmrClusterResources(multiCtx, "us-east-1", ACCOUNT))
                .thenReturn(List.of("*", "*"));

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("elasticmapreduce", multiCtx))
                .thenReturn("elasticmapreduce:TerminateJobFlows");

        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext(AKID))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Deny","Action":"elasticmapreduce:TerminateJobFlows","Resource":"*"}
                        ]}""")));

        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("elasticmapreduce"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());

        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        IamEnforcementFilter filter = buildFilter(
                multiCtx, actionRegistry, stubBuilder, evaluator, iamService, resourcePolicyResolver, true);

        filter.filter(multiCtx);

        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(multiCtx).abortWith(responseCaptor.capture());
        assertEquals(403, responseCaptor.getValue().getStatus());
    }

    @Test
    void unmappedActionDeniedWhenEnforcementOnEvenIfNotStrict() {
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ContainerRequestContext ctx = authCtx("lambda", "/2015-03-31/functions/fn/invocations");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolveRestRouteScope(ctx)).thenReturn(null);
        when(actionRegistry.resolve("lambda", ctx)).thenReturn(null);

        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamEnforcementFilter filter = buildFilter(
                ctx, actionRegistry, arnBuilder, evaluator, iamService, false);

        filter.filter(ctx);

        ArgumentCaptor<Response> responseCaptor = ArgumentCaptor.forClass(Response.class);
        verify(ctx).abortWith(responseCaptor.capture());
        assertEquals(403, responseCaptor.getValue().getStatus());
        verify(evaluator, never()).evaluate(any(), any(), anyString(), anyString(), any());
        verify(arnBuilder, never()).build(anyString(), any(), anyString(), anyString());
    }

    @Test
    void unknownLambdaUrlIdBuildsUnresolvedNotFunctionWildcard() {
        ResourceArnBuilder builder = new ResourceArnBuilder(
                new ObjectMapper(), null, mock(LambdaFunctionStore.class), mock(LambdaAliasStore.class));
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getPath()).thenReturn("lambda-url/deadbeefdeadbeefdeadbeefdeadbeef/");
        when(ctx.getUriInfo()).thenReturn(uriInfo);

        String arn = builder.build("lambda", ctx, "us-east-1", ACCOUNT);

        assertTrue(ResourceRef.isUnresolvedToken(arn), arn);
        assertTrue(ResourceRef.fromBuilt(arn).isUnresolved());
    }

    private static IamEnforcementFilter buildFilter(
            ContainerRequestContext ctx,
            IamActionRegistry actionRegistry,
            ResourceArnBuilder arnBuilder,
            IamPolicyEvaluator evaluator,
            IamService iamService,
            boolean strict) {
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(anyString(), anyString(), anyString())).thenReturn(List.of());
        return buildFilter(ctx, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver, strict);
    }

    private static IamEnforcementFilter buildFilter(
            ContainerRequestContext ctx,
            IamActionRegistry actionRegistry,
            ResourceArnBuilder arnBuilder,
            IamPolicyEvaluator evaluator,
            IamService iamService,
            ResourcePolicyResolver resourcePolicyResolver,
            boolean strict) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctfConfig = mock(EmulatorConfig.CtfConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId(ACCOUNT);

        String scope = scopeFromAuthHeader(ctx);
        String auth = "AWS4-HMAC-SHA256 Credential=" + AKID + "/20260629/us-east-1/" + scope
                + "/aws4_request, SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(strict);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(authConfig.validateSignatures()).thenReturn(false);
        when(config.ctf()).thenReturn(ctfConfig);
        when(ctfConfig.hideInternalEndpointsMode()).thenReturn(CtfHideInternalEndpointsMode.PREFIXED);
        when(ctfConfig.validateFederatedTokens()).thenReturn(false);
        when(ctfConfig.blockPrivateOutboundUrls()).thenReturn(false);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn(AKID);
        when(accountResolver.resolve(auth)).thenReturn(ACCOUNT);
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(ctx.getHeaderString("Authorization")).thenReturn(auth);

        return new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, mock(KmsService.class),
                mock(AnonymousAccessGate.class), requestContext, new IamConditionContextResolver());
    }

    private static String scopeFromAuthHeader(ContainerRequestContext ctx) {
        String existing = ctx.getHeaderString("Authorization");
        if (existing != null && existing.contains("/elasticmapreduce/")) {
            return "elasticmapreduce";
        }
        return "lambda";
    }

    private static ContainerRequestContext authCtx(String scope, String path) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getPath()).thenReturn(path);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn("POST");
        when(ctx.getMediaType()).thenReturn(MediaType.APPLICATION_JSON_TYPE);
        String auth = "AWS4-HMAC-SHA256 Credential=" + AKID + "/20260629/us-east-1/" + scope
                + "/aws4_request, SignedHeaders=host, Signature=abc";
        when(ctx.getHeaderString("Authorization")).thenReturn(auth);
        return ctx;
    }

    private static ContainerRequestContext jsonBodyAuthCtx(String scope, String json) {
        ContainerRequestContext ctx = authCtx(scope, "/");
        when(ctx.getMediaType()).thenReturn(MediaType.valueOf("application/x-amz-json-1.1"));

        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(json.getBytes(StandardCharsets.UTF_8)));
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));

        Map<String, Object> properties = new HashMap<>();
        when(ctx.getProperty(anyString())).thenAnswer(inv -> properties.get(inv.getArgument(0)));
        doAnswer(inv -> {
            properties.put(inv.getArgument(0), inv.getArgument(1));
            return null;
        }).when(ctx).setProperty(anyString(), any());

        return ctx;
    }
}
