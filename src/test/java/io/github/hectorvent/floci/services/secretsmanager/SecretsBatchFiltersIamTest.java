package io.github.hectorvent.floci.services.secretsmanager;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.AnonymousAccessGate;
import io.github.hectorvent.floci.core.common.IamConditionContextResolver;
import io.github.hectorvent.floci.core.common.IamEnforcementFilter;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.secretsmanager.model.Secret;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * O21: BatchGetSecretValue Filters must authorize each matched secret.
 */
@Tag("security-regression")
class SecretsBatchFiltersIamTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";

    private SecretsManagerService secretsService;
    private ResourceArnBuilder arnBuilder;

    @BeforeEach
    void setUp() {
        secretsService = new SecretsManagerService(new InMemoryStorage<>(), 30);
        secretsService.createSecret("allowed/secret", "a", null, null, null, null, REGION);
        secretsService.createSecret("flag-secret", "flag", null, null, null, null, REGION);
        secretsService.createSecret("other/secret", "o", null, null, null, null, REGION);
        arnBuilder = new ResourceArnBuilder(new ObjectMapper(), secretsService);
    }

    @Test
    void buildAllBatchResourcesIncludesSecretsMatchedByFilters() {
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Filters":[{"Key":"name","Values":["allowed/","flag-"]}]}""");

        List<String> arns = arnBuilder.buildAllSecretsManagerBatchResources(ctx, REGION, ACCOUNT);

        assertEquals(2, arns.size());
        assertTrue(arns.stream().anyMatch(a -> a.contains("secret:allowed/secret")));
        assertTrue(arns.stream().anyMatch(a -> a.contains("secret:flag-secret")));
    }

    @Test
    void batchGetSecretValueFiltersDeniesWhenAnyMatchedSecretIsDenied() {
        Secret allowed = secretsService.describeSecret("allowed/secret", REGION);
        ContainerRequestContext ctx = jsonBodyCtx("""
                {"Filters":[{"Key":"name","Values":["allowed/","flag-"]}]}""");
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn("secretsmanager.BatchGetSecretValue");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("secretsmanager", ctx)).thenReturn("secretsmanager:BatchGetSecretValue");

        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIASECRETS"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"secretsmanager:BatchGetSecretValue",
                           "Resource":"%s"}
                        ]}""".formatted(allowed.getArn()))));

        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("secretsmanager"), anyString(), eq(REGION)))
                .thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(ctx, actionRegistry, iamService, resourcePolicyResolver);
        filter.filter(ctx);

        verify(ctx).abortWith(any());
    }

    private IamEnforcementFilter buildFilter(ContainerRequestContext ctx,
                                             IamActionRegistry actionRegistry,
                                             IamService iamService,
                                             ResourcePolicyResolver resourcePolicyResolver) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId(ACCOUNT);

        String akid = "AKIASECRETS";
        String auth = "AWS4-HMAC-SHA256 Credential=" + akid
                + "/20260629/" + REGION + "/secretsmanager/aws4_request, SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(false);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(accountResolver.extractAccessKeyId(auth)).thenReturn(akid);
        when(accountResolver.resolve(auth)).thenReturn(ACCOUNT);
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn(REGION);
        when(ctx.getHeaderString("Authorization")).thenReturn(auth);

        return new IamEnforcementFilter(
                config, accountResolver, iamService, new IamPolicyEvaluator(new ObjectMapper()),
                actionRegistry, arnBuilder, resourcePolicyResolver, regionResolver, mock(KmsService.class),
                mock(AnonymousAccessGate.class), requestContext, new IamConditionContextResolver());
    }

    private static ContainerRequestContext jsonBodyCtx(String json) {
        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(uriInfo.getPath()).thenReturn("/");
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn("POST");
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
