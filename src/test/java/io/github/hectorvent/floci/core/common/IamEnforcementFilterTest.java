package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.container.ContainerRequestContext;
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
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.argThat;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IamEnforcementFilter#accessDeniedResponse}, focused on
 * the protocol-aware response shape. AWS SDKs hard-fail on wrong-shape error
 * payloads — an XML parser blows up on a leading {@code "{"} and a JSON parser
 * blows up on a leading {@code "<"} — so each protocol has to get the right
 * envelope.
 */
class IamEnforcementFilterTest {

    @Test
    void filterBuildsResourceArnWithAccountFromRequestContext() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctfConfig = mock(EmulatorConfig.CtfConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("222233334444");
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);

        String auth = "AWS4-HMAC-SHA256 Credential=ASIASESSION/20260629/us-east-1/lambda/aws4_request, "
                + "SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(config.ctf()).thenReturn(ctfConfig);
        when(ctfConfig.hideInternalEndpointsMode()).thenReturn(CtfHideInternalEndpointsMode.PREFIXED);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn("ASIASESSION");
        // AccountResolver alone collapses ASIA keys to the default account.
        when(accountResolver.resolve(auth)).thenReturn("000000000000");
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/2015-03-31/functions/fn/invocations");
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(actionRegistry.resolveRestRouteScope(containerRequest)).thenReturn(null);
        when(actionRegistry.resolve("lambda", containerRequest)).thenReturn("lambda:InvokeFunction");
        when(iamService.resolveCallerContext("ASIASESSION"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"lambda:InvokeFunction",
                           "Resource":"arn:aws:lambda:us-east-1:222233334444:function:fn"}
                        ]}""")));
        when(arnBuilder.build("lambda", containerRequest, "us-east-1", "222233334444"))
                .thenReturn("arn:aws:lambda:us-east-1:222233334444:function:fn");
        when(resourcePolicyResolver.resolve(eq("lambda"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("lambda:InvokeFunction"),
                eq("arn:aws:lambda:us-east-1:222233334444:function:fn"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        filter.filter(containerRequest);

        verify(arnBuilder).build("lambda", containerRequest, "us-east-1", "222233334444");
    }

    @Test
    void filterBuildsResourceArnViaSessionLookupWhenRequestContextUnset() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctfConfig = mock(EmulatorConfig.CtfConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);

        String auth = "AWS4-HMAC-SHA256 Credential=ASIASESSION/20260629/us-east-1/lambda/aws4_request, "
                + "SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(config.ctf()).thenReturn(ctfConfig);
        when(ctfConfig.hideInternalEndpointsMode()).thenReturn(CtfHideInternalEndpointsMode.PREFIXED);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn("ASIASESSION");
        when(accountResolver.resolve(auth)).thenReturn("000000000000");
        when(iamService.resolveAccountId("ASIASESSION")).thenReturn(Optional.of("222233334444"));
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/2015-03-31/functions/fn/invocations");
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(actionRegistry.resolveRestRouteScope(containerRequest)).thenReturn(null);
        when(actionRegistry.resolve("lambda", containerRequest)).thenReturn("lambda:InvokeFunction");
        when(iamService.resolveCallerContext("ASIASESSION"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"lambda:InvokeFunction",
                           "Resource":"arn:aws:lambda:us-east-1:222233334444:function:fn"}
                        ]}""")));
        when(arnBuilder.build("lambda", containerRequest, "us-east-1", "222233334444"))
                .thenReturn("arn:aws:lambda:us-east-1:222233334444:function:fn");
        when(resourcePolicyResolver.resolve(eq("lambda"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("lambda:InvokeFunction"),
                eq("arn:aws:lambda:us-east-1:222233334444:function:fn"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        filter.filter(containerRequest);

        verify(arnBuilder).build("lambda", containerRequest, "us-east-1", "222233334444");
    }

    @Test
    void enforcePresignedS3UsesSessionAccountNotDefault() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("555566667777");
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedHashMap<String, String> query = new MultivaluedHashMap<>();
        String credential = "ASIAPRESIGNED/20260629/us-east-1/s3/aws4_request";
        query.add("X-Amz-Algorithm", "AWS4-HMAC-SHA256");
        query.add("X-Amz-Credential", credential);

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(accountResolver.extractAccessKeyIdFromCredential(credential)).thenReturn("ASIAPRESIGNED");
        when(accountResolver.resolveFromPresignedCredential(credential)).thenReturn("000000000000");
        when(accountResolver.defaultAccountId()).thenReturn("000000000000");
        when(regionResolver.getDefaultRegion()).thenReturn("us-east-1");
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/bucket/key");
        when(uriInfo.getQueryParameters()).thenReturn(query);
        when(containerRequest.getProperty(io.github.hectorvent.floci.services.s3.PreSignedUrlFilter.PRESIGN_VERIFIED_PROPERTY))
                .thenReturn(Boolean.TRUE);
        when(actionRegistry.resolve("s3", containerRequest)).thenReturn("s3:GetObject");
        when(iamService.resolveCallerContext("ASIAPRESIGNED"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"s3:GetObject",
                           "Resource":"arn:aws:s3:::bucket/key"}
                        ]}""")));
        when(arnBuilder.build("s3", containerRequest, "us-east-1", "555566667777"))
                .thenReturn("arn:aws:s3:::bucket/key");
        when(resourcePolicyResolver.resolve(eq("s3"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("s3:GetObject"),
                eq("arn:aws:s3:::bucket/key"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        filter.filter(containerRequest);

        verify(arnBuilder).build("s3", containerRequest, "us-east-1", "555566667777");
    }

    @Test
    void filterPassesS3ListBucketConditionContext() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctfConfig = mock(EmulatorConfig.CtfConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("222233334444");
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedHashMap<String, String> query = new MultivaluedHashMap<>();
        query.add("prefix", "my_namespace/table/");
        query.add("delimiter", "/");
        query.add("max-keys", "10");
        String auth = "AWS4-HMAC-SHA256 Credential=ASIASESSION/20260629/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(config.ctf()).thenReturn(ctfConfig);
        when(ctfConfig.hideInternalEndpointsMode()).thenReturn(CtfHideInternalEndpointsMode.PREFIXED);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn("ASIASESSION");
        when(accountResolver.resolve(auth)).thenReturn("000000000000");
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/bucket");
        when(uriInfo.getQueryParameters()).thenReturn(query);
        when(actionRegistry.resolveRestRouteScope(containerRequest)).thenReturn(null);
        when(actionRegistry.resolve("s3", containerRequest)).thenReturn("s3:ListBucket");
        when(iamService.resolveCallerContext("ASIASESSION"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"s3:ListBucket","Resource":"arn:aws:s3:::bucket"}
                        ]}""")));
        when(arnBuilder.build("s3", containerRequest, "us-east-1", "222233334444"))
                .thenReturn("arn:aws:s3:::bucket");
        when(resourcePolicyResolver.resolve(eq("s3"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("s3:ListBucket"), eq("arn:aws:s3:::bucket"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        filter.filter(containerRequest);

        verify(evaluator).evaluate(any(), any(), eq("s3:ListBucket"), eq("arn:aws:s3:::bucket"),
                argThat(context -> "my_namespace/table/".equals(context.get("s3:prefix"))
                        && "/".equals(context.get("s3:delimiter"))
                        && "10".equals(context.get("s3:max-keys"))));
    }

    // ── aws:RequestedRegion / aws:CurrentTime / aws:EpochTime condition keys ────

    /**
     * These condition keys let identity and resource policies scope access by region and time
     * (e.g. {@code aws:RequestedRegion} region-locking, {@code aws:EpochTime} temporary access
     * windows). Before this fix {@code buildConditionContext} omitted all three, so any policy
     * relying on them silently evaluated as if the condition key were absent — for
     * {@code StringEquals}/{@code DateGreaterThan} conditions that meant the statement never
     * matched, effectively disabling the restriction rather than enforcing it.
     */
    @Test
    void buildConditionContextIncludesRequestedRegionCurrentTimeAndEpochTime() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("222233334444");
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);

        String auth = "AWS4-HMAC-SHA256 Credential=AKIAREGIONCHECK/20260629/eu-west-1/lambda/aws4_request, "
                + "SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(authConfig.trustForwardedHeaders()).thenReturn(false);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn("AKIAREGIONCHECK");
        when(accountResolver.resolve(auth)).thenReturn("222233334444");
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("eu-west-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/2015-03-31/functions/fn/invocations");
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(actionRegistry.resolveRestRouteScope(containerRequest)).thenReturn(null);
        when(actionRegistry.resolve("lambda", containerRequest)).thenReturn("lambda:InvokeFunction");
        when(iamService.resolveCallerContext("AKIAREGIONCHECK"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"lambda:InvokeFunction",
                           "Resource":"arn:aws:lambda:eu-west-1:222233334444:function:fn"}
                        ]}""")));
        when(arnBuilder.build("lambda", containerRequest, "eu-west-1", "222233334444"))
                .thenReturn("arn:aws:lambda:eu-west-1:222233334444:function:fn");
        when(resourcePolicyResolver.resolve(eq("lambda"), anyString(), eq("eu-west-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("lambda:InvokeFunction"),
                eq("arn:aws:lambda:eu-west-1:222233334444:function:fn"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        long before = java.time.Instant.now().getEpochSecond();
        filter.filter(containerRequest);
        long after = java.time.Instant.now().getEpochSecond();

        verify(evaluator).evaluate(any(), any(), eq("lambda:InvokeFunction"),
                eq("arn:aws:lambda:eu-west-1:222233334444:function:fn"),
                argThat(context -> {
                    if (!"eu-west-1".equals(context.get("aws:requestedregion"))) {
                        return false;
                    }
                    String currentTime = context.get("aws:currenttime");
                    if (currentTime == null) {
                        return false;
                    }
                    java.time.Instant.parse(currentTime);
                    String epochTime = context.get("aws:epochtime");
                    if (epochTime == null) {
                        return false;
                    }
                    long epoch = Long.parseLong(epochTime);
                    return epoch >= before && epoch <= after;
                }));
    }

    // ── S3 CopyObject / UploadPartCopy: s3:GetObject on x-amz-copy-source ────

    /**
     * CopyObject and UploadPartCopy carry an {@code x-amz-copy-source} header naming the object
     * being read. The main filter path only checks {@code s3:PutObject} on the destination; AWS
     * separately requires {@code s3:GetObject} on the source. A caller with {@code s3:PutObject}
     * on their own bucket but no read access to the source object must be denied.
     */
    @Test
    void s3CopyObjectDeniesWhenSourceGetObjectIsDenied() {
        CopyTestHarness h = buildCopySourceHarness();
        when(h.evaluator.evaluate(any(), any(), eq("s3:GetObject"),
                eq("arn:aws:s3:::source-bucket/source-key"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.DENY);

        h.filter.filter(h.containerRequest);

        verify(h.containerRequest).abortWith(any());
    }

    @Test
    void s3CopyObjectAllowsWhenSourceGetObjectIsAllowed() {
        CopyTestHarness h = buildCopySourceHarness();
        when(h.evaluator.evaluate(any(), any(), eq("s3:GetObject"),
                eq("arn:aws:s3:::source-bucket/source-key"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        h.filter.filter(h.containerRequest);

        verify(h.containerRequest, never()).abortWith(any());
        verify(h.evaluator).evaluate(any(), any(), eq("s3:GetObject"),
                eq("arn:aws:s3:::source-bucket/source-key"), any());
    }

    @Test
    void s3PutObjectWithoutCopySourceHeaderSkipsSourceCheck() {
        CopyTestHarness h = buildCopySourceHarness();
        when(h.containerRequest.getHeaderString("x-amz-copy-source")).thenReturn(null);

        h.filter.filter(h.containerRequest);

        verify(h.containerRequest, never()).abortWith(any());
        verify(h.evaluator, never()).evaluate(any(), any(), eq("s3:GetObject"), anyString(), any());
    }

    @Test
    void s3CopyObjectUsesGetObjectVersionWhenSourceHasVersionId() {
        CopyTestHarness h = buildCopySourceHarness();
        when(h.containerRequest.getHeaderString("x-amz-copy-source"))
                .thenReturn("/source-bucket/source-key?versionId=abc123");
        when(h.evaluator.evaluate(any(), any(), eq("s3:GetObjectVersion"),
                eq("arn:aws:s3:::source-bucket/source-key"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.DENY);

        h.filter.filter(h.containerRequest);

        verify(h.containerRequest).abortWith(any());
        verify(h.evaluator, never()).evaluate(any(), any(), eq("s3:GetObject"), anyString(), any());
    }

    private record CopyTestHarness(IamEnforcementFilter filter, IamPolicyEvaluator evaluator,
                                   ContainerRequestContext containerRequest) {
    }

    /**
     * Builds a filter wired for an S3 PUT (CopyObject) request: destination
     * {@code s3:PutObject} on {@code dest-bucket/dest-key} always allowed, source object
     * {@code source-bucket/source-key} named via {@code x-amz-copy-source}. Tests override the
     * source-check decision or remove the header.
     */
    private static CopyTestHarness buildCopySourceHarness() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        IamService iamService = mock(IamService.class);
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("222233334444");
        ContainerRequestContext containerRequest = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);

        String auth = "AWS4-HMAC-SHA256 Credential=AKIACOPYSOURCE/20260629/us-east-1/s3/aws4_request, "
                + "SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(authConfig.trustForwardedHeaders()).thenReturn(false);
        when(accountResolver.extractAccessKeyId(auth)).thenReturn("AKIACOPYSOURCE");
        when(accountResolver.resolve(auth)).thenReturn("222233334444");
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);
        when(containerRequest.getHeaderString("x-amz-copy-source"))
                .thenReturn("/source-bucket/source-key");
        when(containerRequest.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn("/dest-bucket/dest-key");
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(actionRegistry.resolveRestRouteScope(containerRequest)).thenReturn(null);
        when(actionRegistry.resolve("s3", containerRequest)).thenReturn("s3:PutObject");
        when(iamService.resolveCallerContext("AKIACOPYSOURCE"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":["s3:PutObject","s3:GetObject","s3:GetObjectVersion"],
                           "Resource":"arn:aws:s3:::*"}
                        ]}""")));
        when(arnBuilder.build("s3", containerRequest, "us-east-1", "222233334444"))
                .thenReturn("arn:aws:s3:::dest-bucket/dest-key");
        when(resourcePolicyResolver.resolve(eq("s3"), anyString(), eq("us-east-1")))
                .thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("s3:PutObject"),
                eq("arn:aws:s3:::dest-bucket/dest-key"), any()))
                .thenReturn(IamPolicyEvaluator.Decision.ALLOW);

        IamEnforcementFilter filter = new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());

        return new CopyTestHarness(filter, evaluator, containerRequest);
    }

    // ── Multi-resource gates: EventBridge PutEvents / CloudWatch Logs StartQuery ────

    @Test
    void eventsPutEventsMultiBusDeniesWhenAnySecondaryBusIsDenied() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper(), mock(SecretsManagerService.class));
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"Entries":[
                  {"Source":"app","DetailType":"order","Detail":"{}","EventBusName":"allowed-bus"},
                  {"Source":"app","DetailType":"order","Detail":"{}","EventBusName":"secret-bus"}
                ]}""");
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("AWSEvents.PutEvents");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("events", containerRequest)).thenReturn("events:PutEvents");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIAEVENTS"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"events:PutEvents",
                           "Resource":"arn:aws:events:us-east-1:222222222222:event-bus/allowed-bus"}
                        ]}""")));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("events"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIAEVENTS", "events");

        filter.filter(containerRequest);

        verify(containerRequest).abortWith(any());
    }

    @Test
    void eventsPutEventsMultiBusAllowsWhenEveryBusIsAllowed() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper(), mock(SecretsManagerService.class));
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"Entries":[
                  {"Source":"app","DetailType":"order","Detail":"{}","EventBusName":"allowed-bus"},
                  {"Source":"app","DetailType":"order","Detail":"{}","EventBusName":"also-allowed-bus"}
                ]}""");
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("AWSEvents.PutEvents");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("events", containerRequest)).thenReturn("events:PutEvents");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIAEVENTS"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"events:PutEvents",
                           "Resource":"arn:aws:events:us-east-1:222222222222:event-bus/*"}
                        ]}""")));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("events"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIAEVENTS", "events");

        filter.filter(containerRequest);

        verify(containerRequest, never()).abortWith(any());
    }

    @Test
    void logsStartQueryMultiGroupDeniesWhenAnySecondaryGroupIsDenied() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper(), mock(SecretsManagerService.class));
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"logGroupNames":["/aws/lambda/allowed-fn","/aws/lambda/secret-fn"],
                 "queryString":"fields @message"}""");
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("Logs_20140328.StartQuery");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("logs", containerRequest)).thenReturn("logs:StartQuery");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIALOGS"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"logs:StartQuery",
                           "Resource":"arn:aws:logs:us-east-1:222222222222:log-group:/aws/lambda/allowed-fn"}
                        ]}""")));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("logs"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIALOGS", "logs");

        filter.filter(containerRequest);

        verify(containerRequest).abortWith(any());
    }

    @Test
    void logsStartQueryMultiGroupAllowsWhenEveryGroupIsAllowed() {
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper(), mock(SecretsManagerService.class));
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"logGroupNames":["/aws/lambda/allowed-fn","/aws/lambda/also-allowed-fn"]}""");
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("Logs_20140328.StartQuery");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("logs", containerRequest)).thenReturn("logs:StartQuery");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIALOGS"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"logs:StartQuery",
                           "Resource":"arn:aws:logs:us-east-1:222222222222:log-group:*"}
                        ]}""")));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("logs"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIALOGS", "logs");

        filter.filter(containerRequest);

        verify(containerRequest, never()).abortWith(any());
    }

    @Test
    @Tag("security-regression")
    void kmsReEncryptDeniesWhenDestinationKeyLacksReEncryptTo() {
        String sourceKeyId = "550e8400-e29b-41d4-a716-446655440000";
        String destKeyId = "11111111-1111-1111-1111-111111111111";
        String blob = java.util.Base64.getEncoder().encodeToString(
                ("kms:v3:" + sourceKeyId + ":bm9uY2U:Y2lwaGVy").getBytes(StandardCharsets.UTF_8));
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper());
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"CiphertextBlob":"%s","DestinationKeyId":"%s"}""".formatted(blob, destKeyId));
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("TrentService.ReEncrypt");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("kms", containerRequest)).thenReturn("kms:ReEncrypt");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIAKMSRE"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"kms:ReEncryptFrom",
                           "Resource":"arn:aws:kms:us-east-1:222222222222:key/%s"},
                          {"Effect":"Allow","Action":"kms:ReEncryptTo",
                           "Resource":"arn:aws:kms:us-east-1:222222222222:key/%s"}
                        ]}""".formatted(sourceKeyId, sourceKeyId))));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("kms"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIAKMSRE", "kms");

        filter.filter(containerRequest);

        verify(containerRequest).abortWith(any());
    }

    @Test
    @Tag("security-regression")
    void kmsReEncryptAllowsWhenBothFromAndToAreGranted() {
        String sourceKeyId = "550e8400-e29b-41d4-a716-446655440000";
        String destKeyId = "11111111-1111-1111-1111-111111111111";
        String blob = java.util.Base64.getEncoder().encodeToString(
                ("kms:v3:" + sourceKeyId + ":bm9uY2U:Y2lwaGVy").getBytes(StandardCharsets.UTF_8));
        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(new ObjectMapper());
        ResourceArnBuilder arnBuilder = new ResourceArnBuilder(new ObjectMapper());
        ContainerRequestContext containerRequest = jsonBodyRequestCtx("""
                {"CiphertextBlob":"%s","DestinationKeyId":"%s"}""".formatted(blob, destKeyId));
        when(containerRequest.getHeaderString("X-Amz-Target")).thenReturn("TrentService.ReEncrypt");

        IamActionRegistry actionRegistry = mock(IamActionRegistry.class);
        when(actionRegistry.resolve("kms", containerRequest)).thenReturn("kms:ReEncrypt");
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext("AKIAKMSRE"))
                .thenReturn(CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":["kms:ReEncryptFrom","kms:ReEncryptTo"],
                           "Resource":"arn:aws:kms:us-east-1:222222222222:key/*"}
                        ]}""")));
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("kms"), anyString(), eq("us-east-1"))).thenReturn(List.of());

        IamEnforcementFilter filter = buildFilter(
                containerRequest, actionRegistry, arnBuilder, evaluator, iamService, resourcePolicyResolver,
                "AKIAKMSRE", "kms");

        filter.filter(containerRequest);

        verify(containerRequest, never()).abortWith(any());
    }

    /**
     * Builds a filter wired for the multi-resource gate tests and stubs {@code containerRequest}
     * with a matching {@code Authorization} header, so caller {@code akid} authenticates via
     * SigV4 for {@code credentialScope} in {@code us-east-1} under account {@code 222222222222},
     * with strict enforcement off so only the multi-resource gate itself is under test.
     */
    private static IamEnforcementFilter buildFilter(ContainerRequestContext containerRequest,
                                                     IamActionRegistry actionRegistry,
                                                     ResourceArnBuilder arnBuilder,
                                                     IamPolicyEvaluator evaluator,
                                                     IamService iamService,
                                                     ResourcePolicyResolver resourcePolicyResolver,
                                                     String akid,
                                                     String credentialScope) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iamConfig = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig authConfig = mock(EmulatorConfig.AuthConfig.class);
        AccountResolver accountResolver = mock(AccountResolver.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        KmsService kmsService = mock(KmsService.class);
        AnonymousAccessGate anonymousAccessGate = mock(AnonymousAccessGate.class);
        RequestContext requestContext = new RequestContext();
        requestContext.setAccountId("222222222222");

        String auth = "AWS4-HMAC-SHA256 Credential=" + akid + "/20260629/us-east-1/" + credentialScope
                + "/aws4_request, SignedHeaders=host, Signature=abc";

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iamConfig);
        when(iamConfig.enforcementEnabled()).thenReturn(true);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(false);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.empty());
        when(accountResolver.extractAccessKeyId(auth)).thenReturn(akid);
        when(accountResolver.resolve(auth)).thenReturn("222222222222");
        when(regionResolver.resolveRegionFromAuth(auth)).thenReturn("us-east-1");
        when(containerRequest.getHeaderString("Authorization")).thenReturn(auth);

        return new IamEnforcementFilter(
                config, accountResolver, iamService, evaluator, actionRegistry, arnBuilder,
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate,
                requestContext, new IamConditionContextResolver());
    }

    /**
     * Builds a POST {@link ContainerRequestContext} backed by a real JSON body, wired for
     * {@link io.github.hectorvent.floci.core.common.RequestBodyBuffer} and the real
     * {@link ResourceArnBuilder} to read via {@code getEntityStream}/{@code setEntityStream} and
     * the property-backed body cache.
     */
    private static ContainerRequestContext jsonBodyRequestCtx(String json) {
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

    @Test
    void queryProtocolGetsXmlErrorResponse() {
        // IAM/STS/EC2/SQS/SNS/RDS/ELBv2/CFN/... — Query protocol, form-encoded body, XML response.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "iam:ListUsers", "iam", MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        assertEquals(403, r.getStatus());
        assertEquals(MediaType.APPLICATION_XML_TYPE, r.getMediaType());
        String body = entityString(r);
        assertTrue(body.contains("<ErrorResponse>"), body);
        assertTrue(body.contains("<Code>AccessDenied</Code>"), body);
        assertTrue(body.contains("<Type>Sender</Type>"), body);
        assertTrue(body.contains("User is not authorized to perform: iam:ListUsers"), body);
        assertTrue(body.contains("<RequestId>"), body);
    }

    @Test
    void s3GetsS3FlavoredXmlError() {
        // S3 — credential-scope is "s3"; S3 errors are <Error>... at the root, no <ErrorResponse> wrapper.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "s3:GetObject", "s3", null);

        assertEquals(403, r.getStatus());
        assertEquals(MediaType.APPLICATION_XML_TYPE, r.getMediaType());
        String body = entityString(r);
        assertTrue(body.startsWith("<?xml"), body);
        assertTrue(body.contains("<Error>"), body);
        assertTrue(body.contains("<Code>AccessDenied</Code>"), body);
        assertTrue(body.contains("User is not authorized to perform: s3:GetObject"), body);
        // S3 errors do not have the Query <Type>Sender</Type> envelope.
        assertTrue(!body.contains("<ErrorResponse>"), body);
    }

    @Test
    void jsonProtocolGetsJsonErrorResponse() {
        // DynamoDB / Cognito / Kinesis / ... — JSON 1.0/1.1, JSON error response.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "dynamodb:PutItem", "dynamodb", MediaType.valueOf("application/x-amz-json-1.0"));

        assertEquals(403, r.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_TYPE, r.getMediaType());
        String body = entityString(r);
        assertTrue(body.contains("\"__type\":\"AccessDeniedException\""), body);
        assertTrue(body.contains("User is not authorized to perform: dynamodb:PutItem"), body);
    }

    @Test
    void restJsonProtocolGetsJsonErrorResponse() {
        // Lambda / API Gateway — REST-JSON.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "lambda:InvokeFunction", "lambda", MediaType.APPLICATION_JSON_TYPE);

        assertEquals(403, r.getStatus());
        assertEquals(MediaType.APPLICATION_JSON_TYPE, r.getMediaType());
        String body = entityString(r);
        assertTrue(body.contains("\"__type\":\"AccessDeniedException\""), body);
    }

    @Test
    void formEncodedTakesPrecedenceOverNonS3Service() {
        // Even if the credentialScope isn't recognized, a form-encoded body
        // means we're talking to a Query-protocol service — XML response.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "rds:CreateDBInstance", "rds", MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        assertEquals(MediaType.APPLICATION_XML_TYPE, r.getMediaType());
        assertTrue(entityString(r).contains("<ErrorResponse>"));
    }

    @Test
    void s3WithFormEncodedBodyStillGetsS3XmlShape() {
        // S3 presigned POST uploads use multipart/form-data, not x-www-form-urlencoded,
        // but if a form-encoded body ever does land here, the s3 scope must still win.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "s3:PutObject", "s3", MediaType.APPLICATION_FORM_URLENCODED_TYPE);

        String body = entityString(r);
        assertTrue(body.contains("<Error>"));
        assertTrue(!body.contains("<ErrorResponse>"));
    }

    @Test
    void unknownContentTypeFallsBackToJson() {
        // No Content-Type at all — most likely a GET against a REST-JSON service.
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "kms:Decrypt", "kms", null);

        assertEquals(MediaType.APPLICATION_JSON_TYPE, r.getMediaType());
        assertTrue(entityString(r).contains("\"__type\":\"AccessDeniedException\""));
    }

    @Test
    void internalHealthPathMatchesRootHealth() {
        assertTrue(IamEnforcementFilter.isInternalHealthOrInfoPath("health"));
        assertTrue(IamEnforcementFilter.isInternalHealthOrInfoPath("/health"));
    }

    @Test
    void internalHealthPathMatchesFlociAndLocalstackPrefixes() {
        assertTrue(IamEnforcementFilter.isInternalHealthOrInfoPath("/_floci/health"));
        assertTrue(IamEnforcementFilter.isInternalHealthOrInfoPath("/_floci/info"));
        assertTrue(IamEnforcementFilter.isInternalHealthOrInfoPath("/_localstack/init"));
        assertTrue(!IamEnforcementFilter.isInternalHealthOrInfoPath("/"));
        assertTrue(!IamEnforcementFilter.isInternalHealthOrInfoPath("/my-bucket"));
    }

    @Test
    void sqsQueryScopeGetsXmlWhenContentTypeMissing() {
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "sqs:ListQueues", "sqs", null);

        assertEquals(403, r.getStatus());
        assertEquals(MediaType.APPLICATION_XML_TYPE, r.getMediaType());
        String body = entityString(r);
        assertTrue(body.contains("<Code>AccessDenied</Code>"), body);
        assertTrue(body.contains("sqs:ListQueues"), body);
    }

    @Test
    void sqsJsonContentTypeGetsJsonErrorResponse() {
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "sqs:ListQueues", "sqs", MediaType.valueOf("application/x-amz-json-1.0"));

        assertEquals(MediaType.APPLICATION_JSON_TYPE, r.getMediaType());
        assertTrue(entityString(r).contains("\"__type\":\"AccessDeniedException\""));
    }

    @Test
    void jsonErrorEscapesQuotesInMessage() {
        Response r = IamEnforcementFilter.accessDeniedResponse(
                "iam:Action\"WithQuotes", "iam", MediaType.APPLICATION_JSON_TYPE);

        String body = entityString(r);
        assertTrue(body.contains("iam:Action\\\"WithQuotes"), body);
        assertTrue(!body.contains("iam:Action\"WithQuotes"), body);
    }

    @Test
    void cognitoOAuthPathsRecognized() {
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("/cognito-idp/oauth2/token"));
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("cognito-idp/oauth2/userInfo"));
        assertTrue(!SecurityBypassPaths.isCognitoOAuthPath("/cognito-idp/"));
        assertTrue(!SecurityBypassPaths.isCognitoOAuthPath("/"));
    }

    private static String entityString(Response r) {
        Object entity = r.getEntity();
        assertNotNull(entity, "response body should not be null");
        if (entity instanceof byte[] b) {
            return new String(b, StandardCharsets.UTF_8);
        }
        return entity.toString();
    }
}

