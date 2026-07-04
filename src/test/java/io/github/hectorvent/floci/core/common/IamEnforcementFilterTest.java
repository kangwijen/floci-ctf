package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import jakarta.ws.rs.container.ContainerRequestContext;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
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
    void filterBuildsResourceArnWithSessionAccountFromAccountResolver() {
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
        when(accountResolver.resolve(auth)).thenReturn("222233334444");
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
                resourcePolicyResolver, regionResolver, kmsService, anonymousAccessGate);

        filter.filter(containerRequest);

        verify(arnBuilder).build("lambda", containerRequest, "us-east-1", "222233334444");
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
