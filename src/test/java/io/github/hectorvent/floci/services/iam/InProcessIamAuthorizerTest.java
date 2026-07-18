package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@Tag("security-regression")
class InProcessIamAuthorizerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String ROLE_ARN = "arn:aws:iam::222222222222:role/sfn-exec";
    private static final String KEY_ARN = "arn:aws:kms:us-east-1:222222222222:key/abc-123";
    private static final String QUEUE_ARN = "arn:aws:sqs:us-east-1:222222222222:test-target";
    private static final String LAMBDA_ARN = "arn:aws:lambda:us-east-1:222222222222:function:test-target";
    private static final String EVENTS_SERVICE = "events.amazonaws.com";
    private static final String AKID = "AKIATESTCALLER";

    private EmulatorConfig config;
    private IamService iamService;
    private IamPolicyEvaluator evaluator;
    private ResourceArnBuilder arnBuilder;
    private ResourcePolicyResolver resourcePolicyResolver;
    private RegionResolver regionResolver;
    private KmsService kmsService;
    private InProcessIamAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        iamService = mock(IamService.class);
        evaluator = mock(IamPolicyEvaluator.class);
        arnBuilder = mock(ResourceArnBuilder.class);
        resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        regionResolver = mock(RegionResolver.class);
        kmsService = mock(KmsService.class);
        authorizer = new InProcessIamAuthorizer(
                config,
                iamService,
                evaluator,
                arnBuilder,
                resourcePolicyResolver,
                regionResolver,
                kmsService);
    }

    @Test
    void normalizesDynamoDbCamelCaseActions() {
        assertEquals("dynamodb:PutItem", InProcessIamAuthorizer.toIamAction("dynamodb", "putItem"));
        assertEquals("secretsmanager:GetSecretValue",
                InProcessIamAuthorizer.toIamAction("secretsmanager", "GetSecretValue"));
        assertEquals("kms:Decrypt", InProcessIamAuthorizer.toIamAction("kms", "Decrypt"));
    }

    @Test
    void skipsAuthorizationWhenEnforcementDisabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(false);

        ObjectNode body = MAPPER.createObjectNode();
        body.put("SecretId", "ctf/secret");

        assertDoesNotThrow(() -> authorizer.authorize(
                null, "secretsmanager", "GetSecretValue", body, "us-east-1"));
    }

    @Test
    void deniesMissingExecutionRoleWhenEnforcementEnabledRegardlessOfStrictMode() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(config.services().iam().strictEnforcementEnabled()).thenReturn(false);

        ObjectNode body = MAPPER.createObjectNode();
        body.put("SecretId", "ctf/secret");

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorize(null, "secretsmanager", "GetSecretValue", body, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void deniesBlankExecutionRoleWhenEnforcementEnabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        ObjectNode body = MAPPER.createObjectNode();
        body.put("SecretId", "ctf/secret");

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorize("   ", "secretsmanager", "GetSecretValue", body, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void allowsKmsDecryptViaGrantWhenIdentityPolicyDenies() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(CallerContext.of(List.of()));
        when(arnBuilder.buildFromJsonBody(eq("kms"), any(), eq("us-east-1"), eq("222222222222")))
                .thenReturn(KEY_ARN);
        when(resourcePolicyResolver.resolve("kms", KEY_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("kms:Decrypt"), eq(KEY_ARN), any()))
                .thenReturn(Decision.DENY);
        when(kmsService.isGrantAuthorized(
                eq(ROLE_ARN),
                eq("222222222222"),
                eq(KEY_ARN),
                eq("kms:Decrypt"),
                eq("us-east-1"))).thenReturn(true);

        ObjectNode body = MAPPER.createObjectNode();
        body.put("KeyId", KEY_ARN);

        assertDoesNotThrow(() -> authorizer.authorize(ROLE_ARN, "kms", "Decrypt", body, "us-east-1"));
        verify(kmsService).isGrantAuthorized(
                eq(ROLE_ARN),
                eq("222222222222"),
                eq(KEY_ARN),
                eq("kms:Decrypt"),
                eq("us-east-1"));
    }

    @Test
    void authorizeWithResourceSkipsWhenEnforcementDisabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(false);

        assertDoesNotThrow(() -> authorizer.authorizeWithResource(
                null, "sqs", "SendMessage", QUEUE_ARN, "us-east-1"));
        verify(iamService, never()).resolveCallerContextFromRoleArn(any());
    }

    @Test
    void authorizeWithResourceDeniesMissingExecutionRole() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeWithResource(
                        null, "sqs", "SendMessage", QUEUE_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeWithResourceDeniesUnknownExecutionRole() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(null);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeWithResource(
                        ROLE_ARN, "sqs", "SendMessage", QUEUE_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeWithResourceAllowsWhenPolicyPermits() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(CallerContext.of(List.of()));
        when(resourcePolicyResolver.resolve("sqs", QUEUE_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("sqs:SendMessage"), eq(QUEUE_ARN), any()))
                .thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizeWithResource(
                ROLE_ARN, "sqs", "SendMessage", QUEUE_ARN, "us-east-1"));
    }

    @Test
    void authorizeWithResourceDeniesWhenPolicyDenies() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(CallerContext.of(List.of()));
        when(resourcePolicyResolver.resolve("sqs", QUEUE_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("sqs:SendMessage"), eq(QUEUE_ARN), any()))
                .thenReturn(Decision.DENY);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeWithResource(
                        ROLE_ARN, "sqs", "SendMessage", QUEUE_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeWithResourceUsesWildcardWhenResourceBlank() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(CallerContext.of(List.of()));
        when(resourcePolicyResolver.resolve("sqs", "*", "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("sqs:SendMessage"), eq("*"), any()))
                .thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizeWithResource(
                ROLE_ARN, "sqs", "SendMessage", "   ", "us-east-1"));
        verify(resourcePolicyResolver).resolve("sqs", "*", "us-east-1");
    }

    @Test
    void authorizeWithResourceAllowsKmsDecryptViaGrantWhenIdentityPolicyDenies() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(iamService.resolveCallerContextFromRoleArn(ROLE_ARN)).thenReturn(CallerContext.of(List.of()));
        when(resourcePolicyResolver.resolve("kms", KEY_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("kms:Decrypt"), eq(KEY_ARN), any()))
                .thenReturn(Decision.DENY);
        when(kmsService.isGrantAuthorized(
                eq(ROLE_ARN),
                eq("222222222222"),
                eq(KEY_ARN),
                eq("kms:Decrypt"),
                eq("us-east-1"))).thenReturn(true);

        assertDoesNotThrow(() -> authorizer.authorizeWithResource(
                ROLE_ARN, "kms", "Decrypt", KEY_ARN, "us-east-1"));
        verify(kmsService).isGrantAuthorized(
                eq(ROLE_ARN),
                eq("222222222222"),
                eq(KEY_ARN),
                eq("kms:Decrypt"),
                eq("us-east-1"));
    }

    @Test
    void authorizeServicePrincipalSkipsWhenEnforcementDisabled() {
        when(config.services().iam().enforcementEnabled()).thenReturn(false);

        assertDoesNotThrow(() -> authorizer.authorizeServicePrincipal(
                EVENTS_SERVICE, "lambda", "InvokeFunction", LAMBDA_ARN, "us-east-1"));
        verify(resourcePolicyResolver, never()).resolve(any(), any(), any());
    }

    @Test
    void authorizeServicePrincipalDeniesMissingServicePrincipal() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeServicePrincipal(
                        null, "lambda", "InvokeFunction", LAMBDA_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeServicePrincipalDeniesBlankServicePrincipal() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeServicePrincipal(
                        "  ", "lambda", "InvokeFunction", LAMBDA_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeServicePrincipalAllowsWhenResourcePolicyPermits() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(resourcePolicyResolver.resolve("lambda", LAMBDA_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(
                eq(CallerContext.of(List.of())),
                any(),
                eq("lambda:InvokeFunction"),
                eq(LAMBDA_ARN),
                any())).thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizeServicePrincipal(
                EVENTS_SERVICE, "lambda", "InvokeFunction", LAMBDA_ARN, "us-east-1"));
    }

    @Test
    void authorizeServicePrincipalDeniesWhenResourcePolicyDenies() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(resourcePolicyResolver.resolve("lambda", LAMBDA_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(
                eq(CallerContext.of(List.of())),
                any(),
                eq("lambda:InvokeFunction"),
                eq(LAMBDA_ARN),
                any())).thenReturn(Decision.DENY);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizeServicePrincipal(
                        EVENTS_SERVICE, "lambda", "InvokeFunction", LAMBDA_ARN, "us-east-1"));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void authorizeServicePrincipalUsesWildcardWhenResourceBlank() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(resourcePolicyResolver.resolve("lambda", "*", "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(
                eq(CallerContext.of(List.of())),
                any(),
                eq("lambda:InvokeFunction"),
                eq("*"),
                any())).thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizeServicePrincipal(
                EVENTS_SERVICE, "lambda", "InvokeFunction", "  ", "us-east-1"));
        verify(resourcePolicyResolver).resolve("lambda", "*", "us-east-1");
    }

    @Test
    void authorizeServicePrincipalSkipsExemptActions() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);

        assertDoesNotThrow(() -> authorizer.authorizeServicePrincipal(
                EVENTS_SERVICE, "sts", "GetCallerIdentity", LAMBDA_ARN, "us-east-1"));
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }

    @Test
    void authorizeCallerActionMergesExtraCalledViaCondition() {
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(config.auth().rootAccessKeyId()).thenReturn(Optional.empty());
        when(regionResolver.getCallerAccessKeyId()).thenReturn(AKID);
        when(regionResolver.getAccountId()).thenReturn("222222222222");
        when(iamService.resolveCallerContext(AKID)).thenReturn(CallerContext.of(List.of()));
        when(iamService.resolveCallerArn(AKID)).thenReturn(Optional.of(ROLE_ARN));
        when(resourcePolicyResolver.resolve("iam", ROLE_ARN, "us-east-1")).thenReturn(List.of());
        when(evaluator.evaluate(any(), any(), eq("iam:CreateRole"), eq(ROLE_ARN), any()))
                .thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizeCallerAction(
                "iam:CreateRole", ROLE_ARN, "us-east-1", "iam",
                Map.of("aws:calledvia", "cloudformation.amazonaws.com")));

        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> conditions = ArgumentCaptor.forClass(Map.class);
        verify(evaluator).evaluate(any(), any(), eq("iam:CreateRole"), eq(ROLE_ARN), conditions.capture());
        assertEquals("cloudformation.amazonaws.com", conditions.getValue().get("aws:calledvia"));
    }
}
