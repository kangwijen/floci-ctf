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
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class InProcessIamAuthorizerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private static final String ROLE_ARN = "arn:aws:iam::222222222222:role/sfn-exec";
    private static final String KEY_ARN = "arn:aws:kms:us-east-1:222222222222:key/abc-123";

    private EmulatorConfig config;
    private IamService iamService;
    private IamPolicyEvaluator evaluator;
    private ResourceArnBuilder arnBuilder;
    private ResourcePolicyResolver resourcePolicyResolver;
    private KmsService kmsService;
    private InProcessIamAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        iamService = mock(IamService.class);
        evaluator = mock(IamPolicyEvaluator.class);
        arnBuilder = mock(ResourceArnBuilder.class);
        resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        kmsService = mock(KmsService.class);
        authorizer = new InProcessIamAuthorizer(
                config,
                iamService,
                evaluator,
                arnBuilder,
                resourcePolicyResolver,
                mock(RegionResolver.class),
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
}
