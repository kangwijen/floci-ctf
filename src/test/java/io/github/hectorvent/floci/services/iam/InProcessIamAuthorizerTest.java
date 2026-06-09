package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.kms.KmsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class InProcessIamAuthorizerTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private EmulatorConfig config;
    private InProcessIamAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        authorizer = new InProcessIamAuthorizer(
                config,
                mock(IamService.class),
                mock(IamPolicyEvaluator.class),
                mock(ResourceArnBuilder.class),
                mock(ResourcePolicyResolver.class),
                mock(RegionResolver.class),
                mock(KmsService.class));
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
}
