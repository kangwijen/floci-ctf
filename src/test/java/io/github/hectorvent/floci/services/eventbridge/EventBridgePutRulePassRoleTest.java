package io.github.hectorvent.floci.services.eventbridge;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.eventbridge.model.RuleState;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.resourcegroupstagging.ResourceGroupsTaggingService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * E-FO-05: PutRule RoleArn requires iam:PassRole (also covers CFN AWS::Events::Rule via putRule).
 */
@Tag("security-regression")
class EventBridgePutRulePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/events-role";

    private InProcessIamAuthorizer iamAuthorizer;
    private EventBridgeService service;

    @BeforeEach
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        service = new EventBridgeService(
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new RegionResolver(REGION, "000000000000"),
                new ObjectMapper(),
                null,
                mock(EventBridgeInvoker.class),
                null,
                mock(InProcessTargetAuthorizer.class),
                new ResourceGroupsTaggingService(null),
                iamAuthorizer);
        service.getOrCreateDefaultBus(REGION);
    }

    @Test
    void putRuleRequiresPassRoleOnRoleArn() {
        service.putRule("passrole-rule", "default", null, null, RuleState.ENABLED,
                null, ROLE_ARN, null, REGION);

        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "events.amazonaws.com", REGION);
    }

    @Test
    void putRuleDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("events.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.putRule("denied-rule", "default", null, null, RuleState.ENABLED,
                        null, ROLE_ARN, null, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }
}
