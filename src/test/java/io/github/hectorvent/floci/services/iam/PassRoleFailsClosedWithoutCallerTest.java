package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
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

/**
 * O2: {@code authorizePassRole} must deny when the caller cannot be resolved under enforcement,
 * matching {@link InProcessIamAuthorizer#authorizeCallerAction} fail-closed semantics.
 */
@Tag("security-regression")
class PassRoleFailsClosedWithoutCallerTest {

    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/target-role";
    private static final String SERVICE = "lambda.amazonaws.com";
    private static final String REGION = "us-east-1";
    private static final String ROOT_AKID = "AKIAROOTEXAMPLE00";
    private static final String USER_AKID = "AKIAIOSFODNN7EXAMPLE";

    private EmulatorConfig config;
    private IamService iamService;
    private IamPolicyEvaluator evaluator;
    private RegionResolver regionResolver;
    private InProcessIamAuthorizer authorizer;

    @BeforeEach
    void setUp() {
        config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        iamService = mock(IamService.class);
        evaluator = mock(IamPolicyEvaluator.class);
        regionResolver = mock(RegionResolver.class);
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        when(config.auth().rootAccessKeyId()).thenReturn(Optional.of(ROOT_AKID));
        when(regionResolver.getAccountId()).thenReturn("000000000000");
        authorizer = new InProcessIamAuthorizer(
                config,
                iamService,
                evaluator,
                mock(ResourceArnBuilder.class),
                mock(ResourcePolicyResolver.class),
                regionResolver,
                mock(KmsService.class));
    }

    @Test
    void deniesWhenAccessKeyIdMissingUnderEnforcement() {
        when(regionResolver.getCallerAccessKeyId()).thenReturn(null);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }

    @Test
    void deniesWhenAccessKeyIdBlankUnderEnforcement() {
        when(regionResolver.getCallerAccessKeyId()).thenReturn("   ");

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }

    @Test
    void deniesWhenCallerContextUnresolvedUnderEnforcement() {
        when(regionResolver.getCallerAccessKeyId()).thenReturn(USER_AKID);
        when(iamService.resolveCallerContext(USER_AKID)).thenReturn(null);

        AwsException ex = assertThrows(AwsException.class,
                () -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        assertEquals("AccessDeniedException", ex.getErrorCode());
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }

    @Test
    void skipsConfiguredRootAccessKey() {
        when(regionResolver.getCallerAccessKeyId()).thenReturn(ROOT_AKID);

        assertDoesNotThrow(() -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        verify(iamService, never()).resolveCallerContext(any());
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }

    @Test
    void evaluatesPassRoleWhenCallerResolves() {
        when(regionResolver.getCallerAccessKeyId()).thenReturn(USER_AKID);
        when(iamService.resolveCallerContext(USER_AKID)).thenReturn(CallerContext.of(List.of()));
        when(iamService.resolveCallerArn(USER_AKID))
                .thenReturn(Optional.of("arn:aws:iam::000000000000:user/alice"));
        when(evaluator.evaluate(any(), any(), eq("iam:PassRole"), eq(ROLE_ARN), any()))
                .thenReturn(Decision.ALLOW);

        assertDoesNotThrow(() -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        verify(evaluator).evaluate(any(), any(), eq("iam:PassRole"), eq(ROLE_ARN), any());
    }

    @Test
    void skipsWhenEnforcementDisabledEvenWithoutCaller() {
        when(config.services().iam().enforcementEnabled()).thenReturn(false);
        when(regionResolver.getCallerAccessKeyId()).thenReturn(null);

        assertDoesNotThrow(() -> authorizer.authorizePassRole(ROLE_ARN, SERVICE, REGION));
        verify(evaluator, never()).evaluate(any(), any(), any(), any(), any());
    }
}
