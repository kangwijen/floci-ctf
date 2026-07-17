package io.github.hectorvent.floci.services.cognito;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.cognito.model.UserPool;
import io.github.hectorvent.floci.services.cognito.model.UserPoolClient;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Verifies {@code initiateAuth}/{@code adminInitiateAuth} reject any {@code AuthFlow} outside the
 * enumerated set instead of falling through to an authenticated result. Regression coverage for
 * the permissive default branch that previously let a caller with only {@code InitiateAuth}
 * obtain tokens for any user without a password, SRP proof, or refresh token.
 */
class CognitoAuthFlowHandlerTest {

    private static final String USER_POOL_ID = "us-east-1_TestPool";
    private static final String CLIENT_ID = "test-client-id";

    private CognitoService service;
    private CognitoAuthFlowHandler handler;

    @BeforeEach
    void setUp() {
        service = mock(CognitoService.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        InProcessTargetAuthorizer targetAuthorizer = mock(InProcessTargetAuthorizer.class);
        handler = new CognitoAuthFlowHandler(service, null, regionResolver, targetAuthorizer);

        UserPoolClient client = mock(UserPoolClient.class);
        when(client.getUserPoolId()).thenReturn(USER_POOL_ID);
        when(client.getClientId()).thenReturn(CLIENT_ID);
        when(service.findClientById(CLIENT_ID)).thenReturn(client);
        when(service.describeUserPoolClient(USER_POOL_ID, CLIENT_ID)).thenReturn(client);

        UserPool pool = mock(UserPool.class);
        when(pool.getId()).thenReturn(USER_POOL_ID);
        when(service.describeUserPool(USER_POOL_ID)).thenReturn(pool);
    }

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN_NO_SRP_AUTH", "NOT_A_REAL_AUTH_FLOW", "", "user_password_auth"})
    void initiateAuthRejectsUnknownAuthFlow(String authFlow) {
        AwsException ex = assertThrows(AwsException.class,
                () -> handler.initiateAuth(CLIENT_ID, authFlow, Map.of("USERNAME", "someuser"), Map.of()));

        assertEquals("InvalidParameterException", ex.getErrorCode());
        assertEquals(400, ex.getHttpStatus());
    }

    @ParameterizedTest
    @ValueSource(strings = {"ADMIN_NO_SRP_AUTH", "NOT_A_REAL_AUTH_FLOW", "", "admin_user_password_auth"})
    void adminInitiateAuthRejectsUnknownAuthFlow(String authFlow) {
        AwsException ex = assertThrows(AwsException.class,
                () -> handler.adminInitiateAuth(USER_POOL_ID, CLIENT_ID, authFlow, Map.of(), Map.of()));

        assertEquals("InvalidParameterException", ex.getErrorCode());
        assertEquals(400, ex.getHttpStatus());
    }

    @Test
    void initiateAuthRejectsUnknownAuthFlowWithoutTouchingUserLookup() {
        assertThrows(AwsException.class,
                () -> handler.initiateAuth(CLIENT_ID, "SOMETHING_ELSE", Map.of("USERNAME", "someuser"), Map.of()));

        org.mockito.Mockito.verify(service, org.mockito.Mockito.never())
                .adminGetUser(org.mockito.ArgumentMatchers.any(), org.mockito.ArgumentMatchers.any());
    }
}
