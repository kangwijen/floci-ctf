package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Fail-closed execute-plane authz for API Gateway REST, HTTP API, and WebSocket.
 * Covers null authType under strict, CUSTOM misconfig, unsupported Cognito/AWS modes,
 * and Deny-wins multi-Statement evaluation shared across paths.
 */
@Tag("security-regression")
class ExecuteAuthzGateTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String METHOD_ARN =
            "arn:aws:execute-api:us-east-1:000000000000:api1/test/GET/secured";

    private final ExecuteAuthzGate gate = new ExecuteAuthzGate();

    private static JsonNode statements(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Test
    void nullAuthTypeIsNotNoneUnderStrict() {
        assertFalse(gate.allowsAnonymous(null, true));
        assertFalse(gate.allowsAnonymous("  ", true));
    }

    @Test
    void nullAuthTypeMayAllowAnonymousWhenNotStrict() {
        assertTrue(gate.allowsAnonymous(null, false));
    }

    @Test
    void explicitNoneAllowsAnonymous() {
        assertTrue(gate.allowsAnonymous("NONE", true));
        assertTrue(gate.allowsAnonymous("none", false));
    }

    @Test
    void awsIamAndCognitoAreNotAnonymous() {
        assertFalse(gate.allowsAnonymous("AWS_IAM", true));
        assertFalse(gate.allowsAnonymous("COGNITO_USER_POOLS", true));
        assertFalse(gate.allowsAnonymous("CUSTOM", true));
    }

    @Test
    void cognitoUserPoolsIsRejectedNotSilentAllow() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkUnsupportedMethodAuth("COGNITO_USER_POOLS");
        assertTrue(decision.isDenied());
        assertEquals(403, decision.statusCode());
    }

    @Test
    void unknownAuthTypeIsRejected() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkUnsupportedMethodAuth("MAGIC");
        assertTrue(decision.isDenied());
        assertEquals(403, decision.statusCode());
    }

    @Test
    void awsIamProceedsForIamFilterPath() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkUnsupportedMethodAuth("AWS_IAM");
        assertFalse(decision.isDenied());
        assertFalse(decision.isError());
    }

    @Test
    void missingAuthTypeDeniedUnderStrict() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkMissingAuthType(null, true);
        assertTrue(decision.isDenied());
        assertEquals(403, decision.statusCode());
    }

    @Test
    void missingAuthTypeProceedsWhenNotStrict() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkMissingAuthType(null, false);
        assertFalse(decision.isDenied());
    }

    @Test
    void customMissingAuthorizerIdFailsClosed() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkCustomMisconfig(null, "fn");
        assertTrue(decision.isDenied());
        assertEquals(403, decision.statusCode());
    }

    @Test
    void customUnresolvableLambdaUriFailsClosed() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkCustomMisconfig("auth-1", null);
        assertTrue(decision.isError());
        assertEquals(500, decision.statusCode());
    }

    @Test
    void customNonRequestAuthorizerTypeFailsClosed() {
        ExecuteAuthzGate.AuthzDecision decision = gate.checkRequestAuthorizerType("JWT");
        assertTrue(decision.isError());
        assertEquals(500, decision.statusCode());
    }

    @Test
    void customRequestAuthorizerTypeProceeds() {
        assertFalse(gate.checkRequestAuthorizerType("REQUEST").isDenied());
        assertFalse(gate.checkRequestAuthorizerType("REQUEST").isError());
    }

    @Test
    void explicitDenyWinsOverAllowRegardlessOfOrder() {
        JsonNode allowThenDeny = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" },
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN, METHOD_ARN));
        assertFalse(gate.evaluatePolicyStatements(allowThenDeny, METHOD_ARN));

        JsonNode denyThenAllow = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "%s" },
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN, METHOD_ARN));
        assertFalse(gate.evaluatePolicyStatements(denyThenAllow, METHOD_ARN));
    }

    @Test
    void allowAfterNonMatchingDenyIsAllowed() {
        JsonNode stmts = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "arn:aws:execute-api:us-east-1:000000000000:other-api/*" },
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN));
        assertTrue(gate.evaluatePolicyStatements(stmts, METHOD_ARN));
    }

    @Test
    void emptyOrMissingStatementsDenyByDefault() {
        assertFalse(gate.evaluatePolicyStatements(statements("[]"), METHOD_ARN));
        assertFalse(gate.evaluatePolicyStatements(null, METHOD_ARN));
    }
}
