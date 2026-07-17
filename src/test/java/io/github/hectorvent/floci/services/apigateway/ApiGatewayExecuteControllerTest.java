package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Verifies {@link ApiGatewayExecuteController#extractV2PathParams(String, String)}
 * captures path parameters correctly for both greedy ({proxy+}) and non-greedy
 * ({proxy}) route templates, and that repeated invocations against the same
 * route key reuse the cached compiled Pattern (correctness check; the cache
 * itself is an internal implementation detail).
 */
class ApiGatewayExecuteControllerTest {

    @Test
    void capturesGreedyProxyMultiSegment() {
        Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                "ANY /wallet/{proxy+}", "/wallet/users/123/orders");
        assertEquals("users/123/orders", p.get("proxy"));
    }

    @Test
    void capturesNonGreedyNamedParam() {
        Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                "GET /users/{id}", "/users/42");
        assertEquals("42", p.get("id"));
    }

    @Test
    void capturesMultipleNamedParams() {
        Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                "GET /users/{user}/orders/{order}", "/users/u-1/orders/o-2");
        assertEquals("u-1", p.get("user"));
        assertEquals("o-2", p.get("order"));
    }

    @Test
    void capturesMixedGreedyAndNamedParams() {
        Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                "ANY /users/{user}/files/{path+}", "/users/u-1/files/a/b/c");
        assertEquals("u-1", p.get("user"));
        assertEquals("a/b/c", p.get("path"));
    }

    @Test
    void noMatchReturnsEmptyMap() {
        Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                "GET /users/{id}", "/orders/42");
        assertTrue(p.isEmpty());
    }

    @Test
    void nullRouteKeyReturnsEmptyMap() {
        assertTrue(ApiGatewayExecuteController.extractV2PathParams(null, "/x").isEmpty());
    }

    @Test
    void malformedRouteKeyReturnsEmptyMap() {
        // No method/path split — caller passed garbage.
        assertTrue(ApiGatewayExecuteController.extractV2PathParams("garbage", "/x").isEmpty());
    }

    @Test
    void repeatedCallsAgainstSameRouteAreStable() {
        // Second hit reuses the cached compiled Pattern; output must be
        // identical for the same inputs. Run hot to give the cache a chance
        // to be exercised across multiple invocations.
        String routeKey = "ANY /payments/{proxy+}";
        for (int i = 0; i < 100; i++) {
            Map<String, String> p = ApiGatewayExecuteController.extractV2PathParams(
                    routeKey, "/payments/spei/" + i);
            assertEquals("spei/" + i, p.get("proxy"));
        }
    }

    /**
     * Verifies {@link ApiGatewayExecuteController#evaluateCustomAuthorizerPolicy(JsonNode, String)}
     * evaluates every Statement entry in a CUSTOM Lambda authorizer policy document, with an
     * explicit Deny winning over an Allow regardless of statement order.
     */
    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final String METHOD_ARN = "arn:aws:execute-api:us-east-1:000000000000:api1/test/GET/secured";

    private static JsonNode statements(String json) {
        try {
            return MAPPER.readTree(json);
        } catch (Exception e) {
            throw new IllegalArgumentException(e);
        }
    }

    @Test
    void singleAllowStatementAllows() {
        JsonNode stmts = statements("""
                [{ "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" }]
                """.formatted(METHOD_ARN));
        assertTrue(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }

    @Test
    void singleDenyStatementDenies() {
        JsonNode stmts = statements("""
                [{ "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "%s" }]
                """.formatted(METHOD_ARN));
        assertFalse(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }

    @Test
    void explicitDenyWinsOverAllowRegardlessOfOrder() {
        JsonNode allowThenDeny = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" },
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN, METHOD_ARN));
        assertFalse(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(allowThenDeny, METHOD_ARN));

        JsonNode denyThenAllow = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "%s" },
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN, METHOD_ARN));
        assertFalse(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(denyThenAllow, METHOD_ARN));
    }

    @Test
    void allowStatementMatchesAfterNonMatchingResourceStatement() {
        JsonNode stmts = statements("""
                [
                  { "Action": "execute-api:Invoke", "Effect": "Deny", "Resource": "arn:aws:execute-api:us-east-1:000000000000:other-api/*" },
                  { "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "%s" }
                ]
                """.formatted(METHOD_ARN));
        assertTrue(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }

    @Test
    void noMatchingStatementDeniesByDefault() {
        JsonNode stmts = statements("""
                [{ "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "arn:aws:execute-api:us-east-1:000000000000:other-api/*" }]
                """);
        assertFalse(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }

    @Test
    void emptyStatementListDeniesByDefault() {
        assertFalse(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(statements("[]"), METHOD_ARN));
    }

    @Test
    void wildcardResourceAllowsMatchingMethodArn() {
        JsonNode stmts = statements("""
                [{ "Action": "execute-api:Invoke", "Effect": "Allow", "Resource": "arn:aws:execute-api:us-east-1:000000000000:api1/*" }]
                """);
        assertTrue(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }

    @Test
    void resourceArrayIsEvaluatedForAMatch() {
        JsonNode stmts = statements("""
                [{
                  "Action": "execute-api:Invoke",
                  "Effect": "Allow",
                  "Resource": ["arn:aws:execute-api:us-east-1:000000000000:other-api/*", "%s"]
                }]
                """.formatted(METHOD_ARN));
        assertTrue(ApiGatewayExecuteController.evaluateCustomAuthorizerPolicy(stmts, METHOD_ARN));
    }
}
