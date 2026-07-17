package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import jakarta.enterprise.context.ApplicationScoped;

/**
 * Shared fail-closed authorization helpers for API Gateway execute-plane paths
 * (REST, HTTP API REQUEST authorizers, and WebSocket $connect authorizers).
 *
 * <p>Null {@code authorizationType} is not treated as {@code NONE} under strict IAM.
 * CUSTOM misconfiguration and unsupported Cognito method auth fail closed.
 * Lambda authorizer policies use Deny-wins multi-Statement evaluation.
 */
@ApplicationScoped
public class ExecuteAuthzGate {

    public enum MethodAuthKind {
        NONE,
        CUSTOM,
        JWT,
        AWS_IAM,
        COGNITO_USER_POOLS,
        UNKNOWN,
        MISSING
    }

    /**
     * @param statusCode HTTP status when denied or errored
     * @param denied     client-facing deny (403/401)
     * @param error      server/misconfig failure (500)
     */
    public record AuthzDecision(int statusCode, boolean denied, boolean error) {
        public static AuthzDecision proceed() {
            return new AuthzDecision(200, false, false);
        }

        public static AuthzDecision deny(int statusCode) {
            return new AuthzDecision(statusCode, true, false);
        }

        public static AuthzDecision error(int statusCode) {
            return new AuthzDecision(statusCode, false, true);
        }

        public boolean isDenied() {
            return denied;
        }

        public boolean isError() {
            return error;
        }

        public boolean blocks() {
            return denied || error;
        }
    }

    public MethodAuthKind classify(String authorizationType) {
        if (authorizationType == null || authorizationType.isBlank()) {
            return MethodAuthKind.MISSING;
        }
        return switch (authorizationType.trim().toUpperCase()) {
            case "NONE" -> MethodAuthKind.NONE;
            case "CUSTOM" -> MethodAuthKind.CUSTOM;
            case "JWT" -> MethodAuthKind.JWT;
            case "AWS_IAM" -> MethodAuthKind.AWS_IAM;
            case "COGNITO_USER_POOLS" -> MethodAuthKind.COGNITO_USER_POOLS;
            default -> MethodAuthKind.UNKNOWN;
        };
    }

    /**
     * Unsigned anonymous invoke is allowed only for explicit {@code NONE}.
     * Under strict enforcement, a missing auth type is not treated as {@code NONE}.
     */
    public boolean allowsAnonymous(String authorizationType, boolean strict) {
        MethodAuthKind kind = classify(authorizationType);
        if (kind == MethodAuthKind.NONE) {
            return true;
        }
        if (kind == MethodAuthKind.MISSING) {
            return !strict;
        }
        return false;
    }

    /**
     * Missing auth type under strict must not silently proceed as open.
     */
    public AuthzDecision checkMissingAuthType(String authorizationType, boolean strict) {
        if (classify(authorizationType) == MethodAuthKind.MISSING && strict) {
            return AuthzDecision.deny(403);
        }
        return AuthzDecision.proceed();
    }

    /**
     * Reject auth types that are not implemented on the execute plane.
     * {@code AWS_IAM} proceeds so {@code IamEnforcementFilter} can evaluate
     * {@code execute-api:Invoke}; it must not be treated as anonymous.
     */
    public AuthzDecision checkUnsupportedMethodAuth(String authorizationType) {
        MethodAuthKind kind = classify(authorizationType);
        return switch (kind) {
            case COGNITO_USER_POOLS, UNKNOWN -> AuthzDecision.deny(403);
            case NONE, CUSTOM, JWT, AWS_IAM, MISSING -> AuthzDecision.proceed();
        };
    }

    /**
     * CUSTOM without an authorizer id is 403. Unresolvable Lambda URI is 500.
     */
    public AuthzDecision checkCustomMisconfig(String authorizerId, String resolvedFunctionName) {
        if (authorizerId == null || authorizerId.isBlank()) {
            return AuthzDecision.deny(403);
        }
        if (resolvedFunctionName == null || resolvedFunctionName.isBlank()) {
            return AuthzDecision.error(500);
        }
        return AuthzDecision.proceed();
    }

    /**
     * HTTP API / WebSocket Lambda authorizers must be {@code REQUEST} type.
     * Other types fail closed instead of silently allowing.
     */
    public AuthzDecision checkRequestAuthorizerType(String authorizerType) {
        if (authorizerType != null && "REQUEST".equalsIgnoreCase(authorizerType.trim())) {
            return AuthzDecision.proceed();
        }
        return AuthzDecision.error(500);
    }

    /**
     * Evaluates every Statement in a Lambda authorizer policy document.
     * Explicit Deny on any matching statement wins; absent a matching Allow, deny.
     */
    public boolean evaluatePolicyStatements(JsonNode statements, String methodArn) {
        if (statements == null || !statements.isArray() || statements.isEmpty()) {
            return false;
        }
        boolean allowed = false;
        for (JsonNode statement : statements) {
            if (!statementApplies(statement, methodArn)) {
                continue;
            }
            String effect = statement.path("Effect").asText("Deny");
            if ("Deny".equalsIgnoreCase(effect)) {
                return false;
            }
            if ("Allow".equalsIgnoreCase(effect)) {
                allowed = true;
            }
        }
        return allowed;
    }

    private static boolean statementApplies(JsonNode statement, String methodArn) {
        return fieldMatches(statement.path("Action"), "execute-api:Invoke")
                && fieldMatches(statement.path("Resource"), methodArn);
    }

    private static boolean fieldMatches(JsonNode field, String value) {
        if (field == null || field.isMissingNode() || field.isNull()) {
            return true;
        }
        if (field.isArray()) {
            for (JsonNode entry : field) {
                if (entry.isTextual() && IamPolicyEvaluator.globMatches(entry.asText(), value)) {
                    return true;
                }
            }
            return false;
        }
        return field.isTextual() && IamPolicyEvaluator.globMatches(field.asText(), value);
    }
}
