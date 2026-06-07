package io.github.hectorvent.floci.services.iam;

import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;

/**
 * Token-derived claims and provider identity for {@code AssumeRoleWithWebIdentity}
 * and {@code AssumeRoleWithSAML} trust evaluation.
 */
public final class FederatedTrustContext {

    private final String federatedPrincipal;
    private final Map<String, String> conditionClaims;

    public FederatedTrustContext(String federatedPrincipal, Map<String, String> conditionClaims) {
        this.federatedPrincipal = federatedPrincipal;
        this.conditionClaims = conditionClaims == null
                ? Map.of()
                : Collections.unmodifiableMap(new LinkedHashMap<>(conditionClaims));
    }

    public String federatedPrincipal() {
        return federatedPrincipal;
    }

    public Map<String, String> conditionClaims() {
        return conditionClaims;
    }
}
