package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;

import java.util.Collections;
import java.util.Map;
import java.util.Optional;

/**
 * CTF federated token validation settings from {@link EmulatorConfig.CtfConfig}.
 */
public record FederatedTokenValidationConfig(
        boolean validateFederatedTokens,
        Optional<String> federatedJwtHmacSecret,
        Map<String, String> federatedJwtHmacSecrets,
        Optional<String> federatedJwtRs256PublicKeyPem) {

    public FederatedTokenValidationConfig {
        federatedJwtHmacSecrets = federatedJwtHmacSecrets == null
                ? Map.of()
                : Collections.unmodifiableMap(federatedJwtHmacSecrets);
    }

    public static FederatedTokenValidationConfig disabled() {
        return new FederatedTokenValidationConfig(false, Optional.empty(), Map.of(), Optional.empty());
    }

    public static FederatedTokenValidationConfig from(EmulatorConfig.CtfConfig ctf) {
        return new FederatedTokenValidationConfig(
                ctf.validateFederatedTokens(),
                ctf.federatedJwtHmacSecret(),
                ctf.federatedJwtHmacSecrets() == null ? Map.of() : ctf.federatedJwtHmacSecrets(),
                ctf.federatedJwtRs256PublicKeyPem());
    }

    public Optional<String> resolveHmacSecret(String providerHost) {
        if (providerHost != null && !providerHost.isBlank()) {
            String perProvider = federatedJwtHmacSecrets.get(providerHost);
            if (perProvider != null && !perProvider.isBlank()) {
                return Optional.of(perProvider);
            }
        }
        return federatedJwtHmacSecret.filter(secret -> !secret.isBlank());
    }
}
