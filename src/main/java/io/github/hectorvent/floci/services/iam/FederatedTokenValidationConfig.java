package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;

import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * CTF federated token validation settings from {@link EmulatorConfig.CtfConfig}.
 */
public record FederatedTokenValidationConfig(
        boolean validateFederatedTokens,
        Optional<String> federatedJwtHmacSecret,
        Map<String, String> federatedJwtHmacSecrets,
        Optional<String> federatedJwtRs256PublicKeyPem,
        Optional<String> federatedSamlSigningCertPem,
        Map<String, String> federatedSamlSigningCerts) {

    public FederatedTokenValidationConfig {
        federatedJwtHmacSecrets = federatedJwtHmacSecrets == null
                ? Map.of()
                : Collections.unmodifiableMap(federatedJwtHmacSecrets);
        federatedSamlSigningCerts = federatedSamlSigningCerts == null
                ? Map.of()
                : Collections.unmodifiableMap(federatedSamlSigningCerts);
    }

    public static FederatedTokenValidationConfig disabled() {
        return new FederatedTokenValidationConfig(
                false, Optional.empty(), Map.of(), Optional.empty(), Optional.empty(), Map.of());
    }

    public static FederatedTokenValidationConfig from(EmulatorConfig.CtfConfig ctf) {
        return new FederatedTokenValidationConfig(
                ctf.validateFederatedTokens(),
                ctf.federatedJwtHmacSecret(),
                ctf.federatedJwtHmacSecrets() == null ? Map.of() : ctf.federatedJwtHmacSecrets(),
                ctf.federatedJwtRs256PublicKeyPem(),
                ctf.federatedSamlSigningCertPem(),
                ctf.federatedSamlSigningCerts() == null ? Map.of() : ctf.federatedSamlSigningCerts());
    }

    /**
     * Profile {@code ctf} and Compose set {@code FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=true}. Under
     * {@link AuthPosture#strict()}, federated crypto is also required even when the lab YAML default
     * stays false. Main {@code application.yml} remains permissive for unit tests and compat.
     */
    public static FederatedTokenValidationConfig from(EmulatorConfig config) {
        EmulatorConfig.CtfConfig ctf = config.ctf();
        AuthPosture posture = AuthPosture.from(config);
        return new FederatedTokenValidationConfig(
                posture.federatedCryptoRequired(),
                ctf.federatedJwtHmacSecret(),
                ctf.federatedJwtHmacSecrets() == null ? Map.of() : ctf.federatedJwtHmacSecrets(),
                ctf.federatedJwtRs256PublicKeyPem(),
                ctf.federatedSamlSigningCertPem(),
                ctf.federatedSamlSigningCerts() == null ? Map.of() : ctf.federatedSamlSigningCerts());
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

    public List<String> resolveSamlSigningCertPems(String providerName) {
        if (providerName != null && !providerName.isBlank()) {
            String perProvider = federatedSamlSigningCerts.get(providerName);
            if (perProvider != null && !perProvider.isBlank()) {
                return List.of(perProvider);
            }
        }
        if (federatedSamlSigningCertPem.isPresent() && !federatedSamlSigningCertPem.get().isBlank()) {
            return List.of(federatedSamlSigningCertPem.get());
        }
        return List.of();
    }
}
