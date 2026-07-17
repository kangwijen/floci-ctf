package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;

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
     * Compose CTF sets {@code FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=true}. Under IAM enforcement
     * plus strict mode, federated crypto is also required even when the YAML default stays false.
     * Does not flip {@code application.yml} global defaults (Phase B AuthPosture).
     */
    public static FederatedTokenValidationConfig from(EmulatorConfig config) {
        EmulatorConfig.CtfConfig ctf = config.ctf();
        boolean strictIam = config.services().iam().enforcementEnabled()
                && config.services().iam().strictEnforcementEnabled();
        boolean validate = ctf.validateFederatedTokens() || strictIam;
        return new FederatedTokenValidationConfig(
                validate,
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
