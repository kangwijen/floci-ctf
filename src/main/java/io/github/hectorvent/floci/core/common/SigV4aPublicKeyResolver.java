package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.security.PublicKey;
import java.util.Map;
import java.util.Optional;

/**
 * Resolves EC P-256 public keys for SigV4a presigned URL and POST verification.
 */
@ApplicationScoped
public class SigV4aPublicKeyResolver {

    private final EmulatorConfig config;

    @Inject
    public SigV4aPublicKeyResolver(EmulatorConfig config) {
        this.config = config;
    }

    public Optional<PublicKey> resolve(String accessKeyId) {
        if (accessKeyId == null || accessKeyId.isBlank()) {
            return Optional.empty();
        }
        Map<String, String> perKey = config.ctf().sigv4aSigningPublicKeys();
        if (perKey != null) {
            String pem = perKey.get(accessKeyId);
            if (pem != null && !pem.isBlank()) {
                return parsePem(pem);
            }
        }
        Optional<String> shared = config.ctf().sigv4aSigningPublicKeyPem();
        if (shared.isPresent() && !shared.get().isBlank()) {
            Optional<String> rootKeyId = config.auth().rootAccessKeyId();
            if (rootKeyId.isPresent() && rootKeyId.get().equals(accessKeyId)) {
                return parsePem(shared.get());
            }
        }
        return Optional.empty();
    }

    private static Optional<PublicKey> parsePem(String pem) {
        try {
            return Optional.of(SigV4aPresignSupport.parseEcPublicKeyPem(pem));
        } catch (Exception e) {
            return Optional.empty();
        }
    }
}
