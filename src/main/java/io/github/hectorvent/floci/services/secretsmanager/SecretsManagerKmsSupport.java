package io.github.hectorvent.floci.services.secretsmanager;

import io.github.hectorvent.floci.services.kms.KmsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;

/**
 * Encrypts secret payloads with a CMK so {@code GetSecretValue} returns a
 * {@code SecretBinary} blob compatible with {@code aws kms decrypt --ciphertext-blob}.
 *
 * <p>Wire format: UTF-8 bytes of the Floci KMS v2 blob (see {@link KmsService#encrypt}),
 * Base64-encoded in the Secrets Manager JSON API field.
 */
@ApplicationScoped
public class SecretsManagerKmsSupport {

    private final KmsService kmsService;

    @Inject
    public SecretsManagerKmsSupport(KmsService kmsService) {
        this.kmsService = kmsService;
    }

    public String encryptSecretPayloadBase64(String kmsKeyId, byte[] plaintext, String region) {
        if (kmsKeyId == null || kmsKeyId.isBlank() || plaintext == null || plaintext.length == 0) {
            return null;
        }
        byte[] ciphertext = kmsService.encrypt(kmsKeyId, plaintext, region);
        return Base64.getEncoder().encodeToString(ciphertext);
    }

    public String encryptSecretStringBase64(String kmsKeyId, String secretString, String region) {
        if (secretString == null) {
            return null;
        }
        return encryptSecretPayloadBase64(kmsKeyId, secretString.getBytes(StandardCharsets.UTF_8), region);
    }
}
