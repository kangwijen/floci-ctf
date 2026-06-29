package io.github.hectorvent.floci.services.secretsmanager;

import io.github.hectorvent.floci.services.kms.KmsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

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

    /**
     * Detects an already-encrypted Floci KMS blob in create/put inputs (raw UTF-8
     * {@code SecretString} or base64-wrapped {@code SecretString}/{@code SecretBinary}).
     */
    public Optional<byte[]> detectExistingEnvelope(String secretString, String secretBinary) {
        if (secretString != null && !secretString.isEmpty()) {
            byte[] utf8 = secretString.getBytes(StandardCharsets.UTF_8);
            if (looksLikeKmsEnvelope(utf8)) {
                return Optional.of(utf8);
            }
            Optional<byte[]> decoded = decodeBase64Envelope(secretString);
            if (decoded.isPresent()) {
                return decoded;
            }
            return decodeNestedBase64Envelope(secretString);
        }
        if (secretBinary != null && !secretBinary.isEmpty()) {
            Optional<byte[]> decoded = decodeBase64Envelope(secretBinary);
            if (decoded.isPresent()) {
                return decoded;
            }
            return decodeNestedBase64Envelope(secretBinary);
        }
        return Optional.empty();
    }

    public String envelopeSecretBinaryBase64(byte[] envelopeBytes) {
        return Base64.getEncoder().encodeToString(envelopeBytes);
    }

    public boolean isPreWrappedEnvelopeBase64(String base64) {
        return decodeBase64Envelope(base64).isPresent();
    }

    public boolean isPreWrappedEnvelope(byte[] bytes) {
        return looksLikeKmsEnvelope(bytes);
    }

    private static Optional<byte[]> decodeBase64Envelope(String base64) {
        try {
            byte[] decoded = Base64.getDecoder().decode(base64);
            if (looksLikeKmsEnvelope(decoded)) {
                return Optional.of(decoded);
            }
        } catch (IllegalArgumentException ignored) {
            // not valid base64
        }
        return Optional.empty();
    }

    /**
     * Handles clients that pre-base64-encode a KMS ciphertext blob and pass the ASCII
     * string to an SDK that base64-encodes {@code SecretBinary} again on the wire.
     */
    private static Optional<byte[]> decodeNestedBase64Envelope(String base64) {
        try {
            byte[] once = Base64.getDecoder().decode(base64);
            if (once.length == 0) {
                return Optional.empty();
            }
            if (looksLikeKmsEnvelope(once)) {
                return Optional.of(once);
            }
            String inner = new String(once, StandardCharsets.UTF_8).trim();
            if (inner.isEmpty() || inner.indexOf('\n') >= 0) {
                return Optional.empty();
            }
            return decodeBase64Envelope(inner);
        } catch (IllegalArgumentException ignored) {
            return Optional.empty();
        }
    }

    private static boolean looksLikeKmsEnvelope(byte[] bytes) {
        if (bytes == null || bytes.length == 0) {
            return false;
        }
        String data = new String(bytes, StandardCharsets.UTF_8);
        if (data.startsWith("kms:v2:")) {
            String[] parts = data.substring("kms:v2:".length()).split(":", 4);
            return parts.length >= 4;
        }
        if (data.startsWith("kms:")) {
            String[] parts = data.substring("kms:".length()).split(":", 2);
            return parts.length == 2;
        }
        return false;
    }
}
