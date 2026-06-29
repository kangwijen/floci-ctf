package io.github.hectorvent.floci.services.secretsmanager;

import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.core.common.RegionResolver;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class SecretsManagerKmsSupportTest {

    private static final String REGION = "us-east-1";

    private SecretsManagerKmsSupport support;
    private KmsService kmsService;

    @BeforeEach
    void setUp() {
        kmsService = new KmsService(
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new InMemoryStorage<>(),
                new RegionResolver(REGION, "000000000000"));
        support = new SecretsManagerKmsSupport(kmsService);
    }

    @Test
    void detectExistingEnvelopeFromSingleBase64Layer() {
        byte[] plaintext = "sample-payload-01".getBytes(StandardCharsets.UTF_8);
        String envelopeB64 = Base64.getEncoder().encodeToString(
                kmsService.encrypt(createKeyId(), plaintext, REGION));

        Optional<byte[]> detected = support.detectExistingEnvelope(null, envelopeB64);

        assertTrue(detected.isPresent());
        assertTrue(new String(detected.get(), StandardCharsets.UTF_8).startsWith("kms:v2:"));
    }

    @Test
    void detectExistingEnvelopeFromDoubleBase64Layer() {
        byte[] plaintext = "sample-payload-02".getBytes(StandardCharsets.UTF_8);
        String envelopeB64 = Base64.getEncoder().encodeToString(
                kmsService.encrypt(createKeyId(), plaintext, REGION));
        String doubleWrapped = Base64.getEncoder().encodeToString(envelopeB64.getBytes(StandardCharsets.UTF_8));

        Optional<byte[]> detected = support.detectExistingEnvelope(null, doubleWrapped);

        assertTrue(detected.isPresent());
        assertTrue(new String(detected.get(), StandardCharsets.UTF_8).startsWith("kms:v2:"));
    }

    @Test
    void detectExistingEnvelopeFromSecretStringDoubleBase64() {
        byte[] plaintext = "sample-payload-03".getBytes(StandardCharsets.UTF_8);
        String envelopeB64 = Base64.getEncoder().encodeToString(
                kmsService.encrypt(createKeyId(), plaintext, REGION));
        String doubleWrapped = Base64.getEncoder().encodeToString(envelopeB64.getBytes(StandardCharsets.UTF_8));

        Optional<byte[]> detected = support.detectExistingEnvelope(doubleWrapped, null);

        assertTrue(detected.isPresent());
    }

    @Test
    void detectExistingEnvelopeIgnoresPlaintextSecretString() {
        Optional<byte[]> detected = support.detectExistingEnvelope("not-a-kms-blob", null);
        assertTrue(detected.isEmpty());
    }

    @Test
    void detectExistingEnvelopeFromRawKmsV2SecretString() {
        byte[] plaintext = "kms-envelope-plaintext".getBytes(StandardCharsets.UTF_8);
        byte[] envelope = kmsService.encrypt(createKeyId(), plaintext, REGION);
        String rawSecretString = new String(envelope, StandardCharsets.UTF_8);

        Optional<byte[]> detected = support.detectExistingEnvelope(rawSecretString, null);

        assertTrue(detected.isPresent());
        assertTrue(new String(detected.get(), StandardCharsets.UTF_8).startsWith("kms:v2:"));
    }

    @Test
    void detectExistingEnvelopeFromKmsV1Prefix() {
        String keyId = createKeyId();
        String v1Blob = "kms:" + keyId + ":" + Base64.getEncoder().encodeToString("legacy-plain".getBytes(StandardCharsets.UTF_8));

        Optional<byte[]> detected = support.detectExistingEnvelope(v1Blob, null);

        assertTrue(detected.isPresent());
        assertEquals(v1Blob, new String(detected.get(), StandardCharsets.UTF_8));
    }

    private String createKeyId() {
        return kmsService.createKey("kms-support-test", REGION).getKeyId();
    }
}
