package io.github.hectorvent.floci.fuzz.operator;

import java.util.Optional;

/**
 * Optional participant IAM credentials for signed differential operator campaigns.
 *
 * <p>Loaded from {@code FUZZ_PARTICIPANT_ACCESS_KEY_ID} / {@code FUZZ_PARTICIPANT_SECRET_ACCESS_KEY}
 * / {@code FUZZ_PARTICIPANT_SESSION_TOKEN} or {@code fuzz.participant.*} system properties.
 */
public record ParticipantCredentials(
        String accessKeyId,
        String secretAccessKey,
        String sessionToken) {

    public static Optional<ParticipantCredentials> fromEnv() {
        return load(
                "FUZZ_PARTICIPANT_ACCESS_KEY_ID",
                "FUZZ_PARTICIPANT_SECRET_ACCESS_KEY",
                "FUZZ_PARTICIPANT_SESSION_TOKEN",
                "fuzz.participant.accessKeyId",
                "fuzz.participant.secretAccessKey",
                "fuzz.participant.sessionToken");
    }

    /** Presigned POST operator mutation credentials ({@code FUZZ_PRESIGN_*}). */
    public static Optional<ParticipantCredentials> presignFromEnv() {
        return load(
                "FUZZ_PRESIGN_ACCESS_KEY_ID",
                "FUZZ_PRESIGN_SECRET_ACCESS_KEY",
                "FUZZ_PRESIGN_SESSION_TOKEN",
                "fuzz.presign.accessKeyId",
                "fuzz.presign.secretAccessKey",
                "fuzz.presign.sessionToken");
    }

    private static Optional<ParticipantCredentials> load(
            String envAccessKeyId,
            String envSecret,
            String envSessionToken,
            String propAccessKeyId,
            String propSecret,
            String propSessionToken) {
        String accessKeyId = firstNonBlank(
                System.getenv(envAccessKeyId),
                System.getProperty(propAccessKeyId));
        String secret = firstNonBlank(
                System.getenv(envSecret),
                System.getProperty(propSecret));
        if (accessKeyId == null || accessKeyId.isBlank() || secret == null || secret.isBlank()) {
            return Optional.empty();
        }
        String sessionToken = firstNonBlank(
                System.getenv(envSessionToken),
                System.getProperty(propSessionToken));
        return Optional.of(new ParticipantCredentials(
                accessKeyId.trim(),
                secret.trim(),
                sessionToken == null || sessionToken.isBlank() ? null : sessionToken.trim()));
    }

    private static String firstNonBlank(String... values) {
        if (values == null) {
            return null;
        }
        for (String v : values) {
            if (v != null && !v.isBlank()) {
                return v;
            }
        }
        return null;
    }
}
