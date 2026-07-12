package io.github.hectorvent.floci.fuzz.operator;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.Map;
import java.util.Optional;

/**
 * Signed participant differential probes against live CTF Compose.
 *
 * <p>Skipped unless {@code -Pfuzz-operator}, {@code AWS_ENDPOINT_URL}, and participant
 * env ({@code FUZZ_PARTICIPANT_ACCESS_KEY_ID} / {@code FUZZ_PARTICIPANT_SECRET_ACCESS_KEY})
 * are set.
 */
class SignedDifferentialCampaignTest {

    @Test
    void participantStsGetCallerIdentityDeniedWhenUnsignedDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracleWithParticipant();
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "Signed.sts.getCallerIdentity",
                "POST",
                "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded; charset=ISO-8859-1"),
                "Action=GetCallerIdentity&Version=2011-06-15",
                "us-east-1",
                "sts");
    }

    @Test
    void participantS3ListBucketsDeniedWhenUnsignedDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracleWithParticipant();
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "Signed.s3.listBuckets",
                "GET",
                "/",
                Map.of(),
                null,
                "us-east-1",
                "s3");
    }

    @Test
    void participantSecretsGetSecretValueDeniedWhenUnsignedDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracleWithParticipant();
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "Signed.secrets.getSecretValue",
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", "secretsmanager.GetSecretValue"),
                "{\"SecretId\":\"fuzz-flag\"}",
                "us-east-1",
                "secretsmanager");
    }

    private static DifferentialHttpOracle requireOracleWithParticipant() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        Optional<DifferentialHttpOracle> maybe = DifferentialHttpOracle.fromEnv();
        Assumptions.assumeTrue(maybe.isPresent(),
                "Set AWS_ENDPOINT_URL for signed differential campaigns");
        Assumptions.assumeTrue(DifferentialHttpOracle.participantCredentials().isPresent(),
                "Set FUZZ_PARTICIPANT_ACCESS_KEY_ID and FUZZ_PARTICIPANT_SECRET_ACCESS_KEY");
        return maybe.get();
    }
}
