package io.github.hectorvent.floci.core.common.auth;

import io.github.hectorvent.floci.testsupport.CtfQuarkusProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Asserts {@code QUARKUS_PROFILE=ctf} / {@code application-ctf.yml} enables full CTF AuthPosture.
 * Main {@code application.yml} lab defaults stay permissive.
 */
@QuarkusTest
@TestProfile(CtfQuarkusProfile.class)
@Tag("security-regression")
class CtfProfilePostureIntegrationTest {

    @Inject
    AuthPosture authPosture;

    @Test
    void ctfProfileEnablesFullAuthPosture() {
        assertTrue(authPosture.iamEnforced());
        assertTrue(authPosture.strict());
        assertTrue(authPosture.signaturesRequired());
        assertTrue(authPosture.signatureValidationActive());
        assertTrue(authPosture.federatedCryptoRequired());
        assertTrue(authPosture.egressBlock());
        assertTrue(authPosture.deferCallerAccessKeyUntilVerified());
        assertFalse(authPosture.signaturePostureMismatch());
    }
}
