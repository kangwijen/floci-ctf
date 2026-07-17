package io.github.hectorvent.floci.core.common.auth;

import io.github.hectorvent.floci.config.EmulatorConfig;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@Tag("security-regression")
class AuthPostureTest {

    @Test
    void labDefaultsArePermissive() {
        AuthPosture posture = AuthPosture.from(config(false, false, false, false, false));
        assertFalse(posture.iamEnforced());
        assertFalse(posture.strict());
        assertFalse(posture.signaturesRequired());
        assertFalse(posture.federatedCryptoRequired());
        assertFalse(posture.egressBlock());
        assertFalse(posture.signatureValidationActive());
        assertFalse(posture.deferCallerAccessKeyUntilVerified());
        assertFalse(posture.signaturePostureMismatch());
    }

    @Test
    void strictCoercesSignaturesAndFederatedCrypto() {
        AuthPosture posture = AuthPosture.from(config(true, true, false, false, false));
        assertTrue(posture.iamEnforced());
        assertTrue(posture.strict());
        assertTrue(posture.signaturesRequired());
        assertTrue(posture.federatedCryptoRequired());
        assertFalse(posture.signatureValidationActive());
        assertTrue(posture.signaturePostureMismatch());
        assertFalse(posture.deferCallerAccessKeyUntilVerified());
    }

    @Test
    void configuredKnobsEnableWithoutStrict() {
        AuthPosture posture = AuthPosture.from(config(true, false, true, true, true));
        assertTrue(posture.iamEnforced());
        assertFalse(posture.strict());
        assertTrue(posture.signaturesRequired());
        assertTrue(posture.federatedCryptoRequired());
        assertTrue(posture.egressBlock());
        assertTrue(posture.signatureValidationActive());
        assertTrue(posture.deferCallerAccessKeyUntilVerified());
        assertFalse(posture.signaturePostureMismatch());
    }

    @Test
    void composeCtfStylePostureHasNoMismatch() {
        AuthPosture posture = AuthPosture.from(config(true, true, true, true, true));
        assertTrue(posture.signaturesRequired());
        assertTrue(posture.federatedCryptoRequired());
        assertTrue(posture.signatureValidationActive());
        assertTrue(posture.deferCallerAccessKeyUntilVerified());
        assertFalse(posture.signaturePostureMismatch());
    }

    private static EmulatorConfig config(
            boolean iamEnforced,
            boolean strict,
            boolean validateSignatures,
            boolean validateFederated,
            boolean blockEgress) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);

        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
        when(iam.enforcementEnabled()).thenReturn(iamEnforced);
        when(iam.strictEnforcementEnabled()).thenReturn(strict);
        when(config.auth()).thenReturn(auth);
        when(auth.validateSignatures()).thenReturn(validateSignatures);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.validateFederatedTokens()).thenReturn(validateFederated);
        when(ctf.blockPrivateOutboundUrls()).thenReturn(blockEgress);
        return config;
    }
}
