package io.github.hectorvent.floci.core.common.auth;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

/**
 * Single derived view of CTF auth posture from existing config knobs.
 *
 * <p>Does not flip {@code application.yml} lab defaults. Activate Quarkus profile {@code ctf}
 * ({@code application-ctf.yml} / {@code QUARKUS_PROFILE=ctf}) or Compose FLOCI_* env for full
 * CTF posture. Under {@link #strict()}, federated crypto and signatures are coerced on in this
 * posture. {@link #signatureValidationActive()} follows the configured SigV4 knob so lab profiles
 * ({@code CtfLabIamEnforcementProfile}) that keep unsigned Authorization under strict IAM still work.
 */
@ApplicationScoped
public class AuthPosture {

    private final boolean iamEnforced;
    private final boolean strict;
    private final boolean signaturesRequired;
    private final boolean federatedCryptoRequired;
    private final boolean egressBlock;
    private final boolean signatureValidationActive;

    @Inject
    public AuthPosture(EmulatorConfig config) {
        this(derive(config));
    }

    AuthPosture(Derived derived) {
        this.iamEnforced = derived.iamEnforced();
        this.strict = derived.strict();
        this.signaturesRequired = derived.signaturesRequired();
        this.federatedCryptoRequired = derived.federatedCryptoRequired();
        this.egressBlock = derived.egressBlock();
        this.signatureValidationActive = derived.signatureValidationActive();
    }

    /**
     * Pure derivation for unit tests and non-CDI callers (e.g. federated config factories).
     */
    public static AuthPosture from(EmulatorConfig config) {
        return new AuthPosture(derive(config));
    }

    static Derived derive(EmulatorConfig config) {
        boolean iamEnforced = config.services().iam().enforcementEnabled();
        boolean strict = config.services().iam().strictEnforcementEnabled();
        boolean configuredSignatures = config.auth().validateSignatures();
        boolean configuredFederated = config.ctf().validateFederatedTokens();
        boolean egressBlock = config.ctf().blockPrivateOutboundUrls();

        // When strict, coerce federated crypto + signatures in the posture API.
        boolean signaturesRequired = configuredSignatures || strict;
        boolean federatedCryptoRequired = configuredFederated || strict;

        return new Derived(
                iamEnforced,
                strict,
                signaturesRequired,
                federatedCryptoRequired,
                egressBlock,
                configuredSignatures);
    }

    public boolean iamEnforced() {
        return iamEnforced;
    }

    public boolean strict() {
        return strict;
    }

    /**
     * Whether CTF posture requires SigV4 (configured or coerced under {@link #strict()}).
     */
    public boolean signaturesRequired() {
        return signaturesRequired;
    }

    /**
     * Whether the SigV4 / presign filters will actually verify (configured knob only).
     * Lab profiles may keep this false under strict; CTF profile and Compose set the knob on.
     */
    public boolean signatureValidationActive() {
        return signatureValidationActive;
    }

    /**
     * Whether CTF posture requires federated JWT/SAML crypto (configured or coerced under strict).
     */
    public boolean federatedCryptoRequired() {
        return federatedCryptoRequired;
    }

    public boolean egressBlock() {
        return egressBlock;
    }

    /**
     * When true, {@code RequestContext.accessKeyId} must not be set from an unverified
     * Authorization / X-Amz-Credential header (O23). Set only after SigV4 or presign verify.
     */
    public boolean deferCallerAccessKeyUntilVerified() {
        return signatureValidationActive;
    }

    /**
     * True when strict coerced signatures on but the SigV4 YAML/env knob is still off.
     * Compose CTF and profile {@code ctf} set both. Lab unsigned-header profiles hit this on purpose.
     */
    public boolean signaturePostureMismatch() {
        return signaturesRequired && !signatureValidationActive;
    }

    record Derived(
            boolean iamEnforced,
            boolean strict,
            boolean signaturesRequired,
            boolean federatedCryptoRequired,
            boolean egressBlock,
            boolean signatureValidationActive) {
    }
}
