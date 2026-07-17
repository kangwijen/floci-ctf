package io.github.hectorvent.floci.core.common.auth;

import io.quarkus.runtime.StartupEvent;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.enterprise.event.Observes;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

/**
 * Logs (does not fail) when strict posture coerces signatures required but
 * {@code floci.auth.validate-signatures} is still off. Compose CTF sets both.
 * Lab unsigned-header profiles intentionally hit this until B.4.
 */
@ApplicationScoped
public class AuthPostureStartupCheck {

    private static final Logger LOG = Logger.getLogger(AuthPostureStartupCheck.class);

    private final AuthPosture authPosture;

    @Inject
    public AuthPostureStartupCheck(AuthPosture authPosture) {
        this.authPosture = authPosture;
    }

    void onStart(@Observes StartupEvent event) {
        if (authPosture.signaturePostureMismatch()) {
            LOG.warn("AuthPosture: strict mode coerces signaturesRequired=true but "
                    + "floci.auth.validate-signatures is false. SigV4 filter stays off "
                    + "(lab unsigned Authorization). Compose CTF sets FLOCI_AUTH_VALIDATE_SIGNATURES=true.");
        }
    }
}
