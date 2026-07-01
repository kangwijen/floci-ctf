package io.github.hectorvent.floci.core.common;

import java.security.PrivateKey;
import java.security.PublicKey;

/** Fixed P-256 key pair for SigV4a integration and unit tests. */
public final class SigV4aTestSupport {

    public static final String ACCESS_KEY_ID = "AKIATESTSIGV4A01";

    private static final String PUBLIC_KEY_PEM = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAECi3Y3xNt3+cwyB6r2UurOShO5lH/
            MsXUQGo4jCPFTeFM0GhP1owYF6ngjs2zzeyG92NC8GqAm8SSA/poZJ/RcA==
            -----END PUBLIC KEY-----""";

    private static final String PRIVATE_KEY_PEM = """
            -----BEGIN PRIVATE KEY-----
            MEECAQAwEwYHKoZIzj0CAQYIKoZIzj0DAQcEJzAlAgEBBCA2yYSabHJfNCUntwLZ
            XmItlVS4wDaeeVFWc8AY+uRbow==
            -----END PRIVATE KEY-----""";

    private static final PublicKey PUBLIC_KEY;
    private static final PrivateKey PRIVATE_KEY;

    static {
        try {
            PUBLIC_KEY = SigV4aPresignSupport.parseEcPublicKeyPem(PUBLIC_KEY_PEM);
            PRIVATE_KEY = SigV4aPresignSupport.parseEcPrivateKeyPem(PRIVATE_KEY_PEM);
        } catch (Exception e) {
            throw new ExceptionInInitializerError(e);
        }
    }

    private SigV4aTestSupport() {
    }

    public static String publicKeyPem() {
        return PUBLIC_KEY_PEM;
    }

    public static PublicKey publicKey() {
        return PUBLIC_KEY;
    }

    public static PrivateKey privateKey() {
        return PRIVATE_KEY;
    }
}
