package io.github.hectorvent.floci.core.common;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.spec.ECGenParameterSpec;
import java.util.Base64;

/** One-shot helper to print a fixed P-256 key pair for test fixtures. */
public final class SigV4aTestFixtureGenerator {

    public static void main(String[] args) throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("EC");
        generator.initialize(new ECGenParameterSpec("secp256r1"));
        KeyPair pair = generator.generateKeyPair();
        System.out.println("ACCESS_KEY=AKIATESTSIGV4A01");
        System.out.println("PUBLIC_PEM=" + toPem("PUBLIC KEY", pair.getPublic().getEncoded()));
        System.out.println("PRIVATE_PEM=" + toPem("PRIVATE KEY", pair.getPrivate().getEncoded()));
    }

    private static String toPem(String type, byte[] encoded) {
        String b64 = Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(encoded);
        return "-----BEGIN " + type + "-----\n" + b64 + "\n-----END " + type + "-----";
    }

    private SigV4aTestFixtureGenerator() {
    }
}
