package io.github.hectorvent.floci.services.iam;

import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Writes fixed SAML signing fixtures to {@code src/test/resources/saml/}.
 */
public final class SamlTestFixtureGenerator {

    private SamlTestFixtureGenerator() {
    }

    public static void main(String[] args) throws Exception {
        SamlAssertionTestSupport.SigningMaterial material = SamlAssertionTestSupport.generateSigningMaterial();
        Path dir = Path.of("src/test/resources/saml");
        Files.createDirectories(dir);
        Files.writeString(dir.resolve("idp-signing-cert.pem"), material.certificatePem());
        Files.writeString(dir.resolve("idp-signing-key.pem"), material.privateKeyPem());
        System.out.println("Wrote SAML fixtures to " + dir.toAbsolutePath());
    }
}
