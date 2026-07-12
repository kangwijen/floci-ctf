package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.services.iam.FederatedTokenParser;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.StringLength;

import java.util.Base64;

/**
 * Federated token / SAML parser fuzz: garbage must not crash the JVM.
 */
class FederatedTokenParserFuzzTest {

    @Property(tries = 60)
    void webIdentityGarbageDoesNotThrowError(
            @ForAll @StringLength(max = 500) String token) throws Exception {
        CrashWatchdog.run("FederatedTokenParser.webIdentity", token, 2000, () -> {
            try {
                FederatedTokenParser.parseWebIdentityToken(token, "example.com", "111122223333");
            } catch (RuntimeException ignored) {
                // Expected for malformed tokens.
            }
            return null;
        });
    }

    @Property(tries = 40)
    void samlGarbageDoesNotThrowError(
            @ForAll @StringLength(max = 400) String xmlish) throws Exception {
        String b64 = Base64.getEncoder().encodeToString(xmlish.getBytes());
        CrashWatchdog.run("FederatedTokenParser.saml", b64, 2000, () -> {
            try {
                FederatedTokenParser.parseSamlAssertion(
                        b64, "arn:aws:iam::111122223333:saml-provider/Example");
            } catch (RuntimeException ignored) {
                // Expected.
            }
            return null;
        });
    }

    @Property(tries = 20)
    void emptyTokenDoesNotAuthBypass() {
        try {
            var ctx = FederatedTokenParser.parseWebIdentityToken("", "example.com", "111122223333");
            if (ctx != null && ctx.federatedPrincipal() != null && !ctx.federatedPrincipal().isBlank()) {
                SecurityOracle.failSecurity(
                        "FederatedTokenParser.empty",
                        "",
                        "empty web identity token produced a trust context",
                        java.util.Map.of("federatedPrincipal", String.valueOf(ctx.federatedPrincipal())));
            }
        } catch (RuntimeException expected) {
            // reject is correct
        }
    }
}
