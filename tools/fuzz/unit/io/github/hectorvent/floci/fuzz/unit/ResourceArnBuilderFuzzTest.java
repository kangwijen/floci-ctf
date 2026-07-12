package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import jakarta.ws.rs.container.ContainerRequestContext;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;

import java.util.List;

/**
 * Property fuzz for {@link ResourceArnBuilder}: must not throw Errors and must not
 * collapse secrets-manager path inputs into an unrelated service ARN.
 */
class ResourceArnBuilderFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final ResourceArnBuilder BUILDER = FuzzFixtures.resourceArnBuilder();

    @Property(tries = 80)
    void buildNeverThrowsError(
            @ForAll("scopes") String scope,
            @ForAll @StringLength(max = 200) String body) throws Exception {
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|" + body;
        CrashWatchdog.run("ResourceArnBuilder.build", seed, 2000, () -> {
            SecurityOracle.runCatching("ResourceArnBuilder.build", seed,
                    () -> BUILDER.build(scope, ctx, REGION, ACCOUNT));
            return null;
        });
    }

    @Property(tries = 40)
    void ssmParameterNameStaysInSsmNamespace(
            @ForAll @AlphaChars @StringLength(min = 1, max = 40) String name) {
        String json = "{\"Name\":\"/" + name + "\"}";
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", json);
        String arn = BUILDER.build("ssm", ctx, REGION, ACCOUNT);
        if (arn == null) {
            return;
        }
        if (!arn.startsWith("arn:aws:ssm:")) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.ssm",
                    json,
                    "SSM request produced non-ssm ARN",
                    java.util.Map.of("arn", arn));
        }
    }

    @Property(tries = 40)
    void secretsManagerSecretIdStaysInSecretsNamespace(
            @ForAll @AlphaChars @StringLength(min = 1, max = 40) String secretId) {
        String json = "{\"SecretId\":\"" + secretId + "\"}";
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", json);
        String arn = BUILDER.build("secretsmanager", ctx, REGION, ACCOUNT);
        if (arn == null) {
            return;
        }
        if (!arn.contains(":secretsmanager:") && !arn.contains("secret:")) {
            SecurityOracle.failSecurity(
                    "ResourceArnBuilder.secretsmanager",
                    json,
                    "Secrets Manager request produced unrelated ARN",
                    java.util.Map.of("arn", arn));
        }
    }

    @Provide
    Arbitrary<String> scopes() {
        return Arbitraries.of(FuzzRequestContexts.sampleScopes());
    }
}
