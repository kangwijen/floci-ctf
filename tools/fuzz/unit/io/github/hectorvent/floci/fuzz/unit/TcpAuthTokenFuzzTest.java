package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.elasticache.proxy.SigV4Validator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.rds.proxy.RdsSigV4Validator;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.Arbitraries;
import org.mockito.Mockito;

import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

/**
 * TCP wire IAM auth token fuzz: ElastiCache/MemoryDB {@link SigV4Validator} and
 * RDS {@link RdsSigV4Validator}. Garbage tokens must not crash the JVM and must
 * not validate as true when keys are unknown or input is empty/malformed.
 */
class TcpAuthTokenFuzzTest {

    private static final IamService NO_KEYS_IAM = noKeysIamService();
    private static final SigV4Validator ELASTICACHE = FuzzFixtures.elasticacheSigV4Validator(NO_KEYS_IAM);
    private static final RdsSigV4Validator RDS = FuzzFixtures.rdsSigV4Validator(NO_KEYS_IAM);

    @Property(tries = 80)
    void elasticacheValidateNeverThrowsError(
            @ForAll @StringLength(max = 400) String token,
            @ForAll @StringLength(max = 80) String groupId,
            @ForAll @StringLength(max = 80) String username) throws Exception {
        String seed = token + "|" + groupId + "|" + username;
        CrashWatchdog.run("SigV4Validator.validate", seed, 2000, () -> {
            SecurityOracle.runCatching("SigV4Validator.validate", seed, () ->
                    ELASTICACHE.validate(
                            token == null ? "" : token,
                            blankToNull(groupId),
                            blankToNull(username)));
            return null;
        });
    }

    @Property(tries = 80)
    void rdsValidateNeverThrowsError(
            @ForAll @StringLength(max = 400) String token,
            @ForAll @StringLength(max = 80) String clientUsername) throws Exception {
        String seed = token + "|" + clientUsername;
        CrashWatchdog.run("RdsSigV4Validator.validate", seed, 2000, () -> {
            SecurityOracle.runCatching("RdsSigV4Validator.validate", seed, () ->
                    RDS.validate(token == null ? "" : token, blankToNull(clientUsername)));
            return null;
        });
    }

    @Property(tries = 5)
    void knownEmptyTokensNeverValid() {
        for (String token : List.of("", " ", "\t", "\n", "   ")) {
            if (ELASTICACHE.validate(token, "cache-cluster-01", "default")) {
                SecurityOracle.failSecurity(
                        "SigV4Validator.empty",
                        repr(token),
                        "blank ElastiCache IAM token accepted as valid",
                        Map.of());
            }
            if (RDS.validate(token, "admin")) {
                SecurityOracle.failSecurity(
                        "RdsSigV4Validator.empty",
                        repr(token),
                        "blank RDS IAM token accepted as valid",
                        Map.of());
            }
        }
    }

    @Property(tries = 40)
    void garbageTokenNeverValidWithUnknownSigningKey(
            @ForAll @StringLength(min = 1, max = 200) String token,
            @ForAll @StringLength(max = 40) String groupId,
            @ForAll @StringLength(max = 40) String username) {
        if (token.isBlank()) {
            return;
        }
        String group = groupId.isBlank() ? "fuzz-cluster" : groupId;
        String user = username.isBlank() ? "fuzz-user" : username;
        if (ELASTICACHE.validate(token, group, user)) {
            SecurityOracle.failSecurity(
                    "SigV4Validator.garbage",
                    token,
                    "random token validated without registered signing key",
                    Map.of("groupId", group, "username", user));
        }
        if (RDS.validate(token, user)) {
            SecurityOracle.failSecurity(
                    "RdsSigV4Validator.garbage",
                    token,
                    "random token validated without registered signing key",
                    Map.of("clientUsername", user));
        }
    }

    @Property(tries = 20)
    void corpusTokensNeverValidateAsTrue(@ForAll("corpusTokens") String token) {
        if (token.isBlank()) {
            return;
        }
        if (token.contains("DBUser=") || token.startsWith("db.")) {
            if (RDS.validate(token, "admin")) {
                SecurityOracle.failSecurity(
                        "RdsSigV4Validator.corpus",
                        token,
                        "corpus RDS token accepted as valid",
                        Map.of());
            }
            return;
        }
        if (ELASTICACHE.validate(token, "cache-cluster-01", "default")) {
            SecurityOracle.failSecurity(
                    "SigV4Validator.corpus",
                    token,
                    "corpus ElastiCache token accepted as valid",
                    Map.of());
        }
    }

    @Provide
    Arbitrary<String> corpusTokens() {
        List<String> samples = CorpusLoader.orFallback("tcp/tokens.txt", List.of(
                "cache-cluster-01/?Action=connect&User=default&X-Amz-Signature=deadbeef",
                "db.example.local:5432/?Action=connect&DBUser=admin&X-Amz-Signature=deadbeef"));
        return Arbitraries.of(samples);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value;
    }

    private static IamService noKeysIamService() {
        IamService iamService = Mockito.mock(IamService.class);
        when(iamService.findSecretKey(anyString())).thenReturn(Optional.empty());
        return iamService;
    }

    private static String repr(String token) {
        if (token == null) {
            return "null";
        }
        if (token.isEmpty()) {
            return "<empty>";
        }
        return token.replace("\n", "\\n").replace("\t", "\\t");
    }
}
