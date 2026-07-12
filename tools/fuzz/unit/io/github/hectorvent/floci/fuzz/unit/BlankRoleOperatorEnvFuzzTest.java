package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.ContainerEnvHardening;
import io.github.hectorvent.floci.core.common.OperatorCredentialEnv;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Container env hardening helpers used by {@code ContainerLauncher} and {@code CodeBuildRunner}.
 *
 * <p>Full blank-role launcher behavior is covered by {@code LambdaBlankRoleOperatorCredentialIntegrationTest}
 * and {@code CodeBuildBlankServiceRoleIntegrationTest} in {@code src/test}. This fuzz module focuses on
 * {@link ContainerEnvHardening} and the enforcement-on launcher merge path that must not inject
 * {@link OperatorCredentialEnv} when no execution role credentials token is present.
 */
class BlankRoleOperatorEnvFuzzTest {

    @Property(tries = 80)
    void mergeUserEnvStripsBlockedCredentialKeys(
            @ForAll("blockedKeys") String blockedKey,
            @ForAll @StringLength(min = 1, max = 40) String userValue,
            @ForAll @StringLength(min = 1, max = 20) String safeSuffix) {
        Map<String, String> env = new LinkedHashMap<>();
        Map<String, String> userSupplied = new HashMap<>();
        userSupplied.put(blockedKey, userValue);
        userSupplied.put("PLAYER_VAR_" + safeSuffix, "ok");

        ContainerEnvHardening.mergeUserEnvThenOperatorCredentials(env, userSupplied);

        SecurityOracle.expectNoCredentialKey(env, "BlankRole.mergeUserEnv", blockedKey);
        if (!env.containsKey("PLAYER_VAR_" + safeSuffix)) {
            SecurityOracle.failSecurity(
                    "BlankRole.mergeUserEnv",
                    safeSuffix,
                    "non-credential user key was removed",
                    Map.of());
        }
    }

    @Property(tries = 80)
    void filterEnvListStripsBlockedCredentialKeys(
            @ForAll("blockedKeys") String blockedKey,
            @ForAll @StringLength(min = 1, max = 40) String userValue) {
        List<String> filtered = ContainerEnvHardening.filterEnvList(List.of(
                blockedKey + "=" + userValue,
                "PATH=/usr/bin",
                "PLAYER_ROLE=scanner"));
        for (String entry : filtered) {
            String key = entry.split("=", 2)[0].toUpperCase(Locale.ROOT);
            if (ContainerEnvHardening.isBlocked(key)) {
                SecurityOracle.failSecurity(
                        "BlankRole.filterEnvList",
                        entry,
                        "blocked credential entry survived filterEnvList",
                        Map.of("key", key));
            }
        }
    }

    @Property(tries = 60)
    void enforcementOnLauncherPathNeverInjectsOperatorRoot(
            @ForAll("blockedKeys") String blockedKey,
            @ForAll @StringLength(min = 1, max = 40) String userValue,
            @ForAll @StringLength(min = 1, max = 16) String suffix) {
        Map<String, String> userEnv = Map.of(
                blockedKey, userValue,
                "CUSTOM_" + suffix, "player");

        Map<String, String> mapEnv = simulateMapLauncherEnv(userEnv, true, null);
        SecurityOracle.expectNoCredentialKey(mapEnv, "BlankRole.mapLauncher", blockedKey);
        assertNoOperatorRootKeys(mapEnv, "BlankRole.mapLauncher", suffix);

        List<String> listEnv = simulateListLauncherEnv(userEnv, true, null);
        assertListHasNoCredentialKeys(listEnv, "BlankRole.listLauncher", blockedKey);
    }

    @Property(tries = 40)
    void enforcementOnWithCredentialTokenSkipsOperatorRoot(
            @ForAll @StringLength(min = 8, max = 24) String token) {
        Map<String, String> userEnv = Map.of(
                "AWS_ACCESS_KEY_ID", "AKIAPLAYER",
                "AWS_SECRET_ACCESS_KEY", "player-secret");

        Map<String, String> env = simulateMapLauncherEnv(userEnv, true, token);
        SecurityOracle.expectNoCredentialKey(env, "BlankRole.credToken", token);
        assertNoOperatorRootKeys(env, "BlankRole.credToken", token);
        if (!env.containsKey("AWS_CONTAINER_CREDENTIALS_FULL_URI")) {
            SecurityOracle.failSecurity(
                    "BlankRole.credToken",
                    token,
                    "credential token path did not set container credentials URI",
                    Map.of());
        }
    }

    /**
     * Mirrors {@code CodeBuildRunner} env assembly when IAM enforcement is on and service role is blank.
     */
    private static Map<String, String> simulateMapLauncherEnv(
            Map<String, String> userSupplied,
            boolean enforcementEnabled,
            String credentialToken) {
        Map<String, String> env = new LinkedHashMap<>();
        ContainerEnvHardening.putAllIfAllowed(env, userSupplied);
        ContainerEnvHardening.removeBlockedKeys(env);
        if (credentialToken != null) {
            env.put("AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    "http://169.254.170.2:9171/v2/credentials/" + credentialToken);
        } else if (!enforcementEnabled) {
            OperatorCredentialEnv.putIfPresent(env);
        }
        return env;
    }

    /**
     * Mirrors {@code ContainerLauncher} list env assembly when IAM enforcement is on and Lambda role is blank.
     */
    private static List<String> simulateListLauncherEnv(
            Map<String, String> userSupplied,
            boolean enforcementEnabled,
            String credentialToken) {
        List<String> env = new ArrayList<>();
        if (userSupplied != null) {
            userSupplied.forEach((k, v) -> {
                if (!ContainerEnvHardening.isBlocked(k)) {
                    env.add(k + "=" + v);
                }
            });
        }
        if (credentialToken != null) {
            env.add("AWS_CONTAINER_CREDENTIALS_FULL_URI="
                    + "http://169.254.170.2:9171/v2/credentials/" + credentialToken);
        } else if (!enforcementEnabled) {
            OperatorCredentialEnv.addIfPresent(env);
        }
        return ContainerEnvHardening.filterEnvList(env);
    }

    private static void assertNoOperatorRootKeys(Map<String, String> env, String target, String seed) {
        for (String key : env.keySet()) {
            String upper = key.toUpperCase(Locale.ROOT);
            if (upper.startsWith("FLOCI_AUTH_")) {
                SecurityOracle.failSecurity(
                        target,
                        seed,
                        "operator root env key present under enforcement-on blank role",
                        Map.of("key", key));
            }
        }
    }

    private static void assertListHasNoCredentialKeys(List<String> env, String target, String seed) {
        for (String entry : env) {
            String key = entry.split("=", 2)[0];
            if (ContainerEnvHardening.isBlocked(key)) {
                SecurityOracle.failSecurity(
                        target,
                        seed,
                        "blocked credential entry in launcher list env",
                        Map.of("entry", entry));
            }
        }
    }

    @Provide
    Arbitrary<String> blockedKeys() {
        return Arbitraries.of(
                "AWS_ACCESS_KEY_ID",
                "AWS_SECRET_ACCESS_KEY",
                "AWS_SESSION_TOKEN",
                "AWS_SECURITY_TOKEN",
                "FLOCI_AUTH_ROOT_ACCESS_KEY_ID",
                "FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY",
                "AWS_CONTAINER_CREDENTIALS_FULL_URI",
                "AWS_ROLE_ARN");
    }
}
