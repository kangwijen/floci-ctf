package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.ContainerEnvHardening;
import io.github.hectorvent.floci.core.common.OperatorCredentialEnv;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.ExtremeValueGenerators;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;
import org.junit.jupiter.api.Assumptions;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

/**
 * Container env hardening helpers used by {@code ContainerLauncher} and {@code CodeBuildRunner}.
 *
 * <p>Full blank-role launcher behavior is covered by {@code LambdaBlankRoleOperatorCredentialIntegrationTest}
 * and {@code CodeBuildBlankServiceRoleIntegrationTest} in {@code src/test}. This fuzz module focuses on
 * {@link ContainerEnvHardening} and the launcher merge path mirrored from
 * {@code ContainerLauncher} / {@code CodeBuildRunner}: when IAM enforcement is on and the
 * execution role is blank or null (no credential token), {@link OperatorCredentialEnv} must
 * not inject host root credentials. When enforcement is off, operator injection is allowed
 * but user-supplied credential keys are still stripped first.
 */
class BlankRoleOperatorEnvFuzzTest {

    private static final String USER_SECRET_MARKER = "player-supplied-secret-marker";

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
    void enforcementOnBlankOrNullRoleNeverInjectsOperatorRoot(
            @ForAll("blankRoleCredentialTokens") String credentialToken,
            @ForAll("blockedKeys") String blockedKey,
            @ForAll @StringLength(min = 1, max = 40) String userValue,
            @ForAll @StringLength(min = 1, max = 16) String suffix) {
        Map<String, String> userEnv = Map.of(
                blockedKey, userValue,
                "CUSTOM_" + suffix, "player");

        Map<String, String> mapEnv = simulateMapLauncherEnv(userEnv, true, credentialToken);
        SecurityOracle.expectNoCredentialKey(mapEnv, "BlankRole.mapLauncher", blockedKey);
        assertNoOperatorRootKeys(mapEnv, "BlankRole.mapLauncher", suffix);
        assertNoOperatorHostCredentialKeys(mapEnv, "BlankRole.mapLauncher", suffix);

        List<String> listEnv = simulateListLauncherEnv(userEnv, true, credentialToken);
        assertListHasNoCredentialKeys(listEnv, "BlankRole.listLauncher", blockedKey);
        assertListHasNoOperatorHostCredentialKeys(listEnv, "BlankRole.listLauncher", suffix);
    }

    @Property(tries = 40)
    void enforcementOffStripsUserCredentialsBeforeOperatorMayInject(
            @ForAll("blankRoleCredentialTokens") String credentialToken,
            @ForAll @StringLength(min = 1, max = 16) String suffix) {
        Map<String, String> userEnv = Map.of(
                "AWS_ACCESS_KEY_ID", "AKIAPLAYER",
                "AWS_SECRET_ACCESS_KEY", USER_SECRET_MARKER,
                "CUSTOM_" + suffix, "player");

        Map<String, String> mapEnv = simulateMapLauncherEnv(userEnv, false, credentialToken);
        assertUserSecretMarkerAbsent(mapEnv, "BlankRole.enforcementOff.map", suffix);
        SecurityOracle.expectNoCredentialKey(mapEnv, "BlankRole.enforcementOff.map", USER_SECRET_MARKER);

        List<String> listEnv = simulateListLauncherEnv(userEnv, false, credentialToken);
        for (String entry : listEnv) {
            if (entry.contains(USER_SECRET_MARKER)) {
                SecurityOracle.failSecurity(
                        "BlankRole.enforcementOff.list",
                        suffix,
                        "user secret marker survived enforcement-off launcher path",
                        Map.of("entry", entry));
            }
        }
    }

    @Property(tries = 60)
    void mergeUserEnvStripsUserSuppliedSecret(
            @ForAll @StringLength(min = 8, max = 48) String userSecret) {
        Map<String, String> target = new LinkedHashMap<>();
        Map<String, String> userSupplied = Map.of(
                "AWS_SECRET_ACCESS_KEY", userSecret,
                "PLAYER_FLAG", "ok");

        ContainerEnvHardening.mergeUserEnvThenOperatorCredentials(target, userSupplied);

        if (target.containsValue(userSecret)) {
            SecurityOracle.failSecurity(
                    "BlankRole.mergeUserEnv.secret",
                    userSecret,
                    "user-supplied AWS_SECRET_ACCESS_KEY value retained after merge",
                    Map.of());
        }
        if (!target.containsKey("PLAYER_FLAG")) {
            SecurityOracle.failSecurity(
                    "BlankRole.mergeUserEnv.flag",
                    userSecret,
                    "non-credential user key removed by merge",
                    Map.of());
        }
    }

    @Property(tries = 60)
    void filterEnvListStripsUserSuppliedSecret(
            @ForAll @StringLength(min = 8, max = 48) String userSecret) {
        List<String> filtered = ContainerEnvHardening.filterEnvList(List.of(
                "AWS_SECRET_ACCESS_KEY=" + userSecret,
                "PLAYER_VAR=ok"));
        for (String entry : filtered) {
            if (entry.contains(userSecret)) {
                SecurityOracle.failSecurity(
                        "BlankRole.filterEnvList.secret",
                        userSecret,
                        "user-supplied secret survived filterEnvList",
                        Map.of("entry", entry));
            }
        }
    }

    @Property(tries = 40)
    void extremeEnvKeyNamesNeverThrow(
            @ForAll("extremeEnvKeys") String key,
            @ForAll @StringLength(max = 40) String value) throws Exception {
        String seed = key == null ? "<null>" : key;
        CrashWatchdog.run("BlankRole.extremeKeys", seed, 2000, () -> {
            SecurityOracle.runCatching("BlankRole.extremeKeys", seed, () -> {
                Map<String, String> env = new LinkedHashMap<>();
                ContainerEnvHardening.putIfAllowed(env, key, value);
                ContainerEnvHardening.putAllIfAllowed(env, Map.of(Optional.ofNullable(key).orElse("k"), value));
                ContainerEnvHardening.removeBlockedKeys(env);
                ContainerEnvHardening.filterEnvList(List.of(
                        (key == null ? "NULLKEY" : key) + "=" + value,
                        "PATH=/usr/bin"));
                simulateMapLauncherEnv(Map.of(Optional.ofNullable(key).orElse("k"), value), true, null);
                simulateListLauncherEnv(Map.of(Optional.ofNullable(key).orElse("k"), value), true, null);
                return null;
            });
            return null;
        });
    }

    @Property(tries = 40)
    void enforcementOnWithCredentialTokenSkipsOperatorRoot(
            @ForAll("nonBlankCredentialTokens") String token) {
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
        String token = blankCredentialToken(credentialToken);
        Map<String, String> env = new LinkedHashMap<>();
        ContainerEnvHardening.putAllIfAllowed(env, userSupplied);
        ContainerEnvHardening.removeBlockedKeys(env);
        if (token != null) {
            env.put("AWS_CONTAINER_CREDENTIALS_FULL_URI",
                    "http://169.254.170.2:9171/v2/credentials/" + token);
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
        String token = blankCredentialToken(credentialToken);
        List<String> env = new ArrayList<>();
        if (userSupplied != null) {
            userSupplied.forEach((k, v) -> {
                if (!ContainerEnvHardening.isBlocked(k)) {
                    env.add(k + "=" + v);
                }
            });
        }
        if (token != null) {
            env.add("AWS_CONTAINER_CREDENTIALS_FULL_URI="
                    + "http://169.254.170.2:9171/v2/credentials/" + token);
        } else if (!enforcementEnabled) {
            OperatorCredentialEnv.addIfPresent(env);
        }
        return ContainerEnvHardening.filterEnvList(env);
    }

    private static String blankCredentialToken(String credentialToken) {
        if (credentialToken == null || credentialToken.isBlank()) {
            return null;
        }
        return credentialToken;
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

    private static void assertNoOperatorHostCredentialKeys(
            Map<String, String> env, String target, String seed) {
        for (Map.Entry<String, String> entry : env.entrySet()) {
            String upper = entry.getKey().toUpperCase(Locale.ROOT);
            if ("AWS_ACCESS_KEY_ID".equals(upper)
                    || "AWS_SECRET_ACCESS_KEY".equals(upper)
                    || "AWS_SESSION_TOKEN".equals(upper)) {
                String hostValue = System.getenv(entry.getKey());
                if (hostValue != null && hostValue.equals(entry.getValue())) {
                    SecurityOracle.failSecurity(
                            target,
                            seed,
                            "operator host credential injected under enforcement-on blank role",
                            Map.of("key", entry.getKey()));
                }
            }
        }
    }

    private static void assertListHasNoOperatorHostCredentialKeys(
            List<String> env, String target, String seed) {
        for (String entry : env) {
            int eq = entry.indexOf('=');
            if (eq <= 0) {
                continue;
            }
            String key = entry.substring(0, eq);
            String value = entry.substring(eq + 1);
            String upper = key.toUpperCase(Locale.ROOT);
            if ("AWS_ACCESS_KEY_ID".equals(upper)
                    || "AWS_SECRET_ACCESS_KEY".equals(upper)
                    || "AWS_SESSION_TOKEN".equals(upper)) {
                String hostValue = System.getenv(key);
                if (hostValue != null && hostValue.equals(value)) {
                    SecurityOracle.failSecurity(
                            target,
                            seed,
                            "operator host credential injected in list env under enforcement-on blank role",
                            Map.of("entry", entry));
                }
            }
        }
    }

    private static void assertUserSecretMarkerAbsent(
            Map<String, String> env, String target, String seed) {
        for (String value : env.values()) {
            if (USER_SECRET_MARKER.equals(value)) {
                SecurityOracle.failSecurity(
                        target,
                        seed,
                        "user-supplied secret marker retained in launcher env",
                        Map.of());
            }
        }
    }

    @Provide
    Arbitrary<String> nonBlankCredentialTokens() {
        return Arbitraries.strings().withCharRange('a', 'z').ofMinLength(8).ofMaxLength(24);
    }

    @Provide
    Arbitrary<String> blankRoleCredentialTokens() {
        return Arbitraries.of(null, "");
    }

    @Provide
    Arbitrary<String> extremeEnvKeys() {
        return ExtremeValueGenerators.extremeEnvKeyNames();
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
