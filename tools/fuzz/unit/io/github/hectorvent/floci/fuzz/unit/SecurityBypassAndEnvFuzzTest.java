package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.ContainerEnvHardening;
import io.github.hectorvent.floci.core.common.CtfHideInternalEndpointsMode;
import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Filter-adjacent auth classification and container env hardening.
 */
class SecurityBypassAndEnvFuzzTest {

    @Property(tries = 60)
    void internalHealthClassificationIsStable(@ForAll("internalPaths") String path) {
        String normalized = SecurityBypassPaths.normalizePath(path);
        boolean internal = SecurityBypassPaths.isInternalHealthOrInfoPath(path)
                || SecurityBypassPaths.isPrefixedInternalPath(normalized)
                || SecurityBypassPaths.isAwsInspectionPath(normalized);
        if (!internal && looksInternal(path)) {
            SecurityOracle.failSecurity(
                    "SecurityBypassPaths.internal",
                    path,
                    "path looks internal but was not classified",
                    Map.of());
        }
    }

    @Property(tries = 40)
    void hideAllMarksHealthAsHidden() {
        boolean hidden = CtfHideInternalEndpointsMode.ALL.isPathHidden("/health");
        if (!hidden) {
            SecurityOracle.failSecurity(
                    "CtfHideInternalEndpointsMode.hideAll",
                    "/health",
                    "hide=all must hide /health",
                    Map.of());
        }
    }

    @Property(tries = 50)
    void cognitoOauthPathsStayClassified(@ForAll("oauthPaths") String path) {
        if (!SecurityBypassPaths.isCognitoOAuthPath(path)) {
            SecurityOracle.failSecurity(
                    "SecurityBypassPaths.oauth",
                    path,
                    "known OAuth path not classified",
                    Map.of());
        }
    }

    @Property(tries = 80)
    void containerEnvHardeningStripsCredentialKeys(
            @ForAll @StringLength(min = 1, max = 30) String suffix) {
        Map<String, String> env = new HashMap<>();
        env.put("AWS_ACCESS_KEY_ID", "AKIAPLAYER");
        env.put("AWS_SECRET_ACCESS_KEY", "secret");
        env.put("AWS_SESSION_TOKEN", "token");
        env.put("AWS_SECURITY_TOKEN", "legacy");
        env.put("NORMAL_KEY_" + suffix, "ok");
        ContainerEnvHardening.removeBlockedKeys(env);
        SecurityOracle.expectNoCredentialKey(env, "ContainerEnvHardening.removeBlockedKeys", suffix);
        if (!env.containsKey("NORMAL_KEY_" + suffix)) {
            SecurityOracle.failSecurity(
                    "ContainerEnvHardening.removeBlockedKeys",
                    suffix,
                    "non-credential key was removed",
                    Map.of());
        }
    }

    @Property(tries = 40)
    void putIfAllowedRejectsAwsAccessKey() {
        Map<String, String> env = new HashMap<>();
        ContainerEnvHardening.putIfAllowed(env, "AWS_ACCESS_KEY_ID", "AKIAPLAYER");
        if (env.containsKey("AWS_ACCESS_KEY_ID")) {
            SecurityOracle.failSecurity(
                    "ContainerEnvHardening.putIfAllowed",
                    "AWS_ACCESS_KEY_ID",
                    "putIfAllowed retained blocked credential key",
                    Map.of());
        }
    }

    @Property(tries = 40)
    void filterEnvListDropsCredentialEntries(
            @ForAll @StringLength(min = 1, max = 20) String value) {
        List<String> filtered = ContainerEnvHardening.filterEnvList(List.of(
                "AWS_SECRET_ACCESS_KEY=" + value,
                "PATH=/usr/bin",
                "AWS_ACCESS_KEY_ID=AKIAPLAYER"));
        for (String entry : filtered) {
            String key = entry.split("=", 2)[0].toUpperCase(Locale.ROOT);
            if (key.contains("AWS_ACCESS_KEY") || key.contains("AWS_SECRET")
                    || key.contains("AWS_SESSION_TOKEN") || "AWS_SECURITY_TOKEN".equals(key)) {
                SecurityOracle.failSecurity(
                        "ContainerEnvHardening.filterEnvList",
                        entry,
                        "credential entry survived filterEnvList",
                        Map.of());
            }
        }
    }

    @Property(tries = 50)
    void normalizePathNeverThrows(@ForAll @StringLength(max = 200) String path) {
        SecurityOracle.runCatching("SecurityBypassPaths.normalizePath", path, () ->
                SecurityBypassPaths.normalizePath(path));
    }

    private static boolean looksInternal(String path) {
        String n = path == null ? "" : path.toLowerCase(Locale.ROOT);
        return n.equals("/health")
                || n.startsWith("/_floci/")
                || n.startsWith("/_localstack/")
                || n.startsWith("/_aws/");
    }

    @Provide
    Arbitrary<String> internalPaths() {
        return Arbitraries.of(
                "/health",
                "/_floci/health",
                "/_floci/state/reset",
                "/_localstack/health",
                "/_aws/cloudformation/ready");
    }

    @Provide
    Arbitrary<String> oauthPaths() {
        return Arbitraries.of(
                "/cognito-idp/oauth2/token",
                "/cognito-idp/oauth2/userInfo");
    }
}
