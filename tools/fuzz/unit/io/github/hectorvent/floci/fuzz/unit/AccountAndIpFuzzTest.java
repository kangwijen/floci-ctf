package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.ClientSourceIpResolver;
import io.github.hectorvent.floci.core.common.OperatorCredentialEnv;
import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.mockito.Mockito.when;

/**
 * Client IP resolution and lightweight operator-credential / path helpers.
 */
class AccountAndIpFuzzTest {

    @Property(tries = 40)
    void xffIgnoredWhenTrustForwardedHeadersFalse(
            @ForAll("ips") String xff,
            @ForAll("remotes") String remote) throws Exception {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class, Mockito.RETURNS_DEEP_STUBS);
        when(config.ctf().cloudTrailAllowSourceIpHeader()).thenReturn(false);
        when(config.auth().trustForwardedHeaders()).thenReturn(false);

        String seed = xff + "|" + remote;
        String resolved = CrashWatchdog.run("ClientSourceIpResolver.xff", seed, 2000, () ->
                SecurityOracle.runCatching("ClientSourceIpResolver.xff", seed, () ->
                        ClientSourceIpResolver.resolve(config, null, xff, remote)));
        if (resolved == null) {
            return;
        }
        String expectedRemote = normalizeExpected(remote);
        if (!expectedRemote.equals(resolved)) {
            SecurityOracle.failSecurity(
                    "ClientSourceIpResolver.xff",
                    seed,
                    "expected socket peer when trustForwardedHeaders=false",
                    java.util.Map.of(
                            "resolved", resolved,
                            "remote", remote,
                            "xff", xff));
        }
        if (resolved.equals(xff) && !xff.equals(expectedRemote)) {
            SecurityOracle.failSecurity(
                    "ClientSourceIpResolver.xff",
                    seed,
                    "resolved IP equals XFF when trust is off",
                    java.util.Map.of("resolved", resolved, "xff", xff));
        }
    }

    @Property(tries = 30)
    void stampedSourceIpUsedWhenAllowHeaderEnabled(
            @ForAll("ips") String stamped,
            @ForAll("remotes") String remote) {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class, Mockito.RETURNS_DEEP_STUBS);
        when(config.ctf().cloudTrailAllowSourceIpHeader()).thenReturn(true);
        when(config.auth().trustForwardedHeaders()).thenReturn(false);

        String resolved = ClientSourceIpResolver.resolve(config, stamped, "9.9.9.9", remote);
        String expected = normalizeExpected(stamped.trim());
        if (!expected.equals(resolved)) {
            SecurityOracle.failSecurity(
                    "ClientSourceIpResolver.stamped",
                    stamped,
                    "stamped source IP header was not preferred",
                    java.util.Map.of("resolved", String.valueOf(resolved)));
        }
    }

    @Property(tries = 40)
    void operatorCredentialEnvHelpersNeverThrow(
            @ForAll @StringLength(max = 20) String keySuffix) throws Exception {
        String seed = keySuffix;
        CrashWatchdog.run("OperatorCredentialEnv", seed, 2000, () -> {
            SecurityOracle.runCatching("OperatorCredentialEnv", seed, () -> {
                Map<String, String> env = new HashMap<>();
                OperatorCredentialEnv.putIfPresent(env);
                List<String> list = new ArrayList<>();
                OperatorCredentialEnv.addIfPresent(list);
                OperatorCredentialEnv.snapshot();
                return null;
            });
            return null;
        });
    }

    @Property(tries = 40)
    void normalizePathNeverThrows(@ForAll @StringLength(max = 200) String path) {
        SecurityOracle.runCatching("AccountAndIp.normalizePath", path, () ->
                SecurityBypassPaths.normalizePath(path));
    }

    private static String normalizeExpected(String ip) {
        if ("::1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
            return "127.0.0.1";
        }
        return ip;
    }

    @Provide
    Arbitrary<String> ips() {
        return Arbitraries.of("203.0.113.10", "198.51.100.7", "8.8.8.8", "::1");
    }

    @Provide
    Arbitrary<String> remotes() {
        return Arbitraries.of("10.0.0.1", "192.168.1.50", "172.16.0.9", "::1");
    }
}