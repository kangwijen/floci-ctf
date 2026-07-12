package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.services.iot.IotMqttBrokerService;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.StringLength;

/**
 * MQTT CONNECT policy oracle for {@link IotMqttBrokerService#allowMqttConnect}.
 */
class MqttConnectAuthFuzzTest {

    @Property(tries = 40)
    void enforcementOnRejectsBlankUsername(
            @ForAll @StringLength(max = 120) String username) throws Exception {
        if (username != null && !username.isBlank()) {
            return;
        }
        String seed = repr(username);
        boolean allowed = CrashWatchdog.run("IotMqttBrokerService.allowMqttConnect.blank", seed, 1000, () ->
                SecurityOracle.runCatching("IotMqttBrokerService.allowMqttConnect.blank", seed,
                        () -> IotMqttBrokerService.allowMqttConnect(true, username)));
        if (allowed) {
            SecurityOracle.failSecurity(
                    "IotMqttBrokerService.allowMqttConnect",
                    seed,
                    "blank username CONNECT allowed under IAM enforcement",
                    java.util.Map.of("enforcement", "true"));
        }
    }

    @Property(tries = 40)
    void enforcementOffAllowsAnonymous(@ForAll @StringLength(max = 120) String username) throws Exception {
        String seed = repr(username);
        boolean allowed = CrashWatchdog.run("IotMqttBrokerService.allowMqttConnect.off", seed, 1000, () ->
                SecurityOracle.runCatching("IotMqttBrokerService.allowMqttConnect.off", seed,
                        () -> IotMqttBrokerService.allowMqttConnect(false, username)));
        if (!allowed) {
            SecurityOracle.failSecurity(
                    "IotMqttBrokerService.allowMqttConnect",
                    seed,
                    "CONNECT denied when IAM enforcement is off",
                    java.util.Map.of("enforcement", "false"));
        }
    }

    @Property(tries = 80)
    void extremeClientIdAndUsernameNeverThrowsError(
            @ForAll @StringLength(max = 400) String clientId,
            @ForAll @StringLength(max = 400) String username) throws Exception {
        String seed = clientId + "|" + username;
        CrashWatchdog.run("IotMqttBrokerService.allowMqttConnect.crash", seed, 1000, () -> {
            SecurityOracle.runCatching("IotMqttBrokerService.allowMqttConnect.crash", seed, () -> {
                IotMqttBrokerService.allowMqttConnect(true, username);
                IotMqttBrokerService.allowMqttConnect(false, username);
                return Boolean.TRUE;
            });
            return null;
        });
    }

    private static String repr(String value) {
        if (value == null) {
            return "null";
        }
        if (value.isEmpty()) {
            return "<empty>";
        }
        return value.replace("\n", "\\n").replace("\t", "\\t");
    }
}
