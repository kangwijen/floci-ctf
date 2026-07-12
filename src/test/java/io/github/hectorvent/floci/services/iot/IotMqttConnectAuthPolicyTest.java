package io.github.hectorvent.floci.services.iot;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class IotMqttConnectAuthPolicyTest {

    @Test
    void enforcementOffAllowsAnonymousConnect() {
        assertTrue(IotMqttBrokerService.allowMqttConnect(false, null));
        assertTrue(IotMqttBrokerService.allowMqttConnect(false, ""));
        assertTrue(IotMqttBrokerService.allowMqttConnect(false, "   "));
    }

    @Test
    void enforcementOnRejectsBlankUsername() {
        assertFalse(IotMqttBrokerService.allowMqttConnect(true, null));
        assertFalse(IotMqttBrokerService.allowMqttConnect(true, ""));
        assertFalse(IotMqttBrokerService.allowMqttConnect(true, "   "));
    }

    @Test
    void enforcementOnAllowsUsernamePresent() {
        assertTrue(IotMqttBrokerService.allowMqttConnect(true, "participant"));
        assertTrue(IotMqttBrokerService.allowMqttConnect(true, "x"));
    }
}
