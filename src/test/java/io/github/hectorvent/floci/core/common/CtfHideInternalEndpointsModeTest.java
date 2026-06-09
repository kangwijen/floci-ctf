package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class CtfHideInternalEndpointsModeTest {

    @ParameterizedTest
    @ValueSource(strings = {"false", "FALSE", " false ", ""})
    void parseFalse(String raw) {
        assertEquals(CtfHideInternalEndpointsMode.OFF, CtfHideInternalEndpointsMode.parse(raw));
    }

    @Test
    void parseTrue() {
        assertEquals(CtfHideInternalEndpointsMode.PREFIXED, CtfHideInternalEndpointsMode.parse("true"));
    }

    @Test
    void parseAll() {
        assertEquals(CtfHideInternalEndpointsMode.ALL, CtfHideInternalEndpointsMode.parse("all"));
    }

    @Test
    void parseInvalidThrows() {
        assertThrows(IllegalArgumentException.class, () -> CtfHideInternalEndpointsMode.parse("yes"));
    }

    @Test
    void prefixedHidesFlociAndLocalstackOnly() {
        CtfHideInternalEndpointsMode mode = CtfHideInternalEndpointsMode.PREFIXED;
        assertTrue(mode.isPathHidden("/_floci/health"));
        assertTrue(mode.isPathHidden("/_localstack/init"));
        assertTrue(mode.isPathHidden("/_floci/ecr/gc"));
        assertTrue(mode.isPathHidden("/_aws/sqs/messages"));
        assertFalse(mode.isPathHidden("/health"));
        assertFalse(mode.isPathHidden("health"));
        assertFalse(mode.isPathHidden("/"));
    }

    @Test
    void allAlsoHidesRootHealth() {
        CtfHideInternalEndpointsMode mode = CtfHideInternalEndpointsMode.ALL;
        assertTrue(mode.isPathHidden("/health"));
        assertTrue(mode.isPathHidden("health"));
        assertTrue(mode.isPathHidden("/_floci/info"));
    }
}
