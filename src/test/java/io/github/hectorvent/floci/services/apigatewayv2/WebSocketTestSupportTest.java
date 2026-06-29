package io.github.hectorvent.floci.services.apigatewayv2;

import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;

class WebSocketTestSupportTest {

    @Test
    void buildWsUrlUsesLocalhostWhenHostIsWildcard() throws Exception {
        URI base = new URI("http://0.0.0.0:4566/");
        assertEquals("ws://127.0.0.1:4566/ws/api123/prod",
                WebSocketTestSupport.buildWsUrl(base, "api123", "prod"));
    }

    @Test
    void buildWsUrlJoinsPathWithoutTrailingSlash() throws Exception {
        URI base = new URI("http://localhost:8081");
        assertEquals("ws://localhost:8081/ws/api123/prod",
                WebSocketTestSupport.buildWsUrl(base, "api123", "prod"));
    }
}
