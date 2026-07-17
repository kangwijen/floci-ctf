package io.github.hectorvent.floci.services.apigatewayv2.websocket;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.apigateway.ExecuteAuthzGate;
import io.github.hectorvent.floci.services.apigatewayv2.ApiGatewayV2Service;
import io.github.hectorvent.floci.services.apigatewayv2.model.Api;
import io.github.hectorvent.floci.services.apigatewayv2.model.Route;
import io.github.hectorvent.floci.services.apigatewayv2.model.Stage;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.vertx.core.MultiMap;
import io.vertx.core.http.HttpServerRequest;
import io.vertx.core.http.HttpServerResponse;
import io.vertx.core.net.SocketAddress;
import io.vertx.ext.web.RoutingContext;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.util.Collections;

import static org.junit.jupiter.api.Assertions.fail;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * WebSocket $connect CUSTOM authorizer dispatch must agree with
 * {@link ExecuteAuthzGate#classify}: {@code custom} / {@code Custom} must enter the
 * CUSTOM fail-closed path (missing authorizerId → 403), not silent-allow.
 */
@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
@Tag("security-regression")
class WebSocketCustomAuthorizerCaseSensitivityTest {

    @Mock ApiGatewayV2Service apiGatewayV2Service;
    @Mock WebSocketConnectionManager connectionManager;
    @Mock RouteSelectionEvaluator routeSelectionEvaluator;
    @Mock WebSocketProxyEventBuilder proxyEventBuilder;
    @Mock WebSocketIntegrationInvoker integrationInvoker;
    @Mock WebSocketAuthorizerService authorizerService;
    @Mock RegionResolver regionResolver;
    @Mock io.vertx.core.Vertx vertx;
    @Mock EmulatorConfig config;
    @Mock EmulatorConfig.ServicesConfig servicesConfig;
    @Mock EmulatorConfig.IamServiceConfig iamConfig;
    @Mock EmulatorConfig.AuthConfig authConfig;
    @Mock AccountResolver accountResolver;
    @Mock IamService iamService;
    @Mock InProcessIamAuthorizer iamAuthorizer;
    @Mock RoutingContext ctx;
    @Mock HttpServerRequest request;
    @Mock HttpServerResponse response;
    @Mock SocketAddress remoteAddress;

    private WebSocketHandler handler;

    @BeforeEach
    void setUp() {
        when(config.services()).thenReturn(servicesConfig);
        when(servicesConfig.iam()).thenReturn(iamConfig);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(false);
        when(iamConfig.enforcementEnabled()).thenReturn(false);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.validateSignatures()).thenReturn(false);
        when(regionResolver.getDefaultRegion()).thenReturn("us-east-1");

        handler = new WebSocketHandler(
                apiGatewayV2Service, connectionManager, routeSelectionEvaluator,
                proxyEventBuilder, integrationInvoker, authorizerService,
                regionResolver, new ObjectMapper(), vertx, config,
                accountResolver, iamService, iamAuthorizer, new ExecuteAuthzGate());
    }

    @ParameterizedTest
    @ValueSource(strings = {"custom", "Custom", "CUSTOM", "CuStOm"})
    void connectCustomMissingAuthorizerIdFailsClosedRegardlessOfCase(String authType) throws Exception {
        String apiId = "wsapi1";
        String stageName = "test";

        Api api = new Api();
        api.setApiId(apiId);
        api.setProtocolType("WEBSOCKET");

        Stage stage = new Stage();
        stage.setStageName(stageName);
        stage.setStageVariables(Collections.emptyMap());

        Route connectRoute = new Route();
        connectRoute.setRouteKey("$connect");
        connectRoute.setTarget("integrations/int-1");
        connectRoute.setAuthorizationType(authType);
        connectRoute.setAuthorizerId(null);

        when(ctx.request()).thenReturn(request);
        when(request.path()).thenReturn("/ws/" + apiId + "/" + stageName);
        when(request.getHeader("Authorization")).thenReturn(null);
        when(request.getHeader("User-Agent")).thenReturn("test-agent");
        when(request.remoteAddress()).thenReturn(remoteAddress);
        when(remoteAddress.host()).thenReturn("127.0.0.1");
        when(request.headers()).thenReturn(MultiMap.caseInsensitiveMultiMap());
        when(request.params()).thenReturn(MultiMap.caseInsensitiveMultiMap());
        when(ctx.response()).thenReturn(response);
        when(response.setStatusCode(403)).thenReturn(response);

        when(apiGatewayV2Service.getApi("us-east-1", apiId)).thenReturn(api);
        when(apiGatewayV2Service.getStage("us-east-1", apiId, stageName)).thenReturn(stage);
        when(apiGatewayV2Service.findRouteByKey("us-east-1", apiId, "$connect")).thenReturn(connectRoute);

        Method handleUpgrade = WebSocketHandler.class.getDeclaredMethod(
                "handleWebSocketUpgrade", RoutingContext.class);
        handleUpgrade.setAccessible(true);
        try {
            handleUpgrade.invoke(handler, ctx);
        } catch (InvocationTargetException e) {
            fail("authType=" + authType + " silent-allowed into $connect integration path: "
                    + e.getCause());
        }

        verify(response).setStatusCode(403);
        verify(response).end();
        verify(apiGatewayV2Service, never()).getIntegration(anyString(), anyString(), anyString());
    }
}
