package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.apigateway.model.MethodConfig;
import io.github.hectorvent.floci.services.apigatewayv2.ApiGatewayV2Service;
import io.github.hectorvent.floci.services.apigatewayv2.websocket.WebSocketConnectionManager;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.ws.rs.core.Response;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.Mockito.when;

/**
 * REST CUSTOM authorizer dispatch must agree with {@link ExecuteAuthzGate#classify}:
 * non-canonical casing such as {@code custom} / {@code Custom} must still enter the
 * CUSTOM fail-closed path (missing authorizerId → 403), not silent-allow.
 */
@ExtendWith(MockitoExtension.class)
@Tag("security-regression")
class CustomAuthorizerCaseSensitivityTest {

    @Mock ApiGatewayService apiGatewayService;
    @Mock ApiGatewayV2Service apiGatewayV2Service;
    @Mock LambdaService lambdaService;
    @Mock VtlTemplateEngine vtlEngine;
    @Mock AwsServiceRouter serviceRouter;
    @Mock WebSocketConnectionManager webSocketConnectionManager;
    @Mock ElbV2Service elbV2Service;
    @Mock InProcessTargetAuthorizer targetAuthorizer;
    @Mock EmulatorConfig config;
    @Mock EmulatorConfig.ServicesConfig servicesConfig;
    @Mock EmulatorConfig.IamServiceConfig iamConfig;

    private ApiGatewayExecuteController controller;

    @BeforeEach
    void setUp() {
        when(config.services()).thenReturn(servicesConfig);
        when(servicesConfig.iam()).thenReturn(iamConfig);
        when(iamConfig.strictEnforcementEnabled()).thenReturn(false);

        controller = new ApiGatewayExecuteController(
                apiGatewayService, apiGatewayV2Service, lambdaService,
                new RegionResolver("us-east-1", "000000000000"),
                new ObjectMapper(), vtlEngine, serviceRouter, webSocketConnectionManager, elbV2Service,
                targetAuthorizer, config, null, new ExecuteAuthzGate());
    }

    @ParameterizedTest
    @ValueSource(strings = {"custom", "Custom", "CUSTOM", "CuStOm"})
    void restCustomMissingAuthorizerIdFailsClosedRegardlessOfCase(String authType) throws Exception {
        MethodConfig method = new MethodConfig();
        method.setAuthorizationType(authType);
        method.setAuthorizerId(null);

        Method invokeAuthorizer = ApiGatewayExecuteController.class.getDeclaredMethod(
                "invokeAuthorizer",
                String.class, String.class, String.class, String.class, String.class, String.class,
                String.class,
                io.github.hectorvent.floci.services.apigateway.model.Stage.class,
                MethodConfig.class,
                jakarta.ws.rs.core.HttpHeaders.class,
                jakarta.ws.rs.core.UriInfo.class,
                String.class);
        invokeAuthorizer.setAccessible(true);

        Object result = invokeAuthorizer.invoke(
                controller,
                "us-east-1", "api1", "prod", "GET", "/secured", "/secured", "res-1",
                null, method, null, null, null);

        assertNotNull(result, "invokeAuthorizer must return an AuthorizerResult");
        Method errorResponseAccessor = result.getClass().getDeclaredMethod("errorResponse");
        Response errorResponse = (Response) errorResponseAccessor.invoke(result);
        assertNotNull(errorResponse,
                "authType=" + authType + " with missing authorizerId must not silent-allow");
        assertEquals(403, errorResponse.getStatus(),
                "authType=" + authType + " missing authorizerId must fail closed with 403");
    }
}
