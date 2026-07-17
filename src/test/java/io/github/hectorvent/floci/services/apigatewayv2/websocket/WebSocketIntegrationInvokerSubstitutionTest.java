package io.github.hectorvent.floci.services.apigatewayv2.websocket;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.OutboundUrlGuard;
import io.github.hectorvent.floci.services.apigateway.AwsServiceRouter;
import io.github.hectorvent.floci.services.apigateway.VtlTemplateEngine;
import io.github.hectorvent.floci.services.apigatewayv2.model.Integration;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Collections;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;

/**
 * Unit tests for stage variable substitution in WebSocketIntegrationInvoker.
 */
class WebSocketIntegrationInvokerSubstitutionTest {

    private WebSocketIntegrationInvoker invoker;

    @BeforeEach
    void setUp() {
        invoker = new WebSocketIntegrationInvoker(
                mock(LambdaService.class),
                mock(AwsServiceRouter.class),
                new ObjectMapper(),
                mock(VtlTemplateEngine.class),
                mock(InProcessTargetAuthorizer.class),
                new OutboundUrlGuard(false, List.of(), false));
    }

    @Test
    void substituteStageVariables_singleVariable() {
        // substitute stage variable reference with corresponding value
        String uri = "arn:aws:lambda:us-east-1:123456789:function:${stageVariables.functionName}/invocations";
        Map<String, String> vars = Map.of("functionName", "myHandler");

        String result = invoker.substituteStageVariables(uri, vars);

        assertEquals("arn:aws:lambda:us-east-1:123456789:function:myHandler/invocations", result);
    }

    @Test
    void substituteStageVariables_undefinedVariableReplacedWithEmpty() {
        // undefined variable references replaced with empty string
        String uri = "arn:aws:lambda:us-east-1:123456789:function:${stageVariables.missingVar}/invocations";
        Map<String, String> vars = Map.of("otherVar", "value");

        String result = invoker.substituteStageVariables(uri, vars);

        assertEquals("arn:aws:lambda:us-east-1:123456789:function:/invocations", result);
    }

    @Test
    void substituteStageVariables_multipleReferences() {
        // multiple stage variable references in a single URI
        String uri = "arn:aws:lambda:${stageVariables.region}:${stageVariables.account}:function:${stageVariables.functionName}/invocations";
        Map<String, String> vars = Map.of(
                "region", "us-west-2",
                "account", "987654321",
                "functionName", "myFunc");

        String result = invoker.substituteStageVariables(uri, vars);

        assertEquals("arn:aws:lambda:us-west-2:987654321:function:myFunc/invocations", result);
    }

    @Test
    void substituteStageVariables_noReferences() {
        // URI without any stage variable references should be returned unchanged
        String uri = "arn:aws:lambda:us-east-1:123456789:function:myHandler/invocations";
        Map<String, String> vars = Map.of("functionName", "otherHandler");

        String result = invoker.substituteStageVariables(uri, vars);

        assertEquals("arn:aws:lambda:us-east-1:123456789:function:myHandler/invocations", result);
    }

    @Test
    void substituteStageVariables_nullUri() {
        String result = invoker.substituteStageVariables(null, Map.of("key", "value"));
        assertNull(result);
    }

    @Test
    void substituteStageVariables_nullStageVariables() {
        // Null stage variables map should treat all references as undefined (empty string)
        String uri = "arn:aws:lambda:us-east-1:123456789:function:${stageVariables.fn}/invocations";

        String result = invoker.substituteStageVariables(uri, null);

        assertEquals("arn:aws:lambda:us-east-1:123456789:function:/invocations", result);
    }

    @Test
    void substituteStageVariables_emptyStageVariables() {
        // Empty stage variables map should treat all references as undefined (empty string)
        String uri = "arn:aws:lambda:us-east-1:123456789:function:${stageVariables.fn}/invocations";

        String result = invoker.substituteStageVariables(uri, Collections.emptyMap());

        assertEquals("arn:aws:lambda:us-east-1:123456789:function:/invocations", result);
    }

    @Test
    void substituteStageVariables_mixedDefinedAndUndefined() {
        // Mix of defined and undefined variables
        String uri = "${stageVariables.prefix}-${stageVariables.missing}-${stageVariables.suffix}";
        Map<String, String> vars = Map.of("prefix", "hello", "suffix", "world");

        String result = invoker.substituteStageVariables(uri, vars);

        assertEquals("hello--world", result);
    }

    @Test
    @Tag("security-regression")
    void httpProxyRejectsPrivateHostAfterStageVariableSubstitution() {
        WebSocketIntegrationInvoker guarded = new WebSocketIntegrationInvoker(
                mock(LambdaService.class),
                mock(AwsServiceRouter.class),
                new ObjectMapper(),
                mock(VtlTemplateEngine.class),
                mock(InProcessTargetAuthorizer.class),
                new OutboundUrlGuard(true, List.of(), false));

        Integration integration = new Integration();
        integration.setIntegrationType("HTTP_PROXY");
        integration.setIntegrationUri("http://${stageVariables.target}/latest/meta-data");

        WebSocketIntegrationInvoker.IntegrationResult result = guarded.invoke(
                "us-east-1",
                integration,
                "{}",
                Map.of("target", "169.254.169.254"),
                Map.of(),
                Map.of(),
                null);

        assertEquals(502, result.statusCode());
        assertTrue(result.functionError() != null && result.functionError().contains("Bad Gateway"),
                result.functionError());
    }
}
