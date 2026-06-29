package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.quarkus.test.junit.QuarkusTest;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertNotEquals;

/**
 * Regression: API Gateway VTL must not allow ProcessBuilder reflection chains.
 */
@QuarkusTest
class VtlProcessBuilderSandboxTest {

    @Inject
    VtlTemplateEngine engine;

    @Inject
    ObjectMapper objectMapper;

    private VtlTemplateEngine.VtlContext minimalCtx() {
        return new VtlTemplateEngine.VtlContext(
                "{}",
                Map.of(),
                Map.of(),
                Map.of(),
                "prod",
                "GET",
                "/rce",
                "req-sandbox",
                "000000000000",
                Map.of()
        );
    }

    private static String pocPayload(String[] argv) {
        StringBuilder json = new StringBuilder("[");
        for (int i = 0; i < argv.length; i++) {
            if (i > 0) {
                json.append(",");
            }
            json.append("\"").append(argv[i].replace("\\", "\\\\").replace("\"", "\\\"")).append("\"");
        }
        json.append("]");
        String commandJson = json.toString();
        String escaped = commandJson.replace("\\", "\\\\").replace("'", "\\'");
        return "#set($pbClass=$util.getClass().forName('java.lang.ProcessBuilder'))\n"
                + "#set($listClass=$util.getClass().forName('java.util.List'))\n"
                + "#set($ctor=$pbClass.getConstructor($listClass))\n"
                + "#set($cmd=$util.parseJson('" + escaped + "'))\n"
                + "#set($pb=$ctor.newInstance($cmd))\n"
                + "#set($p=$pb.start())\n"
                + "#set($exit=$p.waitFor())\n"
                + "{\"ok\":true,\"exit\":\"$exit\"}";
    }

    @Test
    void processBuilderPayloadFromPoc_py_doesNotExecuteCommand() throws Exception {
        String template = pocPayload(new String[] { "/bin/true" });
        String body = engine.evaluate(template, minimalCtx()).body().trim();
        JsonNode node = objectMapper.readTree(body);
        assertNotEquals("0", node.path("exit").asText(), "ProcessBuilder must not run to completion");
    }
}
