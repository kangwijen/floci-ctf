package io.github.hectorvent.floci.services.lambda;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.services.iam.ComputePassRoleGate;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.zip.CodeStore;
import io.github.hectorvent.floci.services.lambda.zip.ZipExtractor;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * O3: Lambda CreateFunction / UpdateFunctionConfiguration must require iam:PassRole on Role.
 */
@Tag("security-regression")
class LambdaCreateFunctionPassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/lambda-exec";

    @TempDir
    Path tempDir;

    private ComputePassRoleGate passRoleGate;
    private LambdaService service;

    @BeforeEach
    void setUp() {
        passRoleGate = mock(ComputePassRoleGate.class);
        LambdaFunctionStore store = new LambdaFunctionStore(new InMemoryStorage<>());
        WarmPool warmPool = new WarmPool();
        CodeStore codeStore = new CodeStore(tempDir.resolve("code"));
        service = new LambdaService(store, warmPool, codeStore, new ZipExtractor(),
                null, new RegionResolver(REGION, "000000000000"), null, passRoleGate);
    }

    @Test
    void createFunctionRequiresPassRole() {
        Map<String, Object> request = baseCreateRequest("passrole-fn");
        service.createFunction(REGION, request);
        verify(passRoleGate).authorizeLambdaExecutionRole(ROLE_ARN, REGION);
    }

    @Test
    void createFunctionDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeLambdaExecutionRole(eq(ROLE_ARN), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createFunction(REGION, baseCreateRequest("denied-fn")));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void updateFunctionConfigurationRequiresPassRoleOnRoleChange() {
        service.createFunction(REGION, baseCreateRequest("update-role-fn"));
        String newRole = "arn:aws:iam::000000000000:role/lambda-exec-2";

        Map<String, Object> update = new HashMap<>();
        update.put("Role", newRole);
        service.updateFunctionConfiguration(REGION, "update-role-fn", update);

        verify(passRoleGate).authorizeLambdaExecutionRole(newRole, REGION);
    }

    @Test
    void updateFunctionConfigurationDeniesWhenPassRoleDenied() {
        LambdaFunction created = service.createFunction(REGION, baseCreateRequest("update-deny-fn"));
        String newRole = "arn:aws:iam::000000000000:role/lambda-exec-2";
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(passRoleGate).authorizeLambdaExecutionRole(eq(newRole), eq(REGION));

        Map<String, Object> update = new HashMap<>();
        update.put("Role", newRole);
        AwsException ex = assertThrows(AwsException.class,
                () -> service.updateFunctionConfiguration(REGION, created.getFunctionName(), update));
        assertEquals("AccessDeniedException", ex.getErrorCode());
        assertEquals(ROLE_ARN, service.getFunction(REGION, "update-deny-fn").getRole());
    }

    private static Map<String, Object> baseCreateRequest(String name) {
        Map<String, Object> request = new HashMap<>();
        request.put("FunctionName", name);
        request.put("Role", ROLE_ARN);
        request.put("Handler", "index.handler");
        request.put("Runtime", "python3.12");
        return request;
    }
}
