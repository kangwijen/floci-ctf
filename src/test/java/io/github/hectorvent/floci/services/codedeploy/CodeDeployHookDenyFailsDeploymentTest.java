package io.github.hectorvent.floci.services.codedeploy;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.codedeploy.model.Deployment;
import io.github.hectorvent.floci.services.ec2.Ec2Service;
import io.github.hectorvent.floci.services.ecs.EcsService;
import io.github.hectorvent.floci.services.elbv2.ElbV2Service;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.ssm.SsmCommandService;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;

/**
 * O16: CodeDeploy lifecycle hook AccessDenied must not complete the hook as Succeeded.
 */
@Tag("security-regression")
class CodeDeployHookDenyFailsDeploymentTest {

    private static final String REGION = "us-east-1";

    @Test
    void accessDeniedDoesNotCompleteHookAsSucceeded() throws Exception {
        InProcessTargetAuthorizer authorizer = mock(InProcessTargetAuthorizer.class);
        doThrow(new AwsException("AccessDeniedException",
                "User is not authorized to perform: lambda:InvokeFunction", 403))
                .when(authorizer).authorizeCodeDeployLambdaInvoke(anyString(), anyString());

        CodeDeployService service = new CodeDeployService(
                mock(LambdaService.class), mock(EcsService.class), mock(ElbV2Service.class),
                mock(SsmCommandService.class), mock(Ec2Service.class), new ObjectMapper(),
                new RegionResolver(REGION, "000000000000"), null, authorizer);

        Deployment deployment = new Deployment();
        deployment.setDeploymentId("d-HOOKDENY");
        Map<String, Object> lambdaTargetMap = new ConcurrentHashMap<>();
        lambdaTargetMap.put("lifecycleEvents", new CopyOnWriteArrayList<>());

        boolean ok = service.invokeHook(REGION, deployment, "hook-fn",
                "BeforeAllowTraffic", lambdaTargetMap, new AtomicBoolean());

        assertFalse(ok, "AccessDenied must fail the lifecycle hook");
        @SuppressWarnings("unchecked")
        List<Map<String, Object>> events =
                (List<Map<String, Object>>) lambdaTargetMap.get("lifecycleEvents");
        assertEquals(1, events.size());
        assertEquals("Failed", events.get(0).get("status"));
    }

    @Test
    void accessDeniedErrorCodeIsClassifiedAsHookFailure() {
        AwsException denied = new AwsException("AccessDeniedException", "denied", 403);
        assertEquals("Failed", CodeDeployService.resolveHookStatusAfterInvokeFailure(denied));

        AwsException plainDenied = new AwsException("AccessDenied", "denied", 403);
        assertEquals("Failed", CodeDeployService.resolveHookStatusAfterInvokeFailure(plainDenied));
    }
}
