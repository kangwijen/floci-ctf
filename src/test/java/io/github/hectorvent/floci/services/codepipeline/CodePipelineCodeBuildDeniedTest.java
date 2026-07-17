package io.github.hectorvent.floci.services.codepipeline;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.codebuild.CodeBuildService;
import io.github.hectorvent.floci.services.codedeploy.CodeDeployService;
import io.github.hectorvent.floci.services.codepipeline.model.CodePipelineExecution;
import io.github.hectorvent.floci.services.codepipeline.model.CodePipelinePipeline;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.s3.S3Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;

import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;

/**
 * O13: CodePipeline CodeBuild actions must authorize with the pipeline role before StartBuild.
 */
@Tag("security-regression")
@ExtendWith(MockitoExtension.class)
class CodePipelineCodeBuildDeniedTest {

    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/pipeline-role";
    private static final String REGION = "us-east-1";

    @Mock StorageFactory storageFactory;
    @Mock CodeBuildService codeBuildService;
    @Mock CodeDeployService codeDeployService;
    @Mock LambdaService lambdaService;
    @Mock S3Service s3Service;
    @Mock InProcessTargetAuthorizer targetAuthorizer;

    private final ObjectMapper mapper = new ObjectMapper();
    private CodePipelineService service;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        AccountAwareStorageBackend backend = mock(AccountAwareStorageBackend.class);
        lenient().doReturn(backend).when(storageFactory).create(anyString(), anyString(), any());
        service = new CodePipelineService(storageFactory, mapper, codeBuildService, codeDeployService,
                lambdaService, s3Service, targetAuthorizer);
    }

    @Test
    void codeBuildActionDeniedWhenPipelineRoleLacksStartBuild() throws Exception {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(targetAuthorizer).authorizeCodePipelineCodeBuild(
                        eq(ROLE_ARN), eq("secret-project"), eq(REGION), eq("000000000000"));

        CodePipelinePipeline pipeline = pipelineWithRole();
        CodePipelineExecution execution = new CodePipelineExecution();
        execution.setRegion(REGION);
        execution.setAccountId("000000000000");
        ObjectNode action = mapper.createObjectNode();
        action.putObject("configuration").put("ProjectName", "secret-project");
        action.putObject("actionTypeId")
                .put("category", "Build")
                .put("owner", "AWS")
                .put("provider", "CodeBuild")
                .put("version", "1");
        action.put("name", "Build");
        CodePipelineExecution.ActionExecution state = new CodePipelineExecution.ActionExecution();
        state.setCategory("Build");
        state.setOwner("AWS");
        state.setProvider("CodeBuild");
        state.setActionName("Build");

        Method method = CodePipelineService.class.getDeclaredMethod(
                "executeProvider", CodePipelinePipeline.class, CodePipelineExecution.class,
                com.fasterxml.jackson.databind.JsonNode.class, CodePipelineExecution.ActionExecution.class);
        method.setAccessible(true);

        assertThrows(AwsException.class, () -> {
            try {
                method.invoke(service, pipeline, execution, action, state);
            } catch (InvocationTargetException e) {
                if (e.getCause() instanceof Exception ex) {
                    throw ex;
                }
                throw e;
            }
        });

        verify(codeBuildService, never()).startBuild(anyString(), anyString(), anyString(),
                any(), any(), any(), any(), any(), any(), any());
    }

    private CodePipelinePipeline pipelineWithRole() {
        CodePipelinePipeline pipeline = new CodePipelinePipeline();
        ObjectNode declaration = mapper.createObjectNode();
        declaration.put("roleArn", ROLE_ARN);
        pipeline.setDeclaration(declaration);
        return pipeline;
    }
}
