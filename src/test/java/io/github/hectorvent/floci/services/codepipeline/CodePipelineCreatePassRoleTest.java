package io.github.hectorvent.floci.services.codepipeline;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.AccountAwareStorageBackend;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.codebuild.CodeBuildService;
import io.github.hectorvent.floci.services.codedeploy.CodeDeployService;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.s3.S3Service;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * E-FO-06: CreatePipeline / UpdatePipeline roleArn requires iam:PassRole.
 */
@Tag("security-regression")
class CodePipelineCreatePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/pipeline-role";

    private final ObjectMapper mapper = new ObjectMapper();
    private InProcessIamAuthorizer iamAuthorizer;
    private CodePipelineService service;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        lenient().doAnswer(inv -> new AccountAwareStorageBackend<>(
                        new InMemoryStorage<>(), mock(Instance.class), ACCOUNT))
                .when(storageFactory).create(anyString(), anyString(), any());
        service = new CodePipelineService(storageFactory, mapper,
                mock(CodeBuildService.class), mock(CodeDeployService.class),
                mock(LambdaService.class), mock(S3Service.class),
                mock(InProcessTargetAuthorizer.class), iamAuthorizer);
    }

    @Test
    void createPipelineRequiresPassRole() {
        service.handle("CreatePipeline", createRequest("passrole-pipe", ROLE_ARN), REGION, ACCOUNT);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "codepipeline.amazonaws.com", REGION);
    }

    @Test
    void createPipelineDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("codepipeline.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.handle("CreatePipeline", createRequest("denied-pipe", ROLE_ARN), REGION, ACCOUNT));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void updatePipelineRequiresPassRole() {
        service.handle("CreatePipeline", createRequest("update-pipe", ROLE_ARN), REGION, ACCOUNT);
        String newRole = "arn:aws:iam::000000000000:role/pipeline-role-2";
        service.handle("UpdatePipeline", createRequest("update-pipe", newRole), REGION, ACCOUNT);
        verify(iamAuthorizer).authorizePassRole(newRole, "codepipeline.amazonaws.com", REGION);
    }

    private ObjectNode createRequest(String name, String roleArn) {
        ObjectNode root = mapper.createObjectNode();
        ObjectNode pipeline = root.putObject("pipeline");
        pipeline.put("name", name);
        pipeline.put("roleArn", roleArn);
        ObjectNode artifactStore = pipeline.putObject("artifactStore");
        artifactStore.put("type", "S3");
        artifactStore.put("location", "bucket");
        ArrayNode stages = pipeline.putArray("stages");
        stages.add(stage("Source"));
        stages.add(stage("Build"));
        return root;
    }

    private ObjectNode stage(String name) {
        ObjectNode stage = mapper.createObjectNode();
        stage.put("name", name);
        ArrayNode actions = stage.putArray("actions");
        ObjectNode action = actions.addObject();
        action.put("name", name + "Action");
        action.putObject("actionTypeId")
                .put("category", "Source".equals(name) ? "Source" : "Build")
                .put("owner", "AWS")
                .put("provider", "S3")
                .put("version", "1");
        action.putObject("configuration").put("S3Bucket", "bucket").put("S3ObjectKey", "key");
        action.put("runOrder", 1);
        return stage;
    }
}
