package io.github.hectorvent.floci.services.codebuild;

import com.fasterxml.jackson.core.type.TypeReference;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageBackend;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.codebuild.model.Project;
import io.github.hectorvent.floci.services.codebuild.model.ProjectArtifacts;
import io.github.hectorvent.floci.services.codebuild.model.ProjectEnvironment;
import io.github.hectorvent.floci.services.codebuild.model.ProjectSource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.Mockito.mock;

/**
 * Regression: UpdateProject must reject a blank serviceRole so builds cannot
 * later fall back to operator AWS_* under IAM enforcement.
 */
class CodeBuildBlankServiceRoleIntegrationTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";
    private static final String SERVICE_ROLE = "arn:aws:iam::" + ACCOUNT + ":role/cb";

    private CodeBuildService service;

    @BeforeEach
    void setUp() {
        service = serviceWithStorage(new SharedStorageFactory());
    }

    @Test
    void updateProject_blankServiceRole_rejected() {
        service.createProject(REGION, ACCOUNT, "blank-role-proj", "demo",
                source("GITHUB"), null, null, artifacts("NO_ARTIFACTS"), null,
                new ProjectEnvironment(), SERVICE_ROLE,
                30, null, null, null, null, null, null);

        AwsException thrown = assertThrows(AwsException.class, () ->
                service.updateProject(REGION, "blank-role-proj", null, null, null, null, null, null,
                        null, "", null, null, null, null, null, null, null));
        assertEquals(400, thrown.getHttpStatus());
        assertEquals("InvalidInputException", thrown.getErrorCode());
        assertEquals("serviceRole is required", thrown.getMessage());

        AwsException whitespace = assertThrows(AwsException.class, () ->
                service.updateProject(REGION, "blank-role-proj", null, null, null, null, null, null,
                        null, "   ", null, null, null, null, null, null, null));
        assertEquals(400, whitespace.getHttpStatus());
        assertEquals("InvalidInputException", whitespace.getErrorCode());

        Project unchanged = service.batchGetProjects(REGION, List.of("blank-role-proj")).getFirst();
        assertEquals(SERVICE_ROLE, unchanged.getServiceRole());
    }

    private static ProjectSource source(String type) {
        ProjectSource s = new ProjectSource();
        s.setType(type);
        return s;
    }

    private static ProjectArtifacts artifacts(String type) {
        ProjectArtifacts a = new ProjectArtifacts();
        a.setType(type);
        return a;
    }

    private static CodeBuildService serviceWithStorage(StorageFactory storage) {
        CodeBuildService codeBuildService = new CodeBuildService(
                mock(CodeBuildRunner.class), mock(EmulatorConfig.class), storage);
        codeBuildService.initializeStorage();
        return codeBuildService;
    }

    private static final class SharedStorageFactory extends StorageFactory {
        private final Map<String, StorageBackend<String, ?>> stores = new HashMap<>();

        private SharedStorageFactory() {
            super(null, null);
        }

        @Override
        @SuppressWarnings("unchecked")
        public <V> StorageBackend<String, V> create(String serviceName,
                                                    String fileName,
                                                    TypeReference<Map<String, V>> typeReference) {
            return (StorageBackend<String, V>) stores.computeIfAbsent(fileName, ignored -> new InMemoryStorage<>());
        }
    }
}
