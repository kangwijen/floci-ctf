package io.github.hectorvent.floci.services.backup;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.backup.model.BackupPlan;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * E-FO-19: backup selection/job IamRoleArn requires iam:PassRole.
 */
@Tag("security-regression")
class BackupIamRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/backup-role";

    private InProcessIamAuthorizer iamAuthorizer;
    private BackupService service;
    private String planId;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        doReturn(new InMemoryStorage<>()).when(storageFactory).create(anyString(), anyString(), any());
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().backup().jobCompletionDelaySeconds()).thenReturn(3600);
        service = new BackupService(storageFactory, config,
                new RegionResolver(REGION, "000000000000"), iamAuthorizer);
        service.createBackupVault("vault", null, null, null, REGION);
        BackupPlan plan = service.createBackupPlan("plan", List.of(), null, REGION);
        planId = plan.getBackupPlanId();
    }

    @Test
    void createBackupSelectionRequiresPassRole() {
        service.createBackupSelection(planId, "sel", ROLE_ARN, List.of(), List.of(), null);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "backup.amazonaws.com", REGION);
    }

    @Test
    void createBackupSelectionDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("backup.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createBackupSelection(planId, "denied", ROLE_ARN, List.of(), List.of(), null));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void startBackupJobRequiresPassRole() {
        service.startBackupJob("vault", "arn:aws:s3:::bucket", ROLE_ARN, null, REGION);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "backup.amazonaws.com", REGION);
    }
}
