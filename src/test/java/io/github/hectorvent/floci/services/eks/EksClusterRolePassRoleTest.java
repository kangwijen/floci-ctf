package io.github.hectorvent.floci.services.eks;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.eks.model.CreateClusterRequest;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

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
 * E-FO-10: EKS CreateCluster RoleArn requires iam:PassRole (covers CFN AWS::EKS::Cluster arm).
 */
@Tag("security-regression")
class EksClusterRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/eks-cluster";

    private InProcessIamAuthorizer iamAuthorizer;
    private EksService service;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        doReturn(new InMemoryStorage<>()).when(storageFactory).create(anyString(), anyString(), any());
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.defaultRegion()).thenReturn(REGION);
        when(config.services().eks().mock()).thenReturn(true);
        when(config.services().eks().apiServerBasePort()).thenReturn(6443);
        service = new EksService(storageFactory, config,
                new RegionResolver(REGION, "000000000000"),
                mock(EksClusterManager.class), iamAuthorizer);
    }

    @Test
    void createClusterRequiresPassRole() {
        CreateClusterRequest request = new CreateClusterRequest();
        request.setName("passrole-cluster");
        request.setRoleArn(ROLE_ARN);
        service.createCluster(request);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "eks.amazonaws.com", REGION);
    }

    @Test
    void createClusterDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("eks.amazonaws.com"), eq(REGION));

        CreateClusterRequest request = new CreateClusterRequest();
        request.setName("denied-cluster");
        request.setRoleArn(ROLE_ARN);

        AwsException ex = assertThrows(AwsException.class, () -> service.createCluster(request));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }
}
