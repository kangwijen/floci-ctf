package io.github.hectorvent.floci.services.firehose;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.storage.InMemoryStorage;
import io.github.hectorvent.floci.core.storage.StorageFactory;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.firehose.model.DeliveryStreamDescription.S3Destination;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.s3.S3Service;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

/**
 * E-FO-09: delivery stream roleArn create/update requires iam:PassRole.
 */
@Tag("security-regression")
class FirehoseDeliveryRolePassRoleTest {

    private static final String REGION = "us-east-1";
    private static final String ROLE_ARN = "arn:aws:iam::000000000000:role/firehose-role";

    private InProcessIamAuthorizer iamAuthorizer;
    private FirehoseService service;

    @BeforeEach
    @SuppressWarnings({"unchecked", "rawtypes"})
    void setUp() {
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        StorageFactory storageFactory = mock(StorageFactory.class);
        doReturn(new InMemoryStorage<>()).when(storageFactory).create(anyString(), anyString(), any());
        service = new FirehoseService(storageFactory, mock(S3Service.class),
                new RegionResolver(REGION, "000000000000"),
                mock(InProcessCloudTrailRecorder.class),
                mock(InProcessTargetAuthorizer.class),
                iamAuthorizer);
    }

    @Test
    void createDeliveryStreamRequiresPassRole() {
        service.createDeliveryStream("passrole-stream", ROLE_ARN, null, List.of(), null);
        verify(iamAuthorizer).authorizePassRole(ROLE_ARN, "firehose.amazonaws.com", REGION);
    }

    @Test
    void createDeliveryStreamDeniesWhenPassRoleDenied() {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizePassRole(eq(ROLE_ARN), eq("firehose.amazonaws.com"), eq(REGION));

        AwsException ex = assertThrows(AwsException.class,
                () -> service.createDeliveryStream("denied-stream", ROLE_ARN, null, List.of(), null));
        assertEquals("AccessDeniedException", ex.getErrorCode());
    }

    @Test
    void updateDestinationRequiresPassRoleOnRoleChange() {
        service.createDeliveryStream("upd-stream", ROLE_ARN, new S3Destination(), List.of(), null);
        var stream = service.describeDeliveryStream("upd-stream");
        String destId = stream.getDestinations().get(0).getDestinationId();
        String newRole = "arn:aws:iam::000000000000:role/firehose-role-2";
        S3Destination update = new S3Destination();
        update.setRoleArn(newRole);
        service.updateDestination("upd-stream", stream.getVersionId(), destId, update);
        verify(iamAuthorizer).authorizePassRole(newRole, "firehose.amazonaws.com", REGION);
    }
}
