package io.github.hectorvent.floci.services.sns;

import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

/**
 * E-FO-24: SNS HTTP(S) subscription delivery is egress-controlled ({@code OutboundUrlGuard}
 * pin-connect), not an InProcess IAM deputy edge. This regression locks that contract so
 * {@link InProcessTargetAuthorizer#authorizeSnsDelivery} stays a no-op for http/https.
 */
@Tag("security-regression")
class SnsHttpSubscriptionEgressOnlyContractTest {

    @Test
    void authorizeSnsDeliveryHttpDoesNotTouchIamAuthorizer() {
        var iamAuthorizer = mock(io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer.class);
        var config = mock(io.github.hectorvent.floci.config.EmulatorConfig.class);
        whenEnforcementOff(config);

        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iamAuthorizer, config);
        authorizer.authorizeSnsDelivery("https://example.com/hook", "https", "us-east-1",
                "arn:aws:sns:us-east-1:123456789012:topic");

        verifyNoInteractions(iamAuthorizer);
    }

    @Test
    void authorizeSnsDeliveryHttpBlankEndpointIsNoOp() {
        var iamAuthorizer = mock(io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer.class);
        var config = mock(io.github.hectorvent.floci.config.EmulatorConfig.class);
        whenEnforcementOff(config);

        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iamAuthorizer, config);
        authorizer.authorizeSnsDelivery("  ", "http", "us-east-1");

        verifyNoInteractions(iamAuthorizer);
    }

    private static void whenEnforcementOff(io.github.hectorvent.floci.config.EmulatorConfig config) {
        var services = mock(io.github.hectorvent.floci.config.EmulatorConfig.ServicesConfig.class);
        var iam = mock(io.github.hectorvent.floci.config.EmulatorConfig.IamServiceConfig.class);
        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
        when(iam.enforcementEnabled()).thenReturn(false);
        when(config.defaultAccountId()).thenReturn("123456789012");
    }
}
