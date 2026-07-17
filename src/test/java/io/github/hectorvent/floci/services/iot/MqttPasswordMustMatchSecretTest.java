package io.github.hectorvent.floci.services.iot;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.vertx.core.Vertx;
import jakarta.enterprise.inject.Instance;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O15: MQTT CONNECT with an IAM access key ID must verify the password against the
 * stored secret access key. Wrong or missing secrets fail closed.
 */
@Tag("security-regression")
class MqttPasswordMustMatchSecretTest {

    private static final String REGION = "us-east-1";
    private static final String AKID = "AKIAUSERKEY0001";
    private static final String SECRET = "correct-secret-access-key";
    private static final String POLICY = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Action":"iot:Subscribe","Resource":"*"}
            ]}""";

    private EmulatorConfig.AuthConfig authConfig;
    private IamService iamService;
    private IotService iotService;
    private IotMqttBrokerService service;

    @BeforeEach
    void setUp() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        authConfig = mock(EmulatorConfig.AuthConfig.class);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.of("AKIAROOTACCESSKEY"));
        when(authConfig.rootSecretAccessKey()).thenReturn(Optional.of("root-secret-access-key"));
        when(authConfig.resolveRootSecretAccessKey()).thenReturn(Optional.of("root-secret-access-key"));

        iamService = mock(IamService.class);
        iotService = mock(IotService.class);
        @SuppressWarnings("unchecked")
        Instance<IotService> iotServiceInstance = mock(Instance.class);
        when(iotServiceInstance.get()).thenReturn(iotService);

        RegionResolver regionResolver = mock(RegionResolver.class);
        when(regionResolver.getDefaultRegion()).thenReturn(REGION);

        service = new IotMqttBrokerService(config, mock(Vertx.class), iotServiceInstance, iamService,
                new IamPolicyEvaluator(new ObjectMapper()), regionResolver);

        when(iamService.resolveCallerContext(AKID)).thenReturn(CallerContext.of(List.of(POLICY)));
        when(iamService.findSecretKey(AKID)).thenReturn(Optional.of(SECRET));
        when(iotService.describeCertificate(AKID, REGION))
                .thenThrow(new RuntimeException("ResourceNotFoundException"));
    }

    @Test
    void wrongPasswordDoesNotResolveIamPrincipal() {
        assertNull(service.resolvePrincipal(AKID, "wrong-password"));
    }

    @Test
    void missingStoredSecretDoesNotResolveIamPrincipal() {
        when(iamService.findSecretKey(AKID)).thenReturn(Optional.empty());

        assertNull(service.resolvePrincipal(AKID, SECRET));
    }

    @Test
    void matchingSecretResolvesScopedIamPrincipal() {
        var principal = service.resolvePrincipal(AKID, SECRET);

        assertNotNull(principal);
        assertFalse(principal.unrestricted());
        assertTrue(principal.isAuthorized(new IamPolicyEvaluator(new ObjectMapper()),
                "iot:Subscribe", "arn:aws:iot:us-east-1:000000000000:topicfilter/x"));
    }

    @Test
    void rootAccessKeyRequiresMatchingRootSecret() {
        assertNull(service.resolvePrincipal("AKIAROOTACCESSKEY", "any-password"));
        assertNull(service.resolvePrincipal("AKIAROOTACCESSKEY", ""));

        var principal = service.resolvePrincipal("AKIAROOTACCESSKEY", "root-secret-access-key");
        assertNotNull(principal);
        assertTrue(principal.unrestricted());
    }
}
