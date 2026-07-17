package io.github.hectorvent.floci.services.iot;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iot.model.IotCertificate;
import io.github.hectorvent.floci.services.iot.model.IotPolicy;
import jakarta.enterprise.inject.Instance;
import io.vertx.core.Vertx;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Unit tests for {@link IotMqttBrokerService#resolvePrincipal} and
 * {@link IotMqttBrokerService.ConnectPrincipal}, covering the CTF-safe credential resolution
 * (root / IAM access key / active IoT certificate) and the resulting authorization decisions.
 */
class IotMqttBrokerServiceTest {

    private static final String REGION = "us-east-1";

    private EmulatorConfig config;
    private EmulatorConfig.AuthConfig authConfig;
    private IamService iamService;
    private IotService iotService;
    private IotMqttBrokerService service;

    private IotMqttBrokerService newService() {
        config = mock(EmulatorConfig.class);
        authConfig = mock(EmulatorConfig.AuthConfig.class);
        when(config.auth()).thenReturn(authConfig);
        when(authConfig.rootAccessKeyId()).thenReturn(Optional.of("AKIAROOTACCESSKEY"));

        iamService = mock(IamService.class);
        iotService = mock(IotService.class);
        @SuppressWarnings("unchecked")
        Instance<IotService> iotServiceInstance = mock(Instance.class);
        when(iotServiceInstance.get()).thenReturn(iotService);

        IamPolicyEvaluator policyEvaluator = new IamPolicyEvaluator(new ObjectMapper());
        RegionResolver regionResolver = mock(RegionResolver.class);
        when(regionResolver.getDefaultRegion()).thenReturn(REGION);

        Vertx vertx = mock(Vertx.class);

        return new IotMqttBrokerService(config, vertx, iotServiceInstance, iamService, policyEvaluator,
                regionResolver);
    }

    // ── resolvePrincipal ─────────────────────────────────────────────────────

    @Test
    void resolvePrincipalReturnsNullForBlankUsername() {
        service = newService();
        assertNull(service.resolvePrincipal(null, "pw"));
        assertNull(service.resolvePrincipal("", "pw"));
        assertNull(service.resolvePrincipal("   ", "pw"));
    }

    @Test
    void resolvePrincipalGrantsUnrestrictedAccessForRootAccessKey() {
        service = newService();
        var principal = service.resolvePrincipal("AKIAROOTACCESSKEY", "any-password");
        assertTrue(principal.unrestricted());
        assertTrue(principal.isAuthorized(new IamPolicyEvaluator(new ObjectMapper()),
                "iot:Subscribe", "arn:aws:iot:us-east-1:000000000000:topicfilter/anything"));
    }

    @Test
    void resolvePrincipalGrantsUnrestrictedAccessForRootEvenWithBlankPassword() {
        // Root is the operator credential — CONNECT still requires SOME password field
        // upstream via SigV4, but resolvePrincipal itself does not gate root on password.
        service = newService();
        var principal = service.resolvePrincipal("AKIAROOTACCESSKEY", "");
        assertTrue(principal.unrestricted());
    }

    @Test
    void resolvePrincipalResolvesIamAccessKeyWithNonBlankPassword() {
        service = newService();
        when(iamService.resolveCallerContext("AKIAUSERKEY")).thenReturn(
                CallerContext.of(List.of("""
                        {"Version":"2012-10-17","Statement":[
                          {"Effect":"Allow","Action":"iot:Subscribe","Resource":"*"}
                        ]}""")));

        var principal = service.resolvePrincipal("AKIAUSERKEY", "s3cr3t");

        assertFalse(principal.unrestricted());
        assertEquals(1, principal.policyDocuments().size());
    }

    @Test
    void resolvePrincipalRejectsIamAccessKeyWithBlankPassword() {
        // A bare, non-blank username used to be treated as authenticated. Real IAM access-key
        // auth requires a non-blank password field before the identity lookup even happens.
        service = newService();
        when(iotService.describeCertificate("AKIAUSERKEY", REGION))
                .thenThrow(new RuntimeException("ResourceNotFoundException"));

        var principal = service.resolvePrincipal("AKIAUSERKEY", "");

        // Falls through to certificate resolution, which also fails for this identifier.
        assertNull(principal);
        Mockito.verify(iamService, Mockito.never()).resolveCallerContext(Mockito.anyString());
    }

    @Test
    void resolvePrincipalResolvesActiveCertificateById() {
        service = newService();
        IotCertificate cert = new IotCertificate();
        cert.setCertificateId("cert-123");
        cert.setCertificateArn("arn:aws:iot:us-east-1:000000000000:cert/cert-123");
        cert.setStatus("ACTIVE");
        when(iotService.describeCertificate("cert-123", REGION)).thenReturn(cert);

        IotPolicy policy = new IotPolicy();
        policy.setPolicyName("device-policy");
        policy.setPolicyDocument("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"iot:Publish","Resource":"*"}
                ]}""");
        when(iotService.listAttachedPolicies("arn:aws:iot:us-east-1:000000000000:cert/cert-123", REGION))
                .thenReturn(List.of(policy));

        var principal = service.resolvePrincipal("cert-123", null);

        assertFalse(principal.unrestricted());
        assertEquals(1, principal.policyDocuments().size());
    }

    @Test
    void resolvePrincipalResolvesActiveCertificateByArn() {
        service = newService();
        String certArn = "arn:aws:iot:us-east-1:000000000000:cert/cert-abc";
        IotCertificate cert = new IotCertificate();
        cert.setCertificateId("cert-abc");
        cert.setCertificateArn(certArn);
        cert.setStatus("ACTIVE");
        when(iotService.describeCertificate("cert-abc", REGION)).thenReturn(cert);
        when(iotService.listAttachedPolicies(certArn, REGION)).thenReturn(List.of());

        var principal = service.resolvePrincipal(certArn, null);

        assertFalse(principal.unrestricted());
        assertTrue(principal.policyDocuments().isEmpty());
    }

    @Test
    void resolvePrincipalRejectsInactiveCertificate() {
        service = newService();
        IotCertificate cert = new IotCertificate();
        cert.setCertificateId("cert-inactive");
        cert.setCertificateArn("arn:aws:iot:us-east-1:000000000000:cert/cert-inactive");
        cert.setStatus("INACTIVE");
        when(iotService.describeCertificate("cert-inactive", REGION)).thenReturn(cert);

        assertNull(service.resolvePrincipal("cert-inactive", null));
    }

    @Test
    void resolvePrincipalRejectsUnknownIdentifier() {
        service = newService();
        when(iotService.describeCertificate("does-not-exist", REGION))
                .thenThrow(new RuntimeException("ResourceNotFoundException"));

        assertNull(service.resolvePrincipal("does-not-exist", null));
    }

    // ── ConnectPrincipal authorization ──────────────────────────────────────

    @Test
    void connectPrincipalUnrestrictedAllowsAnyAction() {
        var evaluator = new IamPolicyEvaluator(new ObjectMapper());
        var principal = IotMqttBrokerService.ConnectPrincipal.unrestricted("root:test");

        assertTrue(principal.isAuthorized(evaluator, "iot:Publish", "arn:aws:iot:us-east-1:000000000000:topic/anything"));
    }

    @Test
    void connectPrincipalScopedDeniesWhenNoPolicyMatches() {
        var evaluator = new IamPolicyEvaluator(new ObjectMapper());
        var principal = IotMqttBrokerService.ConnectPrincipal.scoped("cert:test", List.of("""
                {"Version":"2012-10-17","Statement":[
                  {"Effect":"Allow","Action":"iot:Subscribe",
                   "Resource":"arn:aws:iot:us-east-1:000000000000:topicfilter/allowed"}
                ]}"""));

        assertTrue(principal.isAuthorized(evaluator, "iot:Subscribe",
                "arn:aws:iot:us-east-1:000000000000:topicfilter/allowed"));
        assertFalse(principal.isAuthorized(evaluator, "iot:Subscribe",
                "arn:aws:iot:us-east-1:000000000000:topicfilter/secret"));
        assertFalse(principal.isAuthorized(evaluator, "iot:Publish",
                "arn:aws:iot:us-east-1:000000000000:topic/allowed"));
    }

    @Test
    void connectPrincipalScopedWithNullPolicyDocumentsTreatedAsEmpty() {
        var principal = IotMqttBrokerService.ConnectPrincipal.scoped("cert:test", null);
        assertTrue(principal.policyDocuments().isEmpty());
    }
}
