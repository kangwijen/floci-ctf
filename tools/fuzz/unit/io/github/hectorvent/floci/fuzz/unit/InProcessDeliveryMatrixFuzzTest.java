package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.mockito.Mockito;

import java.util.concurrent.atomic.AtomicBoolean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Delivery-path matrix: each authorize* helper must consult the IAM authorizer when enforcement is on.
 */
class InProcessDeliveryMatrixFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String ROLE = "arn:aws:iam::" + ACCOUNT + ":role/exec";

    @Property(tries = 30)
    void s3ToSqsDelegatesToIam(@ForAll @AlphaChars @StringLength(min = 3, max = 16) String queue) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String queueArn = "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":" + queue;
        authorizer.authorizeS3ToSqs(queueArn, REGION);
        expectCalled(called, "authorizeS3ToSqs", queueArn);
    }

    @Property(tries = 30)
    void s3ToSnsDelegatesToIam(@ForAll @AlphaChars @StringLength(min = 3, max = 16) String topic) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String topicArn = "arn:aws:sns:" + REGION + ":" + ACCOUNT + ":" + topic;
        authorizer.authorizeS3ToSns(topicArn, REGION);
        expectCalled(called, "authorizeS3ToSns", topicArn);
    }

    @Property(tries = 30)
    void s3ToLambdaDelegatesToIam(@ForAll @AlphaChars @StringLength(min = 3, max = 16) String fn) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + fn;
        authorizer.authorizeS3ToLambda(fnArn, REGION);
        expectCalled(called, "authorizeS3ToLambda", fnArn);
    }

    @Property(tries = 30)
    void sesToSnsDelegatesToIam(@ForAll @AlphaChars @StringLength(min = 3, max = 16) String topic) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String topicArn = "arn:aws:sns:" + REGION + ":" + ACCOUNT + ":" + topic;
        authorizer.authorizeSesToSns(topicArn, REGION);
        expectCalled(called, "authorizeSesToSns", topicArn);
    }

    @Property(tries = 30)
    void elbLambdaTargetDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String fn) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + fn;
        authorizer.authorizeElbLambdaTarget(fnArn, REGION);
        expectCalled(called, "authorizeElbLambdaTarget", fnArn);
    }

    @Property(tries = 30)
    void apigwLambdaInvokeDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String fn) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + fn;
        authorizer.authorizeApigwLambdaInvoke(fnArn, REGION);
        expectCalled(called, "authorizeApigwLambdaInvoke", fnArn);
    }

    @Property(tries = 30)
    void cognitoLambdaInvokeDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String fn) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + fn;
        authorizer.authorizeCognitoLambdaInvoke(fnArn, REGION);
        expectCalled(called, "authorizeCognitoLambdaInvoke", fnArn);
    }

    @Property(tries = 30)
    void codeDeployLambdaInvokeDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String fn) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:" + fn;
        authorizer.authorizeCodeDeployLambdaInvoke(fnArn, REGION);
        expectCalled(called, "authorizeCodeDeployLambdaInvoke", fnArn);
    }

    @Property(tries = 30)
    void vpcFlowLogsS3PutDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String bucket) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        authorizer.authorizeVpcFlowLogsS3Put(bucket, "AWSLogs/x", REGION);
        expectCalled(called, "authorizeVpcFlowLogsS3Put", bucket);
    }

    @Property(tries = 30)
    void firehoseS3PutDelegatesToIam(
            @ForAll @AlphaChars @StringLength(min = 3, max = 16) String bucket) {
        AtomicBoolean called = new AtomicBoolean(false);
        InProcessTargetAuthorizer authorizer = authorizerTracking(called);
        authorizer.authorizeFirehoseS3Put(ROLE, bucket, "prefix/obj", REGION);
        expectCalled(called, "authorizeFirehoseS3Put", bucket);
    }

    @Property(tries = 30)
    void eventBridgeReplayIsNoOpAgainstIam() {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        String busArn = "arn:aws:events:" + REGION + ":" + ACCOUNT + ":event-bus/default";
        authorizer.authorizeEventBridgeReplay(busArn, REGION);
        Mockito.verifyNoInteractions(iam);
    }

    private static InProcessTargetAuthorizer authorizerTracking(AtomicBoolean called) {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeWithResource(anyString(), anyString(), anyString(), anyString(), anyString());
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeServicePrincipal(
                anyString(), anyString(), anyString(), anyString(), anyString());
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeServicePrincipal(
                anyString(), anyString(), anyString(), anyString(), anyString(), any());
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeServicePrincipal(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any());
        return new InProcessTargetAuthorizer(iam, config);
    }

    private static void expectCalled(AtomicBoolean called, String method, String seed) {
        if (!called.get()) {
            SecurityOracle.failSecurity(
                    "InProcessDeliveryMatrix." + method,
                    seed,
                    method + " did not invoke IAM authorizer",
                    java.util.Map.of());
        }
    }

    private static EmulatorConfig mockConfig(boolean enforcement) {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class, Mockito.RETURNS_DEEP_STUBS);
        when(config.services().iam().enforcementEnabled()).thenReturn(enforcement);
        when(config.defaultAccountId()).thenReturn(ACCOUNT);
        return config;
    }
}
