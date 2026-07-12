package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.AlphaChars;
import net.jqwik.api.constraints.StringLength;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicBoolean;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * In-process delivery authorizer properties.
 */
class InProcessAuthorizerFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String ROLE = "arn:aws:iam::" + ACCOUNT + ":role/exec";

    @Property(tries = 40)
    void pipeSourceWithRoleDelegatesToIam(@ForAll("sourceArns") String sourceArn) {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        AtomicBoolean called = new AtomicBoolean(false);
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeWithResource(anyString(), anyString(), anyString(), anyString(), anyString());

        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        authorizer.authorizePipeSource(ROLE, sourceArn, REGION);
        if (!called.get()) {
            SecurityOracle.failSecurity(
                    "InProcessTargetAuthorizer.pipeSource",
                    sourceArn,
                    "pipe source with role did not invoke IAM authorizer",
                    java.util.Map.of());
        }
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

    @Property(tries = 30)
    void lambdaEsmPollDelegatesForSqs(
            @ForAll @AlphaChars @StringLength(min = 3, max = 20) String queue) {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        List<String> actions = new ArrayList<>();
        doAnswer(inv -> {
            actions.add(inv.getArgument(2));
            return null;
        }).when(iam).authorizeWithResource(anyString(), anyString(), anyString(), anyString(), anyString());

        String queueArn = "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":" + queue;
        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        authorizer.authorizeLambdaEventSourcePoll(ROLE, queueArn, REGION);
        if (!actions.contains("ReceiveMessage")) {
            SecurityOracle.failSecurity(
                    "InProcessTargetAuthorizer.esm",
                    queueArn,
                    "Lambda ESM SQS poll missing ReceiveMessage authorization",
                    java.util.Map.of("actions", actions.toString()));
        }
    }

    @Property(tries = 20)
    void snsLambdaDeliveryUsesServicePrincipal() {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        AtomicBoolean called = new AtomicBoolean(false);
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeServicePrincipal(
                anyString(), anyString(), anyString(), anyString(), anyString());

        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        String fnArn = "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:fn";
        authorizer.authorizeSnsDelivery(fnArn, "lambda", REGION);
        if (!called.get()) {
            SecurityOracle.failSecurity(
                    "InProcessTargetAuthorizer.sns",
                    fnArn,
                    "SNS lambda delivery did not authorize service principal",
                    java.util.Map.of());
        }
    }

    @Property(tries = 20)
    void logsFirehoseWithoutRoleDeniesWhenEnforcementOn() {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        String firehoseArn = "arn:aws:firehose:" + REGION + ":" + ACCOUNT + ":deliverystream/s";
        try {
            authorizer.authorizeLogsSubscription(null, firehoseArn, REGION);
            SecurityOracle.failSecurity(
                    "InProcessTargetAuthorizer.logs",
                    firehoseArn,
                    "logs Firehose subscription without role did not deny",
                    java.util.Map.of());
        } catch (AwsException expected) {
            // Correct fail-closed behavior.
        }
    }

    @Property(tries = 20)
    void cloudTrailS3PutDelegates(@ForAll @AlphaChars @StringLength(min = 3, max = 20) String bucket) {
        InProcessIamAuthorizer iam = Mockito.mock(InProcessIamAuthorizer.class);
        EmulatorConfig config = mockConfig(true);
        AtomicBoolean called = new AtomicBoolean(false);
        doAnswer(inv -> {
            called.set(true);
            return null;
        }).when(iam).authorizeServicePrincipal(
                anyString(), anyString(), anyString(), anyString(), anyString(),
                any(), any(), any());

        InProcessTargetAuthorizer authorizer = new InProcessTargetAuthorizer(iam, config);
        authorizer.authorizeServiceS3Put(
                InProcessTargetAuthorizer.CLOUDTRAIL_SERVICE, bucket, "AWSLogs/x", REGION);
        if (!called.get()) {
            // CloudTrail also calls GetBucketAcl with 5-arg overload.
            Mockito.verify(iam, Mockito.atLeastOnce()).authorizeServicePrincipal(
                    anyString(), anyString(), anyString(), anyString(), anyString());
        }
    }

    private static EmulatorConfig mockConfig(boolean enforcement) {
        EmulatorConfig config = Mockito.mock(EmulatorConfig.class, Mockito.RETURNS_DEEP_STUBS);
        when(config.services().iam().enforcementEnabled()).thenReturn(enforcement);
        when(config.defaultAccountId()).thenReturn(ACCOUNT);
        return config;
    }

    @Provide
    Arbitrary<String> sourceArns() {
        return Arbitraries.of(
                "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":example-queue",
                "arn:aws:kinesis:" + REGION + ":" + ACCOUNT + ":stream/example",
                "arn:aws:dynamodb:" + REGION + ":" + ACCOUNT + ":table/t/stream/2024-01-01");
    }
}
