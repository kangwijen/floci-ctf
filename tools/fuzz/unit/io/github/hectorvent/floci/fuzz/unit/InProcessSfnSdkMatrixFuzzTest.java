package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.kms.KmsService;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.List;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.RETURNS_DEEP_STUBS;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * SFN {@code aws-sdk} and optimized task integrations: in-process IAM must deny blank roles
 * and roles with empty identity policies when enforcement is on.
 *
 * <p>Credential scopes mirror {@link io.github.hectorvent.floci.services.stepfunctions.AslExecutor}.
 */
class InProcessSfnSdkMatrixFuzzTest {

    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "123456789012";
    private static final String FAKE_ROLE = "arn:aws:iam::" + ACCOUNT + ":role/sfn-fuzz-exec";

    @Property(tries = 60)
    void blankRoleArnDeniesAcrossSfnSdkMatrix(
            @ForAll("sfnSdkTasks") SfnSdkTask task,
            @ForAll("blankRoleArns") String roleArn) throws Exception {
        InProcessIamAuthorizer authorizer = authorizerEnforcementOn();
        ObjectNode body = sampleBody(task);
        CrashWatchdog.run("InProcessSfnSdk.blankRole", task.seed(roleArn), 2000, () -> {
            SecurityOracle.runCatching("InProcessSfnSdk.blankRole", task.seed(roleArn), () -> {
                try {
                    authorizer.authorize(roleArn, task.scope(), task.action(), body, REGION);
                    SecurityOracle.failSecurity(
                            "InProcessSfnSdk.blankRole",
                            task.seed(roleArn),
                            "blank roleArn did not deny under enforcement",
                            java.util.Map.of(
                                    "scope", task.scope(),
                                    "action", task.action(),
                                    "roleArn", String.valueOf(roleArn)));
                } catch (AwsException e) {
                    expectAccessDenied(e, "InProcessSfnSdk.blankRole", task.seed(roleArn));
                }
                return null;
            });
            return null;
        });
    }

    @Property(tries = 50)
    void fakeRoleWithEmptyPoliciesDeniesAcrossSfnSdkMatrix(
            @ForAll("sfnSdkTasks") SfnSdkTask task) throws Exception {
        InProcessIamAuthorizer authorizer = authorizerWithDenyEvaluator();
        ObjectNode body = sampleBody(task);
        CrashWatchdog.run("InProcessSfnSdk.emptyPolicy", task.seed(FAKE_ROLE), 2000, () -> {
            SecurityOracle.runCatching("InProcessSfnSdk.emptyPolicy", task.seed(FAKE_ROLE), () -> {
                try {
                    authorizer.authorize(FAKE_ROLE, task.scope(), task.action(), body, REGION);
                    SecurityOracle.failSecurity(
                            "InProcessSfnSdk.emptyPolicy",
                            task.seed(FAKE_ROLE),
                            "role with empty policies did not deny",
                            java.util.Map.of(
                                    "scope", task.scope(),
                                    "action", task.action()));
                } catch (AwsException e) {
                    expectAccessDenied(e, "InProcessSfnSdk.emptyPolicy", task.seed(FAKE_ROLE));
                }
                return null;
            });
            return null;
        });
    }

    @Property(tries = 30)
    void authorizeNeverThrowsError(
            @ForAll("sfnSdkTasks") SfnSdkTask task,
            @ForAll @StringLength(max = 80) String roleNoise) throws Exception {
        InProcessIamAuthorizer authorizer = authorizerWithDenyEvaluator();
        String roleArn = roleNoise.isBlank()
                ? null
                : "arn:aws:iam::" + ACCOUNT + ":role/" + roleNoise.replaceAll("[^a-zA-Z0-9/_+=,.@-]", "");
        ObjectNode body = sampleBody(task);
        CrashWatchdog.run("InProcessSfnSdk.noError", task.seed(roleNoise), 2000, () -> {
            SecurityOracle.runCatching("InProcessSfnSdk.noError", task.seed(roleNoise), () -> {
                try {
                    authorizer.authorize(roleArn, task.scope(), task.action(), body, REGION);
                } catch (AwsException ignored) {
                    // deny is expected for most seeds
                }
                return null;
            });
            return null;
        });
    }

    private static void expectAccessDenied(AwsException e, String target, String seed) {
        if (!"AccessDeniedException".equals(e.getErrorCode())) {
            SecurityOracle.failSecurity(
                    target,
                    seed,
                    "expected AccessDeniedException, got " + e.getErrorCode(),
                    java.util.Map.of("message", String.valueOf(e.getMessage())));
        }
    }

    private static ObjectNode sampleBody(SfnSdkTask task) {
        ObjectNode body = MAPPER.createObjectNode();
        switch (task.scope()) {
            case "lambda" -> body.put("FunctionName", "fuzz-fn");
            case "dynamodb" -> body.put("TableName", "fuzz-table");
            case "sqs" -> body.put("QueueUrl", "http://localhost:4566/000000000000/fuzz-queue");
            case "secretsmanager" -> body.put("SecretId", "fuzz/secret");
            case "kms" -> body.put("KeyId", "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/fuzz-key");
            case "s3" -> {
                body.put("Bucket", "fuzz-bucket");
                body.put("Key", "object.txt");
            }
            case "states" -> body.put("StateMachineArn",
                    "arn:aws:states:" + REGION + ":" + ACCOUNT + ":stateMachine:child");
            case "ecs" -> body.put("TaskDefinition", "fuzz-task:1");
            case "cloudformation" -> body.put("StackName", "fuzz-stack");
            case "ec2" -> body.putObject("RegionNames").put("member", "us-east-1");
            default -> body.put("fuzz", task.action());
        }
        return body;
    }

    private static InProcessIamAuthorizer authorizerEnforcementOn() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        return new InProcessIamAuthorizer(
                config,
                mock(IamService.class),
                mock(IamPolicyEvaluator.class),
                FuzzFixtures.resourceArnBuilder(),
                mock(ResourcePolicyResolver.class),
                mock(RegionResolver.class),
                mock(KmsService.class));
    }

    private static InProcessIamAuthorizer authorizerWithDenyEvaluator() {
        EmulatorConfig config = mock(EmulatorConfig.class, RETURNS_DEEP_STUBS);
        when(config.services().iam().enforcementEnabled()).thenReturn(true);
        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContextFromRoleArn(FAKE_ROLE))
                .thenReturn(CallerContext.of(List.of()));
        IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
        when(evaluator.evaluate(any(), any(), any(), any(), any()))
                .thenReturn(IamPolicyEvaluator.Decision.DENY);
        ResourceArnBuilder arnBuilder = mock(ResourceArnBuilder.class);
        when(arnBuilder.buildFromJsonBody(any(), any(), eq(REGION), eq(ACCOUNT)))
                .thenReturn("*");
        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(any(), any(), eq(REGION))).thenReturn(List.of());
        KmsService kmsService = mock(KmsService.class);
        when(kmsService.isGrantAuthorized(any(), any(), any(), any(), any())).thenReturn(false);
        return new InProcessIamAuthorizer(
                config,
                iamService,
                evaluator,
                arnBuilder,
                resourcePolicyResolver,
                mock(RegionResolver.class),
                kmsService);
    }

    @Provide
    Arbitrary<String> blankRoleArns() {
        return Arbitraries.of(null, "", "   ", "\t", "\n", "  \t\n  ");
    }

    @Provide
    Arbitrary<SfnSdkTask> sfnSdkTasks() {
        return Arbitraries.of(
                new SfnSdkTask("lambda", "InvokeFunction"),
                new SfnSdkTask("dynamodb", "putItem"),
                new SfnSdkTask("dynamodb", "GetItem"),
                new SfnSdkTask("dynamodb", "updateItem"),
                new SfnSdkTask("dynamodb", "deleteItem"),
                new SfnSdkTask("sqs", "SendMessage"),
                new SfnSdkTask("secretsmanager", "GetSecretValue"),
                new SfnSdkTask("kms", "Decrypt"),
                new SfnSdkTask("s3", "PutObject"),
                new SfnSdkTask("s3", "GetObject"),
                new SfnSdkTask("states", "StartExecution"),
                new SfnSdkTask("ecs", "RunTask"),
                new SfnSdkTask("cloudformation", "DescribeStacks"),
                new SfnSdkTask("ec2", "DescribeRegions"));
    }

    private record SfnSdkTask(String scope, String action) {
        String seed(String roleArn) {
            return scope + ":" + action + ":" + String.valueOf(roleArn);
        }
    }
}
