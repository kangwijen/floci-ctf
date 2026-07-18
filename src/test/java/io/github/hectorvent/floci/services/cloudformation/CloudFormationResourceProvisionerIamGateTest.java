package io.github.hectorvent.floci.services.cloudformation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.cloudformation.model.StackResource;
import io.github.hectorvent.floci.services.cloudformation.provisioners.CloudFormationResourceRegistry;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.iam.model.AccessKey;
import io.github.hectorvent.floci.services.iam.model.IamPolicy;
import io.github.hectorvent.floci.services.iam.model.IamRole;
import io.github.hectorvent.floci.services.iam.model.IamUser;
import io.github.hectorvent.floci.services.iam.model.InstanceProfile;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

import java.util.List;
import java.util.Map;
import java.util.function.Function;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifies that privileged IAM create and attach APIs inside CloudFormation stacks (role, user,
 * access key, policy, instance profile, AttachRolePolicy) are gated behind
 * {@link InProcessIamAuthorizer} with {@code aws:CalledVia=cloudformation.amazonaws.com}.
 * CloudFormation provisioning runs on a background executor thread that bypasses the JAX-RS
 * {@code IamEnforcementFilter} entirely, so without this gate any caller able to create a stack
 * could mint arbitrary IAM principals and attach managed policies regardless of their own
 * permissions.
 */
@Tag("security-regression")
class CloudFormationResourceProvisionerIamGateTest {

    private static final String ACCOUNT_ID = "000000000000";
    private static final String REGION = "us-east-1";

    private final ObjectMapper mapper = new ObjectMapper();
    private IamService iamService;
    private InProcessIamAuthorizer iamAuthorizer;
    private CloudFormationResourceProvisioner provisioner;

    @BeforeEach
    void setUp() {
        iamService = mock(IamService.class);
        iamAuthorizer = mock(InProcessIamAuthorizer.class);
        provisioner = new CloudFormationResourceProvisioner(
                null, null, null, null, null, iamService, null, null, null, null,
                null, null, null, null, null, null,
                mapper,
                null, null, null, null, null, null, null,
                null, null, null, null, null, null, null,
                new CloudFormationResourceRegistry(List.of()),
                null, iamAuthorizer);
    }

    private CloudFormationTemplateEngine engine() {
        return new CloudFormationTemplateEngine(ACCOUNT_ID, REGION, "my-stack",
                "stack/id", Map.of(), Map.of(), Map.of(), Map.of(), Map.of(), mapper,
                (Function<String, String>) name -> null);
    }

    private JsonNode props(String json) {
        try {
            return mapper.readTree(json);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private StackResource provision(String logicalId, String type, String json) {
        return provisioner.provision(logicalId, type, props(json), engine(),
                REGION, ACCOUNT_ID, "my-stack");
    }

    private static void denyNextIamCreate(InProcessIamAuthorizer iamAuthorizer, String action) {
        doThrow(new AwsException("AccessDeniedException", "denied", 403))
                .when(iamAuthorizer).authorizeCallerAction(
                        eq(action), anyString(), anyString(), eq("iam"), anyMap());
    }

    private static void verifyCfnIamGate(InProcessIamAuthorizer iamAuthorizer, String action,
                                         String resourceArn) {
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Map<String, String>> conditions = ArgumentCaptor.forClass(Map.class);
        verify(iamAuthorizer).authorizeCallerAction(
                eq(action), eq(resourceArn), eq(REGION), eq("iam"), conditions.capture());
        assertEquals(CfnIamConditionContext.CLOUDFORMATION_SERVICE_PRINCIPAL,
                conditions.getValue().get("aws:calledvia"));
    }

    // ── AWS::IAM::Role ───────────────────────────────────────────────────────

    @Test
    void deniesRoleCreationWhenCallerLacksCreateRole() {
        denyNextIamCreate(iamAuthorizer, "iam:CreateRole");

        StackResource r = provision("Role1", "AWS::IAM::Role", """
                {"RoleName":"my-role","AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[]}}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).createRole(any(), any(), any(), any(), anyInt(), anyMap());
    }

    @Test
    void allowsRoleCreationWhenCallerHasCreateRole() {
        IamRole role = mock(IamRole.class);
        when(role.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":role/my-role");
        when(role.getRoleId()).thenReturn("AROA123");
        when(iamService.createRole(eq("my-role"), any(), any(), any(), anyInt(), anyMap())).thenReturn(role);

        StackResource r = provision("Role1", "AWS::IAM::Role", """
                {"RoleName":"my-role","AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[]}}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:CreateRole",
                "arn:aws:iam::" + ACCOUNT_ID + ":role/my-role");
        verify(iamService).createRole(eq("my-role"), any(), any(), any(), anyInt(), anyMap());
    }

    @Test
    void deniesManagedPolicyAttachWhenCallerLacksAttachRolePolicy() {
        IamRole role = mock(IamRole.class);
        when(role.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":role/my-role");
        when(role.getRoleId()).thenReturn("AROA123");
        when(iamService.createRole(eq("my-role"), any(), any(), any(), anyInt(), anyMap())).thenReturn(role);
        denyNextIamCreate(iamAuthorizer, "iam:AttachRolePolicy");

        StackResource r = provision("Role1", "AWS::IAM::Role", """
                {"RoleName":"my-role",
                 "AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[]},
                 "ManagedPolicyArns":["arn:aws:iam::aws:policy/ReadOnlyAccess"]}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).attachRolePolicy(anyString(), anyString());
    }

    @Test
    void authorizesAttachRolePolicyBeforeManagedPolicyArnsAttach() {
        IamRole role = mock(IamRole.class);
        when(role.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":role/my-role");
        when(role.getRoleId()).thenReturn("AROA123");
        when(iamService.createRole(eq("my-role"), any(), any(), any(), anyInt(), anyMap())).thenReturn(role);

        StackResource r = provision("Role1", "AWS::IAM::Role", """
                {"RoleName":"my-role",
                 "AssumeRolePolicyDocument":{"Version":"2012-10-17","Statement":[]},
                 "ManagedPolicyArns":["arn:aws:iam::aws:policy/ReadOnlyAccess"]}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:AttachRolePolicy",
                "arn:aws:iam::aws:policy/ReadOnlyAccess");
        verify(iamService).attachRolePolicy("my-role", "arn:aws:iam::aws:policy/ReadOnlyAccess");
    }

    @Test
    void deniesPolicyRolesAttachWhenCallerLacksAttachRolePolicy() {
        IamPolicy policy = mock(IamPolicy.class);
        when(policy.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":policy/my-policy");
        when(iamService.createPolicy(eq("my-policy"), any(), isNull(), any(), anyMap())).thenReturn(policy);
        denyNextIamCreate(iamAuthorizer, "iam:AttachRolePolicy");

        StackResource r = provision("Policy1", "AWS::IAM::Policy", """
                {"PolicyName":"my-policy",
                 "PolicyDocument":{"Version":"2012-10-17","Statement":[]},
                 "Roles":["target-role"]}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).attachRolePolicy(anyString(), anyString());
    }

    // ── AWS::IAM::User ───────────────────────────────────────────────────────

    @Test
    void deniesUserCreationWhenCallerLacksCreateUser() {
        denyNextIamCreate(iamAuthorizer, "iam:CreateUser");

        StackResource r = provision("User1", "AWS::IAM::User", """
                {"UserName":"my-user"}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).createUser(any(), any());
    }

    @Test
    void allowsUserCreationWhenCallerHasCreateUser() {
        IamUser user = mock(IamUser.class);
        when(user.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":user/my-user");
        when(iamService.createUser(eq("my-user"), any())).thenReturn(user);

        StackResource r = provision("User1", "AWS::IAM::User", """
                {"UserName":"my-user"}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:CreateUser",
                "arn:aws:iam::" + ACCOUNT_ID + ":user/my-user");
        verify(iamService).createUser(eq("my-user"), any());
    }

    // ── AWS::IAM::AccessKey ──────────────────────────────────────────────────

    @Test
    void deniesAccessKeyCreationWhenCallerLacksCreateAccessKey() {
        denyNextIamCreate(iamAuthorizer, "iam:CreateAccessKey");

        StackResource r = provision("Key1", "AWS::IAM::AccessKey", """
                {"UserName":"existing-user"}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).createAccessKey(any());
    }

    @Test
    void allowsAccessKeyCreationWhenCallerHasCreateAccessKey() {
        AccessKey key = mock(AccessKey.class);
        when(key.getAccessKeyId()).thenReturn("AKIAGENERATED");
        when(key.getSecretAccessKey()).thenReturn("secret");
        when(iamService.createAccessKey("existing-user")).thenReturn(key);

        StackResource r = provision("Key1", "AWS::IAM::AccessKey", """
                {"UserName":"existing-user"}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:CreateAccessKey",
                "arn:aws:iam::" + ACCOUNT_ID + ":user/existing-user");
        verify(iamService).createAccessKey("existing-user");
    }

    // ── AWS::IAM::Policy / AWS::IAM::ManagedPolicy ──────────────────────────

    @Test
    void deniesPolicyCreationWhenCallerLacksCreatePolicy() {
        denyNextIamCreate(iamAuthorizer, "iam:CreatePolicy");

        StackResource r = provision("Policy1", "AWS::IAM::Policy", """
                {"PolicyName":"my-policy","PolicyDocument":{"Version":"2012-10-17","Statement":[]}}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).createPolicy(any(), any(), any(), any(), anyMap());
    }

    @Test
    void allowsPolicyCreationWhenCallerHasCreatePolicy() {
        IamPolicy policy = mock(IamPolicy.class);
        when(policy.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":policy/my-policy");
        when(iamService.createPolicy(eq("my-policy"), any(), isNull(), any(), anyMap())).thenReturn(policy);

        StackResource r = provision("Policy1", "AWS::IAM::Policy", """
                {"PolicyName":"my-policy","PolicyDocument":{"Version":"2012-10-17","Statement":[]}}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:CreatePolicy",
                "arn:aws:iam::" + ACCOUNT_ID + ":policy/my-policy");
        verify(iamService).createPolicy(eq("my-policy"), any(), isNull(), any(), anyMap());
    }

    // ── AWS::IAM::InstanceProfile ────────────────────────────────────────────

    @Test
    void deniesInstanceProfileCreationWhenCallerLacksCreateInstanceProfile() {
        denyNextIamCreate(iamAuthorizer, "iam:CreateInstanceProfile");

        StackResource r = provision("Profile1", "AWS::IAM::InstanceProfile", """
                {"InstanceProfileName":"my-profile"}""");

        assertEquals("CREATE_FAILED", r.getStatus());
        verify(iamService, never()).createInstanceProfile(any(), any());
    }

    @Test
    void allowsInstanceProfileCreationWhenCallerHasCreateInstanceProfile() {
        InstanceProfile profile = mock(InstanceProfile.class);
        when(profile.getArn()).thenReturn("arn:aws:iam::" + ACCOUNT_ID + ":instance-profile/my-profile");
        when(iamService.createInstanceProfile(eq("my-profile"), any())).thenReturn(profile);

        StackResource r = provision("Profile1", "AWS::IAM::InstanceProfile", """
                {"InstanceProfileName":"my-profile"}""");

        assertEquals("CREATE_COMPLETE", r.getStatus());
        verifyCfnIamGate(iamAuthorizer, "iam:CreateInstanceProfile",
                "arn:aws:iam::" + ACCOUNT_ID + ":instance-profile/my-profile");
        verify(iamService).createInstanceProfile(eq("my-profile"), any());
    }
}
