# IAM

**Protocol:** Query (XML) — `POST http://localhost:4566/` with `Action=` parameter

## Supported Actions

### Users
`CreateUser` · `GetUser` · `DeleteUser` · `ListUsers` · `UpdateUser` · `TagUser` · `UntagUser` · `ListUserTags`

### Groups
`CreateGroup` · `GetGroup` · `DeleteGroup` · `ListGroups` · `AddUserToGroup` · `RemoveUserFromGroup` · `ListGroupsForUser`

### Roles
`CreateRole` · `GetRole` · `DeleteRole` · `ListRoles` · `UpdateRole` · `UpdateAssumeRolePolicy` · `TagRole` · `UntagRole` · `ListRoleTags`

### Policies
`CreatePolicy` · `GetPolicy` · `DeletePolicy` · `ListPolicies` · `CreatePolicyVersion` · `GetPolicyVersion` · `DeletePolicyVersion` · `ListPolicyVersions` · `SetDefaultPolicyVersion` · `TagPolicy` · `UntagPolicy` · `ListPolicyTags`

### Permission Boundaries
`PutUserPermissionsBoundary` · `DeleteUserPermissionsBoundary` · `PutRolePermissionsBoundary` · `DeleteRolePermissionsBoundary`

### Policy Attachments
`AttachUserPolicy` · `DetachUserPolicy` · `ListAttachedUserPolicies`
`AttachGroupPolicy` · `DetachGroupPolicy` · `ListAttachedGroupPolicies`
`AttachRolePolicy` · `DetachRolePolicy` · `ListAttachedRolePolicies`

### Inline Policies
`PutUserPolicy` · `GetUserPolicy` · `DeleteUserPolicy` · `ListUserPolicies`
`PutGroupPolicy` · `GetGroupPolicy` · `DeleteGroupPolicy` · `ListGroupPolicies`
`PutRolePolicy` · `GetRolePolicy` · `DeleteRolePolicy` · `ListRolePolicies`

### Instance Profiles
`CreateInstanceProfile` · `GetInstanceProfile` · `DeleteInstanceProfile` · `ListInstanceProfiles` · `AddRoleToInstanceProfile` · `RemoveRoleFromInstanceProfile` · `ListInstanceProfilesForRole`

### Access Keys
`CreateAccessKey` · `GetAccessKeyLastUsed` · `ListAccessKeys` · `UpdateAccessKey` · `DeleteAccessKey`

### Login Profiles
`CreateLoginProfile` · `DeleteLoginProfile` · `UpdateLoginProfile`

## AWS Managed Policies

Floci seeds a catalog of commonly-used AWS managed policies at startup. These are attachable immediately without any setup:

**General access**
`AdministratorAccess` · `PowerUserAccess` · `ReadOnlyAccess` · `IAMFullAccess` · `AmazonS3FullAccess` · `AmazonS3ReadOnlyAccess` · `AmazonDynamoDBFullAccess` · `AmazonEC2FullAccess` · `AmazonSQSFullAccess` · `AmazonSNSFullAccess` · `AmazonVPCFullAccess` · `CloudWatchFullAccess` · `AWSLambdaFullAccess`

**Lambda execution roles** (`arn:aws:iam::aws:policy/service-role/...`)
`AWSLambdaBasicExecutionRole` · `AWSLambdaBasicDurableExecutionRolePolicy` · `AWSLambdaDynamoDBExecutionRole` · `AWSLambdaKinesisExecutionRole` · `AWSLambdaMSKExecutionRole` · `AWSLambdaSQSQueueExecutionRole` · `AWSLambdaVPCAccessExecutionRole`

**ECS / EKS execution roles**
`AmazonECSTaskExecutionRolePolicy` · `AmazonEKSFargatePodExecutionRolePolicy`

**EKS cluster & node groups**
`AmazonEKSClusterPolicy` · `AmazonEKSServicePolicy` · `AmazonEKSVPCResourceController` · `AmazonEKSWorkerNodePolicy` · `AmazonEKS_CNI_Policy`

**Other execution roles**
`AmazonS3ObjectLambdaExecutionRolePolicy` · `CloudWatchLambdaInsightsExecutionRolePolicy` · `CloudWatchLambdaApplicationSignalsExecutionRolePolicy` · `AWSConfigRulesExecutionRole` · `AWSMSKReplicatorExecutionRole` · `AWS-SSM-DiagnosisAutomation-ExecutionRolePolicy` · `AWS-SSM-RemediationAutomation-ExecutionRolePolicy` · `AmazonSageMakerGeospatialExecutionRole` · `AmazonSageMakerCanvasEMRServerlessExecutionRolePolicy` · `SageMakerStudioBedrockFunctionExecutionRolePolicy` · `SageMakerStudioDomainExecutionRolePolicy` · `SageMakerStudioQueryExecutionRolePolicy` · `AmazonDataZoneDomainExecutionRolePolicy` · `AmazonBedrockAgentCoreMemoryBedrockModelInferenceExecutionRolePolicy` · `AWSPartnerCentralSellingResourceSnapshotJobExecutionRolePolicy`

All seeded policies use a permissive wildcard document since Floci does not enforce IAM policy evaluation by default.

## IAM Enforcement Mode

By default Floci accepts any credentials without enforcing IAM policies — all requests are allowed through regardless of what policies are attached to the calling identity. This preserves backward compatibility and keeps the default setup frictionless.

Setting `enforcement-enabled: true` activates the policy evaluator as a JAX-RS request filter. Every inbound request is then evaluated against the identity-based policies of the calling IAM user or assumed role before it reaches the service handler.

### Enable enforcement

**Environment variable:**
```bash
FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true
```

Docker Compose:
```yaml
environment:
  FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED: "true"
```

### Evaluation rules

Policy evaluation follows the standard AWS precedence:

1. An explicit **Deny** in any policy → request is denied (HTTP 403 `AccessDeniedException`)
2. An explicit **Allow** in any policy → request is allowed
3. No matching statement → implicit deny (HTTP 403)

**AWS parity (policy-exempt actions):** AWS documents only two STS operations that do not require identity-based IAM permissions. Floci skips `IamPolicyEvaluator` for these when the access key is registered (SigV4 and strict-mode rules still apply). This applies globally on port 4566 for every emulated service: exemption is keyed on the resolved IAM action string, not per handler.

| IAM action | AWS documentation |
|---|---|
| `sts:GetCallerIdentity` | [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html): no permissions required; explicit Deny does not block the call |
| `sts:GetSessionToken` | [GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html): no permissions required; policies cannot control this authentication operation |

No other Floci-emulated service (S3, EC2, IAM, DynamoDB, Lambda, ...) has an AWS-documented equivalent. Calls such as `ec2:DescribeRegions`, `s3:ListAllMyBuckets`, or `iam:GetUser` still need an explicit Allow (or root bypass). Temporary credentials from `GetSessionToken` inherit the IAM user's permissions for subsequent calls.

Implementation: `IamUnrestrictedActions` in `core.common`, used by `IamEnforcementFilter` after `IamActionRegistry` resolves the action.

**GetCallerIdentity identity shape:** `StsQueryHandler` resolves the signing access key via `IamService.resolveCallerIdentity` (IAM user ARN, assumed-role ARN, federated user, configured root AKID, or 12-digit account id). It does not always return account `:root`.

**AssumeRole trust policies:** `AssumeRoleTrustPolicyEvaluator` checks role trust documents before credentials are issued, including `sts:ExternalId` conditions and `Principal.AWS` matching.

**Scoped resource ARNs:** `ResourceArnBuilder` maps each request to an AWS-shaped resource ARN for `IamPolicyEvaluator` (see [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)). Covered scopes include:

| Scope | Source fields (examples) |
|---|---|
| `iam` | `UserName`, `GroupName`, `RoleName`, `PolicyArn` (form) |
| `dynamodb` | `TableName`, `TableArn`, `GlobalTableName` (JSON) |
| `secretsmanager` | `SecretId` (JSON; friendly names get `-000000` suffix for `secret:name-*` patterns) |
| `s3` | Bucket/key from URL path |
| `lambda` | Function or layer name from path |
| `sqs` / `sns` | `QueueName` / `Name`, or ARN from `QueueUrl` / `TopicArn` |
| `kms` / `kinesis` | `KeyId`, `AliasName`, `StreamName`, `StreamARN` (JSON) |
| `ssm` | `Name` or first `Names[]` entry (JSON) |
| `sts` | `RoleArn` (form) |
| `ec2` | `InstanceId`, `ResourceId`, `VpcId`, `GroupId`, prefixed form keys |
| `cloudformation` | `StackName` (placeholder stack id for `stack/name/*` patterns) |
| `elasticache` / `rds` / `neptune` | Cluster/instance identifiers (query) |
| `email` / `ses` | Identity, template, configuration set (query) |
| `monitoring` | `AlarmName`, `ResourceARN` (query) |
| `elasticloadbalancing` | Load balancer / target group ARNs (query) |
| `autoscaling` | `AutoScalingGroupName` (query) |
| `logs` / `events` / `states` | `logGroupName`, `Rule`, `stateMachineArn`, ... (JSON) |
| `ecs` / `ecr` / `firehose` / `cognito-idp` | Cluster/service/repo/stream/pool fields (JSON) |
| `apigateway` / `execute-api` | REST API id from path |
| `glue` / `athena` / `es` | Database/table/workgroup/domain fields (JSON or path) |

When a specific resource cannot be determined, the builder returns a service-scoped wildcard (for example `table/*`) so broad `*` in policies still matches, but narrowly scoped ARNs do not.

**Resource-based policies:** `ResourcePolicyResolver` loads policy documents for **S3** (bucket policy), **Lambda** (function permissions), **SQS** (queue `Policy` attribute), **SNS** (topic policy, including the default topic policy), **KMS** (key policy), and **Secrets Manager** (secret resource policy). `IamEnforcementFilter` passes them to `IamPolicyEvaluator` Phase 2: an Allow from identity **or** resource is required; explicit Deny in either wins. Resource statements match `Principal` / `NotPrincipal` (AWS account id, `:root` as any principal in that account, ARN globs, `*`) via `PolicyPrincipalMatcher`. Condition context includes `aws:principalarn`, `aws:principalaccount`, `aws:sourceaccount`, `aws:sourcearn`, `aws:userid`, and `aws:sourceip`.

**Pre-signed S3 URLs:** After `PreSignedUrlFilter` validates SigV4 query auth (secret from the registered IAM access key or operator root pair), `IamEnforcementFilter` evaluates S3 identity and bucket policies for that credential.

### Bypass rules

These identities bypass enforcement:

| Identity | Behaviour |
|---|---|
| Access key matching `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` and secret matching `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | Allowed when both are configured (operator root) |
| No `Authorization` header | Allowed by default (health checks and unauthenticated paths) |
| Non-SigV4 `Authorization` (Basic, Bearer, etc.) on AWS API paths | Denied when enforcement is enabled (HTTP 403); Cognito `/cognito-idp/oauth2/*` is exempt and uses OAuth client auth instead |
| Unresolvable IAM action for the request | Allowed by default (unknown mappings are permissive) |

When enforcement is enabled, access keys that are not registered in the IAM store are **denied** (HTTP 403). This closes the legacy `test`/`test` bypass path used in local development.

### Strict enforcement (CTF hardening)

Set `strict-enforcement-enabled: true` together with `enforcement-enabled: true` to close the remaining permissive bypasses. Strict mode is intended for CTF and security-hardened deployments, not everyday local development.

**Environment variable:**
```bash
FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED=true
```

Under strict enforcement:

| Case | Behaviour |
|---|---|
| No `Authorization` header on `/health`, `/_floci/*`, or `/_localstack/*` | Allowed unless `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` is `true` or `all` (those paths return 404) |
| No `Authorization` header on any other path | Denied (HTTP 403) |
| Unresolvable IAM action for the request | Denied (HTTP 403) |

The configured root credential pair (`FLOCI_AUTH_ROOT_ACCESS_KEY_ID` and `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY`) still bypasses all enforcement checks when both match the request, including strict mode.

Pair strict enforcement with `FLOCI_AUTH_VALIDATE_SIGNATURES=true` so inbound API requests must carry a valid SigV4 signature. See [CTF hardening](#ctf-hardening) for the full operator workflow.

### Supported policy features

- **Identity-based policies**: inline user/group/role policies and managed attached policies.
- **Session policies**: inline policies passed during `sts:AssumeRole`.
- **Permission boundaries**: managed policies used to cap maximum permissions.
- **Action/Resource patterns**: literal matches, wildcards (`*`, `?`), and `NotAction`/`NotResource` blocks.
- **Conditions**: support for `Condition` blocks with multiple operators.
- **Effects**: `Allow` and `Deny`.

#### Supported Condition Operators:
- `StringEquals`, `StringNotEquals`, `StringEqualsIgnoreCase`, `StringNotEqualsIgnoreCase`
- `StringLike`, `StringNotLike`
- `ArnEquals`, `ArnLike`, `ArnNotEquals`, `ArnNotLike`
- `NumericEquals`, `NumericNotEquals`, `NumericLessThan`, `NumericGreaterThan` (and Equals variants)
- `DateEquals`, `DateNotEquals`, `DateLessThan`, `DateGreaterThan` (and Equals variants)
- `Bool`, `IpAddress`, `NotIpAddress`, `Null`
- Supports `...IfExists` variants for all operators.

**Resource-based policies (HTTP):** S3 bucket policy, Lambda resource policy, SQS queue policy, SNS topic policy, KMS key policy (see above).

**Not yet supported**: full cross-account condition keys, `NotPrincipal` on trust policies combined with complex federated principals, presigned POST (`policy` form field).

### Assumed roles

When a caller uses `sts:AssumeRole` the returned session credentials are registered internally. Subsequent requests signed with those session credentials are evaluated against:
1. The **role's** attached and inline policies.
2. The **session policy** (if provided during `AssumeRole`), acting as an intersection filter.

### Example — minimal enforcement setup

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create a user and get credentials
aws iam create-user --user-name alice
KEY=$(aws iam create-access-key --user-name alice --query 'AccessKey.[AccessKeyId,SecretAccessKey]' --output text)
AKID=$(echo $KEY | awk '{print $1}')
SECRET=$(echo $KEY | awk '{print $2}')

# Create and attach a policy that allows S3 list
POLICY_ARN=$(aws iam create-policy \
  --policy-name allow-s3-list \
  --policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListAllMyBuckets","Resource":"*"}]}' \
  --query 'Policy.Arn' --output text)

aws iam attach-user-policy --user-name alice --policy-arn $POLICY_ARN

# alice can now list buckets
AWS_ACCESS_KEY_ID=$AKID AWS_SECRET_ACCESS_KEY=$SECRET \
  aws s3 ls
```

## CTF hardening

Use this profile when Floci backs a capture-the-flag or security exercise and you need participants to prove valid IAM credentials and SigV4 signatures rather than relying on permissive local defaults.

### Required environment variables

| Variable | Value | Purpose |
|---|---|---|
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `true` | Evaluate IAM policies on every API call |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `true` | Deny unregistered access keys and unknown IAM action mappings (no permissive fall-through) |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `true` | Verify SigV4 request signatures using the caller's secret access key |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | operator secret | Access key ID for operator provisioning |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | operator secret | Secret access key paired with `FLOCI_AUTH_ROOT_ACCESS_KEY_ID`; both must match for the operator bypass |
The repository `docker-compose.yml` enables IAM enforcement, strict mode, and SigV4 validation by default. Export operator credentials on the host before starting Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
docker compose up
```

S3 presigned URLs use the same SigV4 query-string model as AWS. Sign with `aws s3 presign` using participant or operator IAM credentials, or use Floci's `PreSignedUrlGenerator` (requires `FLOCI_AUTH_ROOT_*` for built-in URL generation).

### Operator workflow

1. **Start Floci** with the CTF env vars set. Keep the root access key ID and secret known only to operators.
2. **Provision resources** using the root credentials (bypass IAM enforcement when the ID and secret both match):
   ```bash
   export AWS_ENDPOINT_URL=http://localhost:4566
   export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
   export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

   aws iam create-user --user-name player1
   aws iam create-access-key --user-name player1
   # attach policies, create S3 buckets, Lambda functions, etc.
   ```
3. **Issue participant credentials** from IAM (`CreateAccessKey` output). Participants must sign every request with SigV4 using those keys.
4. **Verify enforcement** by confirming an unprivileged or forged request returns HTTP 403:
   ```bash
   # wrong secret -> signature failure
   AWS_ACCESS_KEY_ID=<participant-akid> AWS_SECRET_ACCESS_KEY=wrong \
     aws s3 ls --endpoint-url http://localhost:4566
   ```

Under strict enforcement, the legacy `test`/`test` credential pair and other unregistered keys are rejected. Only IAM-registered identities with policies that allow the action (or the configured root pair) succeed.

**Cognito OAuth routes:** `/cognito-idp/oauth2/token` and `/cognito-idp/oauth2/userInfo` are not SigV4 APIs. Real Cognito uses `client_secret_basic` (HTTP Basic with `client_id:client_secret`) or `client_secret_post` for the token endpoint, and a Bearer access token for userInfo ([token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html)). Floci skips IAM policy evaluation on these paths and lets `CognitoOAuthController` / `CognitoUserInfoController` validate registered app-client credentials. They are **not** listed in `SecurityBypassPaths` as health or internal routes. Under strict enforcement, unauthenticated calls to other paths are denied; OAuth routes still require client credentials or a Bearer token at the controller. A Cognito-issued Bearer JWT does **not** satisfy SigV4 on S3, IAM, or other emulated services — `IamEnforcementFilter` rejects non-SigV4 `Authorization` headers on the data plane.

### AWS CLI version compatibility

The `floci:local` Docker image installs **AWS CLI v1** via pip on Alpine Linux (`pip3 install awscli`). When `FLOCI_AUTH_VALIDATE_SIGNATURES=true`, AWS CLI v1 frequently produces `SignatureDoesNotMatch` errors, even with correct credentials. The root cause is that v1 defaults to older signing behaviour in some configurations.

Use **boto3** (pre-installed in the image) or **AWS CLI v2** for operator provisioning scripts when signature validation is enabled:

```python
import boto3

client = boto3.client(
    "ssm",
    endpoint_url="http://localhost:4566",
    region_name="us-east-1",
    aws_access_key_id="...",
    aws_secret_access_key="...",
    config=boto3.session.Config(signature_version="v4"),
)
```

AWS CLI v2 does not install cleanly on Alpine (glibc vs musl mismatch); pin operator scripts to boto3 for CTF use.

See also [Docker Compose](../configuration/docker-compose.md) and [Environment Variables](../configuration/environment-variables.md).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_IAM_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `false` | Enforce IAM policies on all inbound requests |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `false` | When `true` with enforcement enabled, deny unregistered keys and unknown action mappings |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | _(none)_ | Operator root access key ID; bypasses enforcement when paired with `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | _(none)_ | Operator root secret; must match `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` for the bypass |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `false` | When `true`, verify SigV4 signatures on inbound API requests |

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create a role
aws iam create-role \
  --role-name lambda-execution-role \
  --assume-role-policy-document '{
    "Version": "2012-10-17",
    "Statement": [{
      "Effect": "Allow",
      "Principal": {"Service": "lambda.amazonaws.com"},
      "Action": "sts:AssumeRole"
    }]
  }' \
  --endpoint-url $AWS_ENDPOINT_URL

# Attach a managed policy
aws iam attach-role-policy \
  --role-name lambda-execution-role \
  --policy-arn arn:aws:iam::aws:policy/service-role/AWSLambdaBasicExecutionRole \
  --endpoint-url $AWS_ENDPOINT_URL

# Create a user
aws iam create-user --user-name alice --endpoint-url $AWS_ENDPOINT_URL

# Create an access key
aws iam create-access-key --user-name alice --endpoint-url $AWS_ENDPOINT_URL

# List roles
aws iam list-roles --endpoint-url $AWS_ENDPOINT_URL
```
