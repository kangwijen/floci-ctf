# IAM

**Protocol:** Query (XML) — `POST http://localhost:4566/` with `Action=` parameter

## Supported Actions

### Users

| Action | Description |
|--------|-------------|
| CreateUser | Creates an IAM user in the local account. |
| GetUser | Returns a stored IAM user. |
| DeleteUser | Deletes an IAM user from the local IAM store. |
| ListUsers | Lists IAM users in the local account. |
| UpdateUser | Updates mutable IAM user fields. |
| TagUser | Adds tags to an IAM user. |
| UntagUser | Removes tags from an IAM user. |
| ListUserTags | Lists tags stored for an IAM user. |

### Groups

| Action | Description |
|--------|-------------|
| CreateGroup | Creates an IAM group. |
| GetGroup | Returns an IAM group and its users. |
| DeleteGroup | Deletes an IAM group from the local IAM store. |
| ListGroups | Lists IAM groups in the local account. |
| AddUserToGroup | Adds a user to an IAM group. |
| RemoveUserFromGroup | Removes a user from an IAM group. |
| ListGroupsForUser | Lists groups that contain a user. |

### Roles

| Action | Description |
|--------|-------------|
| CreateRole | Creates an IAM role with an assume-role policy. |
| GetRole | Returns a stored IAM role. |
| DeleteRole | Deletes an IAM role from the local IAM store. |
| ListRoles | Lists IAM roles in the local account. |
| UpdateRole | Updates mutable IAM role fields. |
| UpdateAssumeRolePolicy | Replaces a role's assume-role policy document. |
| TagRole | Adds tags to an IAM role. |
| UntagRole | Removes tags from an IAM role. |
| ListRoleTags | Lists tags stored for an IAM role. |

### Policies

| Action | Description |
|--------|-------------|
| CreatePolicy | Creates a customer-managed IAM policy. |
| GetPolicy | Returns metadata for a managed IAM policy. |
| DeletePolicy | Deletes a managed IAM policy. |
| ListPolicies | Lists managed IAM policies, including seeded AWS managed policies. |
| CreatePolicyVersion | Creates a new version of a managed policy. |
| GetPolicyVersion | Returns a managed policy version document. |
| DeletePolicyVersion | Deletes a non-default managed policy version. |
| ListPolicyVersions | Lists versions for a managed policy. |
| SetDefaultPolicyVersion | Sets the default version for a managed policy. |
| TagPolicy | Adds tags to a managed policy. |
| UntagPolicy | Removes tags from a managed policy. |
| ListPolicyTags | Lists tags stored for a managed policy. |

### Permission Boundaries

| Action | Description |
|--------|-------------|
| PutUserPermissionsBoundary | Sets a managed policy as a user's permissions boundary. |
| DeleteUserPermissionsBoundary | Removes a user's permissions boundary. |
| PutRolePermissionsBoundary | Sets a managed policy as a role's permissions boundary. |
| DeleteRolePermissionsBoundary | Removes a role's permissions boundary. |

### Policy Attachments

| Action | Description |
|--------|-------------|
| AttachUserPolicy | Attaches a managed policy to a user. |
| DetachUserPolicy | Detaches a managed policy from a user. |
| ListAttachedUserPolicies | Lists managed policies attached to a user. |
| AttachGroupPolicy | Attaches a managed policy to a group. |
| DetachGroupPolicy | Detaches a managed policy from a group. |
| ListAttachedGroupPolicies | Lists managed policies attached to a group. |
| AttachRolePolicy | Attaches a managed policy to a role. |
| DetachRolePolicy | Detaches a managed policy from a role. |
| ListAttachedRolePolicies | Lists managed policies attached to a role. |

### Inline Policies

| Action | Description |
|--------|-------------|
| PutUserPolicy | Stores or replaces an inline policy on a user. |
| GetUserPolicy | Returns an inline policy stored on a user. |
| DeleteUserPolicy | Deletes an inline policy from a user. |
| ListUserPolicies | Lists inline policy names stored on a user. |
| PutGroupPolicy | Stores or replaces an inline policy on a group. |
| GetGroupPolicy | Returns an inline policy stored on a group. |
| DeleteGroupPolicy | Deletes an inline policy from a group. |
| ListGroupPolicies | Lists inline policy names stored on a group. |
| PutRolePolicy | Stores or replaces an inline policy on a role. |
| GetRolePolicy | Returns an inline policy stored on a role. |
| DeleteRolePolicy | Deletes an inline policy from a role. |
| ListRolePolicies | Lists inline policy names stored on a role. |

### Instance Profiles

| Action | Description |
|--------|-------------|
| CreateInstanceProfile | Creates an IAM instance profile. |
| GetInstanceProfile | Returns an instance profile and its roles. |
| DeleteInstanceProfile | Deletes an instance profile from the local IAM store. |
| ListInstanceProfiles | Lists IAM instance profiles. |
| AddRoleToInstanceProfile | Adds a role to an instance profile. |
| RemoveRoleFromInstanceProfile | Removes a role from an instance profile. |
| ListInstanceProfilesForRole | Lists instance profiles associated with a role. |

### Access Keys

| Action | Description |
|--------|-------------|
| CreateAccessKey | Creates access-key credentials for a user. |
| GetAccessKeyLastUsed | Returns the stored last-used metadata for an access key. |
| ListAccessKeys | Lists access keys for a user. |
| UpdateAccessKey | Updates an access key's status. |
| DeleteAccessKey | Deletes an access key from a user. |

### Login Profiles

| Action | Description |
|--------|-------------|
| CreateLoginProfile | Creates a password login profile for a user. |
| DeleteLoginProfile | Deletes a user's login profile. |
| UpdateLoginProfile | Updates a user's login profile password settings. |

### Policy Simulation

| Action | Description |
|--------|-------------|
| SimulatePrincipalPolicy | Evaluates requested actions and resources against the resolved principal's policies. |

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

## Optional Local Deployer Principal

Floci can seed a local IAM user for development workflows that expect a concrete caller identity before provisioning starts. This is disabled by default.

Enable it with:

```bash
FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL=true
```

When enabled, Floci creates the `floci-deployer` user if it does not already exist, attaches `arn:aws:iam::aws:policy/AdministratorAccess`, and creates static `floci` / `floci` access-key credentials if that access key does not already exist. Existing users and access keys are preserved.

Requests signed with the seeded access key return the deployer user ARN from `sts:GetCallerIdentity`.

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

1. An explicit **Deny** in any identity, session, or boundary policy → request is denied (HTTP 403 `AccessDeniedException`)
2. An explicit **Allow** in an identity policy creates the base grant
3. If a session policy is present, it must also explicitly allow the request
4. If a permission boundary is present, it must also explicitly allow the request
5. No matching effective allow → implicit deny (HTTP 403)

**AWS parity (policy-exempt actions):** AWS documents only two STS operations that do not require identity-based IAM permissions. Floci skips `IamPolicyEvaluator` for these when the access key is registered (SigV4 and strict-mode rules still apply). This applies globally on port 4566 for every emulated service: exemption is keyed on the resolved IAM action string, not per handler.

| IAM action | AWS documentation |
|---|---|
| `sts:GetCallerIdentity` | [GetCallerIdentity](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetCallerIdentity.html): no permissions required; explicit Deny does not block the call |
| `sts:GetSessionToken` | [GetSessionToken](https://docs.aws.amazon.com/STS/latest/APIReference/API_GetSessionToken.html): no permissions required; policies cannot control this authentication operation |

No other Floci-emulated service (S3, EC2, IAM, DynamoDB, Lambda, ...) has an AWS-documented equivalent. Calls such as `ec2:DescribeRegions`, `s3:ListAllMyBuckets`, or `iam:GetUser` still need an explicit Allow (or root bypass). Temporary credentials from `GetSessionToken` inherit the IAM user's permissions for subsequent calls.

Implementation: `IamUnrestrictedActions` in `core.common`, used by `IamEnforcementFilter` after `IamActionRegistry` resolves the action.

**JSON 1.1 credential scope:** For `POST /` requests with `X-Amz-Target`, `IamActionRegistry` resolves the IAM action from the **target service** in the header (for example `secretsmanager.ListSecrets`), not only from the SigV4 credential scope service. When the credential scope service and target service differ, strict enforcement returns HTTP 403. Regression: `IamJson11CredentialScopeSplitIntegrationTest`.

**REST route scope:** Catch-all rules that mis-route unrelated paths (historically Kinesis `POST .*`) are removed in favor of explicit service rules (for example `apigatewayv2` `/v2/apis`). Regression: `IamKinesisCatchAllRouteScopeIntegrationTest`.

**GetCallerIdentity identity shape:** `StsQueryHandler` resolves the signing access key via `IamService.resolveCallerIdentity` (IAM user ARN, assumed-role ARN, federated user, configured root AKID, or 12-digit account id). It does not always return account `:root`. Regression: `StsGetCallerIdentityIntegrationTest`.

**AssumeRole trust policies:** `AssumeRoleTrustPolicyEvaluator` checks role trust documents before credentials are issued, including `sts:ExternalId` conditions and `Principal.AWS` matching.

**Scoped resource ARNs:** `ResourceArnBuilder` maps each request to an AWS-shaped resource ARN for `IamPolicyEvaluator` (see [Service Authorization Reference](https://docs.aws.amazon.com/service-authorization/latest/reference/reference.html)). Covered scopes include:

| Scope | Source fields (examples) |
|---|---|
| `iam` | `UserName`, `GroupName`, `RoleName`, `PolicyArn` (form) |
| `dynamodb` | `TableName`, `TableArn`, `GlobalTableName` (JSON) |
| `secretsmanager` | `SecretId` / `Name` (JSON); stored secret ARN with six-char suffix when secret exists, else `secret:name-??????` per [AWS IAM examples](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html) |
| `s3` | Bucket/key from URL path |
| `lambda` | Function or layer name from path |
| `sqs` / `sns` | `QueueUrl` / `TopicArn` from Query form **or JSON 1.0 body**; account from queue URL path |
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
| `cloudtrail` | `Name`, `TrailName`, or `TrailARN` (JSON) |
| `guardduty` | `DetectorId` (JSON) |
| `config` | `ConfigRuleName` / `ConfigRule.ConfigRuleName`, or `ResourceArn` (JSON) |
| `rds-data` | `resourceArn` (JSON; full ARN or `rds:cluster:` prefix on REST execute/transaction routes) |
| `elasticmapreduce` | `ClusterId`, `JobFlowId`, `ClusterArn`, `ResourceArn`, or `JobFlowIds[]` (JSON `X-Amz-Target`); multi-ID requests evaluate every cluster ARN |
| `wafv2` | `Id`, `Name`, `Scope`, `ARN`/`Arn`/`WebACLArn`/`ResourceArn`, logging `ResourceArn` (JSON) |
| `scheduler` | `Name`, `GroupName`, path `/schedules/` or `/schedule-groups/`, `groupName` query |
| `pipes` | `Name` (JSON) or path `/v1/pipes/` |
| `kafka` | cluster ARN in path (`/v1/clusters/`, `/api/v2/clusters/`) or `clusterName` (JSON) |
| `securityhub` | `hub/default`; `Findings[].ProductArn` on `BatchImportFindings` / `BatchUpdateFindings` (JSON) |
| `apigatewayv2` | `ApiId` (JSON) |
| `codebuild` | `projectName` / `ProjectName` (JSON) |
| `codedeploy` | `applicationName`, `deploymentGroupName` (JSON) |
| `acm` | `CertificateArn` (JSON) |
| `backup` | `BackupVaultName`, `BackupVaultArn`, `DestinationBackupVaultArn`, `ResourceArn`, path `/backup-vaults/` (JSON) |
| `route53` | path `/hostedzone/` or `/healthcheck/` |
| `cloudfront` | path `/2020-05-31/distribution/`, policy paths, `function/`, query `Resource` on `/tagging` |
| `bedrock` / `bedrock-runtime` | path `/model/{modelId}/converse` or `/invoke` |
| `transfer` | `ServerId`, `UserName`, `Arn` (JSON `X-Amz-Target`) |
| `transcribe` | `TranscriptionJobName`, `VocabularyName` (JSON) |
| `cur` | `ReportName`, `ReportDefinition.ReportName` (JSON) |
| `bcm-data-exports` | `ExportArn`, `Export.Name` (JSON) |
| `appconfig` | REST paths under `/applications/` (application, environment, configuration profile, deployment) |
| `appconfigdata` | `ApplicationIdentifier`, `EnvironmentIdentifier`, `ConfigurationProfileIdentifier` (JSON) |
| `iot` / `iotdata` | Thing name from REST path `/things/{name}` or `/things/{name}/shadow`; topic from `/topics/{topic}`; policy/cert/rule names from control-plane paths. SigV4 scope `iotdata` maps to IAM actions with `iot:` prefix (for example `iot:UpdateThingShadow`). |
| `textract` | `JobId` on async job APIs (JSON) |
| `tagging` | `ResourceARNList[]` (multi-ARN evaluation for Tag/Untag/GetResources; `GetTagKeys`/`GetTagValues` stay `*`) |

**Intentionally unscoped per AWS SAR:** `pricing`, `api.pricing`, `ce` (query APIs in Floci), `ec2messages`, `cloudcontrolapi`.

When a specific resource cannot be determined, the builder returns a service-scoped wildcard (for example `table/*`) so broad `*` in policies still matches, but narrowly scoped ARNs do not. Extraction failures that previously returned bare `*` now return a `ResourceRef` UNRESOLVED token (`arn:floci:unresolved:::reason`). Under IAM strict enforcement, UNRESOLVED is denied. Intentional bare `*` (catalog scopes above, tagging `GetTagKeys`/`GetTagValues`, EMR list/create ops) stays `*`.

| Case | Behaviour when enforcement is on |
|---|---|
| Unmapped IAM action (registry miss) | Denied (HTTP 403), not only under strict |
| UNRESOLVED resource under strict | Denied (HTTP 403) |
| Bare `*` in multi-resource loops under strict | Evaluated (no longer skipped) |
| Unknown Lambda Function URL `urlId` | UNRESOLVED (not `function:*`) |
| Tagging `ResourceARNList` with no ARN-prefixed entries | UNRESOLVED under strict |

Regression: `UnresolvedResourceStrictModeTest`, `ResourceRefTest`, `TaggingIamScopedIntegrationTest`, `LambdaUrlArnNotWildcardTest`.

### Lab author IAM patterns (AWS-aligned)

When authoring policies or lab verifiers against `floci:local` with IAM enforcement, strict mode, and SigV4:

| Check | Why |
|---|---|
| `test`/`test` denied on `sts:GetCallerIdentity` | CTF hardening default |
| Invalid or missing SigV4 on HTTP API paths returns 403 | `FLOCI_AUTH_VALIDATE_SIGNATURES=true` |
| S3 presigned GET/PUT query URLs reject bad or expired SigV4 | `PreSignedUrlFilter` under strict IAM |
| Operator root secret wins when `X-Amz-Credential` matches `FLOCI_AUTH_ROOT_*` | Stale IAM registration with same AKID must not shadow operator secret |
| Each hop: `GetCallerIdentity` account + principal ARN (not `:root` for IAM users) | CTF identity fidelity |
| Wrong `sts:ExternalId` denied on every trust hop | Trust policy fidelity |
| SQS scoped policies use queue **ARN**; boto3 sends **QueueUrl** (Query or JSON 1.0) | [SQS authorization reference](https://docs.aws.amazon.com/service-authorization/latest/reference/list_amazonsqs.html) |
| SQS queue **resource policy** Allow alone can grant access (identity policy not required) | AWS `(identity OR resource) AND NOT deny` model |
| SNS topics get **no** open default policy when IAM enforcement is on | Operators must attach explicit topic policies |
| SNS account `:root` in topic policy does **not** authorize every IAM user | Identity Allow still required |
| Secrets path prefixes: `arn:...:secret:env/prod/*` | Not `secret:env/prod-*` ([AWS IAM examples](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html)) |
| Single secret: `secret:name-*` or `secret:name-??????` | Matches AWS six-character ARN suffix |
| `GetSecretValue` + CMK: pass raw bytes to `SecretBinary`; one base64 layer on wire | See [secrets-manager.md](./secrets-manager.md#kms-wrapped-secretbinary) |
| Secret rotation with CMK does not re-wrap existing KMS ciphertext | `AWSPENDING` / rotation Lambda path |
| Scoped IAM on `codebuild`, `backup`, `route53`, `codedeploy`, `acm`, `iot` / `iotdata` | Per-resource ARNs from request body or path; Lambda container creds honor execution-role policy on `iotdata` SigV4 scope |
| ECS task and CodeBuild build env use container credentials URI + task/build role SigV4 | `LaunchedContainerAwsEnv` + `ContainerEnvHardening`; no `test`/`test`; operator keys only via `OperatorCredentialEnv` when no role |
| Operator root never given to participants | Compose CTF profile |

Regression: `SigV4ValidationFilterIntegrationTest`, `PreSignedUrlFilterIntegrationTest`, `PreSignedUrlRootSecretPrecedenceIntegrationTest`, `StsGetCallerIdentityIntegrationTest`, `StsWebIdentityStrictUnsignedIntegrationTest`, `SqsReceiveMessageScopedQueueIntegrationTest`, `SqsResourcePolicyOnlyAllowIntegrationTest`, `SnsTopicNoDefaultPolicyIntegrationTest`, `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest`, `CodeBuildIamScopedIntegrationTest`, `BackupIamScopedIntegrationTest`, `Route53IamScopedIntegrationTest`, `IotIamScopedIntegrationTest`, `CodeDeployIamScopedIntegrationTest`, `AcmIamScopedIntegrationTest`, `EcsContainerCredentialsIamIntegrationTest`, `LambdaContainerCredentialsIamIntegrationTest`, `CodeBuildContainerCredentialsServerTest`, `SecretsManagerGetSecretValueScopedArnIntegrationTest`, `SecretsManagerKmsEnvelopeIntegrationTest`, `SecretsManagerRotationKmsIntegrationTest`.

**EMR multi-cluster:** requests with more than one `JobFlowIds[]` entry (for example `TerminateJobFlows`) call `ResourceArnBuilder.buildAllEmrClusterResources`; `IamEnforcementFilter` runs policy evaluation against each cluster ARN and denies the request if any cluster hits an explicit Deny.

**Tagging multi-ARN:** `TagResources`, `UntagResources`, and `GetResources` with multiple `ResourceARNList[]` entries call `ResourceArnBuilder.buildAllTaggingResources`; `IamEnforcementFilter` evaluates each ARN (CTF enhancement; AWS documents `tag:*` on `Resource`).

### In-process IAM (non-HTTP)

Some AWS integrations call emulated services inside the JVM without hitting `IamEnforcementFilter`. When `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`, Floci evaluates policies on these paths the same way as HTTP (identity + resource policies; explicit Deny wins).

**Execution-role paths (`InProcessIamAuthorizer`):** Step Functions AWS SDK task integrations and API Gateway AWS integrations require a non-blank `roleArn` / integration `credentials` role. Identity and resource policies are evaluated via `ResourceArnBuilder.buildFromJsonBody`; KMS grant fallback applies on this path (same as HTTP).

| Path | IAM actions (representative) | AWS reference |
|---|---|---|
| Step Functions task integrations | Per integration (e.g. `dynamodb:PutItem`, `secretsmanager:GetSecretValue`, `kms:Decrypt`) | [SFN service integrations](https://docs.aws.amazon.com/step-functions/latest/dg/supported-services-awssdk.html) |
| API Gateway AWS integrations | Per integration JSON body | [API Gateway credentials](https://docs.aws.amazon.com/apigateway/latest/developerguide/api-gateway-integration-settings-integration-request.html) |

**Delivery paths (`InProcessTargetAuthorizer`):** Role-based callers use identity policies on the supplied role ARN. Service-to-service delivery uses destination resource policies with the AWS service principal shown.

| Path | Caller identity | IAM actions on destination | AWS reference |
|---|---|---|---|
| EventBridge Pipes (source poll) | Pipe `roleArn` | SQS: `ReceiveMessage`, `GetQueueAttributes`; Kinesis: `DescribeStream`, `GetRecords`, `GetShardIterator`; DynamoDB Streams: `DescribeStream`, `GetRecords`, `GetShardIterator`; SQS delete on ack: `DeleteMessage` | [Pipes permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-permissions.html) |
| EventBridge Pipes / Scheduler (target) | Pipe or schedule `roleArn` | Lambda `InvokeFunction`, SQS `SendMessage`, SNS `Publish`, EventBridge `PutEvents`, Step Functions `StartExecution`, Kinesis/Firehose `PutRecord` | [Pipes permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-pipes-permissions.html), [Scheduler target permissions](https://docs.aws.amazon.com/scheduler/latest/UserGuide/managing-target-permissions.html) |
| EventBridge rule targets | Rule `roleArn` if set; else `events.amazonaws.com` on destination | Same target mapping as Pipes/Scheduler | [EventBridge permissions](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-use-resource-based.html) |
| EventBridge archive replay | Internal replay (no destination bus policy gate) | N/A | [Archive replay](https://docs.aws.amazon.com/eventbridge/latest/userguide/eb-archive-replay.html) |
| SNS subscriptions (Lambda/SQS) | `sns.amazonaws.com` on endpoint | Lambda `InvokeFunction`, SQS `SendMessage` | [SNS access policies](https://docs.aws.amazon.com/sns/latest/dg/sns-access-policy-use-cases.html) |
| S3 event notifications | `s3.amazonaws.com` on destination (EventBridge: no policy gate) | SQS `SendMessage`, SNS `Publish`, Lambda `InvokeFunction` | [S3 event notifications](https://docs.aws.amazon.com/AmazonS3/latest/userguide/EventNotifications.html) |
| SES event destinations | `ses.amazonaws.com` on SNS; Firehose `roleArn` or service principal; EventBridge: no policy gate | SNS `Publish`, Firehose `PutRecord` / `PutRecordBatch` | [Monitor sending activity](https://docs.aws.amazon.com/ses/latest/dg/monitor-sending-activity.html) |
| Lambda event source mappings | Function execution role on source | SQS: `ReceiveMessage`, `GetQueueAttributes`, `DeleteMessage`; Kinesis/DynamoDB Streams: `DescribeStream`, `GetShardIterator`, `GetRecords` | [Lambda execution role](https://docs.aws.amazon.com/lambda/latest/dg/lambda-intro-execution-role.html), [Using Lambda with SQS](https://docs.aws.amazon.com/lambda/latest/dg/with-sqs.html) |
| CloudWatch Logs subscription filters | Lambda: `logs.amazonaws.com` on function; Kinesis/Firehose: filter `roleArn` identity policy (required) | Lambda `InvokeFunction`, Firehose/Kinesis `PutRecord` | [Logs subscription permissions](https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/Subscriptions.html) |
| ALB Lambda targets | `elasticloadbalancing.amazonaws.com` on function | Lambda `InvokeFunction` | [ALB Lambda permissions](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/lambda-functions.html) |
| API Gateway Lambda proxy/authorizer | `apigateway.amazonaws.com` on function | Lambda `InvokeFunction` | [Lambda permissions for API Gateway](https://docs.aws.amazon.com/lambda/latest/dg/services-apigateway.html) |
| Cognito Lambda triggers | `cognito-idp.amazonaws.com` on function | Lambda `InvokeFunction` | [Cognito Lambda triggers](https://docs.aws.amazon.com/cognito/latest/developerguide/cognito-user-identity-pools-working-with-aws-lambda-triggers.html) |
| CodeDeploy lifecycle hooks | `codedeploy.amazonaws.com` on function | Lambda `InvokeFunction` | [CodeDeploy Lambda integrations](https://docs.aws.amazon.com/codedeploy/latest/userguide/integrations-lambda.html) |
| CloudTrail / Config / VPC flow logs (S3 delivery) | Service principal on bucket/object | CloudTrail/Config: `s3:GetBucketAcl`, `s3:ListBucket` (Config), scoped `s3:PutObject`; VPC flow logs: `delivery.logs.amazonaws.com` | [CloudTrail S3 bucket policy](https://docs.aws.amazon.com/awscloudtrail/latest/userguide/create-s3-bucket-policy-for-cloudtrail.html), [Config S3 delivery](https://docs.aws.amazon.com/config/latest/developerguide/s3-bucket-policy.html), [Flow logs to S3](https://docs.aws.amazon.com/vpc/latest/userguide/flow-logs-s3.html) |
| Firehose S3 destination flush | Delivery stream `RoleARN` identity policy | `s3:PutObject` on destination prefix | [Firehose access control](https://docs.aws.amazon.com/firehose/latest/dev/controlling-access.html) |
| CUR / BCM Data Exports (Parquet emit) | `bcm-data-exports.amazonaws.com` or `billingreports.amazonaws.com` on destination | BCM: `s3:PutObject` only; legacy CUR: `s3:PutObject` + `s3:GetBucketPolicy` | [BCM Data Exports](https://docs.aws.amazon.com/cur/latest/userguide/dataexports-s3-bucket.html) |

Unmapped pipe sources (for example Amazon MQ) and unknown target ARNs are denied when enforcement is on. Container runtime credentials (Lambda/CodeBuild/ECS on ports 9170-9172) still call `:4566` over HTTP with SigV4 and pass through `IamEnforcementFilter`. Regression: `EcsContainerCredentialsIamIntegrationTest`, `CodeBuildContainerCredentialsServerTest`.

**Resource-based policies:** `ResourcePolicyResolver` loads policy documents for **S3** (bucket policy), **Lambda** (function permissions), **SQS** (queue `Policy` attribute), **SNS** (topic policy; no open default when IAM enforcement is on), **KMS** (key policy), and **Secrets Manager** (secret resource policy). `IamEnforcementFilter` passes them to `IamPolicyEvaluator` Phase 2: an Allow from identity **or** resource is required; explicit Deny in either wins. Account `:root` in a resource policy does **not** authorize every IAM user (unlike trust-policy `:root` semantics). Resource statements match `Principal` / `NotPrincipal` (AWS account id, `:root` as account root only, ARN globs, `*`, and `Principal.Service` for bare service names or `aws-service-role` SLR paths) via `PolicyPrincipalMatcher`. Condition context includes `aws:principalarn`, `aws:principalaccount`, `aws:sourceaccount`, `aws:sourcearn`, `aws:userid`, and `aws:sourceip`. Regression: `SnsTopicNoDefaultPolicyIntegrationTest`, `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest`, `SqsResourcePolicyOnlyAllowIntegrationTest`, `PolicyPrincipalMatcherTest`.

**Pre-signed S3 URLs:** After `PreSignedUrlFilter` validates SigV4 query auth, `IamEnforcementFilter` evaluates S3 identity and bucket policies for that credential. When `X-Amz-Credential` matches `FLOCI_AUTH_ROOT_ACCESS_KEY_ID`, the operator root secret from config (not a stale IAM registration with the same access key id) is used for signature verification. Regression: `PreSignedUrlFilterIntegrationTest`, `PreSignedUrlRootSecretPrecedenceIntegrationTest`.

**S3 bucket-list conditions:** `IamConditionContextResolver` adds `s3:prefix`, `s3:delimiter`, and `s3:max-keys` to the condition context for `s3:ListBucket` when the matching query parameters are present. This lets CTF IAM policies restrict S3 listings by requested prefix, delimiter, or page size.

**API Gateway in-process IAM:** JSON-body AWS integrations and path-style integrations (`arn:...:sqs:path/...`, `arn:...:lambda:path/...`) evaluate the integration execution role via `InProcessIamAuthorizer` when enforcement is on. Path-style SQS calls use `AwsServiceRouter.invokeQuery` with `integration.credentials`. Regression: `ApiGatewaySqsQueryIamBypassIntegrationTest`.

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
| No `Authorization` header on `/health`, `/_floci/*`, `/_localstack/*`, or `/_aws/*` | Allowed unless `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` is `true` or `all` (prefixed paths return 404; `/health` only hidden in `all` mode) |
| `aws:sourceip` from `X-Forwarded-For` | Ignored unless `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` (default `false`) |
| Temporary credentials (`ASIA*`) with SigV4 on | `x-amz-security-token` must match the token issued with the session (HTTP headers and S3 presigned query URLs via `X-Amz-Security-Token`) |
| No `Authorization` header on any other path | Denied (HTTP 403) |
| `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML` with token in form body (no SigV4) | Allowed through IAM filter; trust evaluated in `StsQueryHandler` (`SecurityBypassPaths.isFederatedStsAssumeRequest`) |
| Unresolvable IAM action for the request | Denied (HTTP 403). Same deny applies whenever enforcement is on (not only strict) |
| UNRESOLVED resource ARN (`ResourceRef`) | Denied (HTTP 403). Bare `*` in multi-resource loops is evaluated, not skipped |

**Anonymous-access exceptions (`AnonymousAccessGate`):** {#anonymous-access-exceptions} Under strict enforcement, unsigned requests are still allowed only on AWS-intentional public invoke paths. Each surface has an explicit gate: resource policy evaluation for S3 and Lambda function URLs, and method `authorizationType` for API Gateway. Methods with `authorizationType=AWS_IAM` (or any non-`NONE` value) do not qualify; unsigned invoke is denied like any other unsigned path.

| Surface | Gate condition | Regression |
|---|---|---|
| S3 object read | Public bucket policy allows `s3:GetObject` or `s3:HeadObject` for `Principal *` | `S3PublicBucketPolicyAnonymousGetIntegrationTest` |
| API Gateway data plane | REST method explicit `authorizationType=NONE` on `execute-api` or `_user_request_` paths; null auth type is not `NONE` under strict; `AWS_IAM` and other non-`NONE` types require SigV4 | `ApiGatewayNoneAuthAnonymousInvokeIntegrationTest`, `ExecuteAuthzGateTest` |
| Lambda function URL | `AuthType=NONE` on `/lambda-url/{urlId}` **and** function resource policy allows `lambda:InvokeFunctionUrl` for anonymous principal. `AuthType=AWS_IAM` requires Authorization even when non-strict. IAM resource ARN is the concrete function from the urlId store | `LambdaFunctionUrlNoneAuthIntegrationTest`, `LambdaUrlAwsIamAuthTypeTest`, `LambdaUrlArnNotWildcardTest` |
| Bypass regressions (negative) | Unsigned requests denied when gate conditions are not met (private bucket, `AWS_IAM` method, `AuthType=AWS_IAM`, `AuthType=NONE` without public resource policy, unsigned `PutObject` despite public `GetObject`) | `AnonymousAccessGateBypassIntegrationTest` |

The configured root credential pair (`FLOCI_AUTH_ROOT_ACCESS_KEY_ID` and `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY`) still bypasses all enforcement checks when both match the request, including strict mode.

Pair strict enforcement with `FLOCI_AUTH_VALIDATE_SIGNATURES=true` so inbound API requests must carry a valid SigV4 signature. Regression: `SigV4ValidationFilterIntegrationTest`. See [CTF hardening](#ctf-hardening) for the full operator workflow.

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

**Not yet supported**: full cross-account condition keys, `NotPrincipal` on trust policies combined with complex federated principals.

**Presigned S3 (CTF fork):** Query-string GET/PUT URLs validate under `FLOCI_AUTH_VALIDATE_SIGNATURES=true` with IAM or operator root secrets (`PreSignedUrlFilter`). When the access key id matches `FLOCI_AUTH_ROOT_ACCESS_KEY_ID`, the configured operator root secret wins over IAM lookups. Signed `x-amz-*` headers are read from the request when absent from the query string. Presigned POST requires policy and signature fields under strict enforcement; policy expiration is enforced. Regression: `PreSignedUrlFilterIntegrationTest`, `PreSignedUrlRootSecretPrecedenceIntegrationTest`, `PreSignedUrlCtfIntegrationTest`, `S3PresignedPostCtfIntegrationTest`, `S3PresignedPostIntegrationTest`.

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

Optional CTF controls (see [environment variables](../configuration/environment-variables.md#ctf-hardening)):

| Variable | Default | Purpose |
|---|---|---|
| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | `true` | Hide `/_floci/*`, `/_localstack/*`, `/_aws/*`; `all` also hides `/health` |
| `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` | `false` | Trust `X-Forwarded-For` for `aws:sourceip` (enable only behind a trusted proxy) |
| `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS` | `false` (Compose `true`) | When `true`, require structurally valid JWT/SAML assertions and validate expiry, issuer, and configured verification keys. SAML claims bind to the verified Signature Assertion (XSW rejected). `AuthPosture` also requires federated crypto when IAM strict is on, without changing this YAML default |
| `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRET` | _(none)_ | Shared HS256 secret for web identity JWT verification when validation is enabled |
| `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRETS__<provider_host>` | _(none)_ | Per-provider HS256 secrets (for example `accounts_google.com`) |
| `FLOCI_CTF_FEDERATED_JWT_RS256_PUBLIC_KEY_PEM` | _(none)_ | PEM RSA public key for RS256 web identity JWT verification |
| `FLOCI_CTF_REQUIRE_EKS_TOKEN_SIGV4` | `true` | Require a valid SigV4 or SigV4a presigned STS `GetCallerIdentity` URL in EKS bearer tokens |
| `FLOCI_CTF_CONTAINER_CREDENTIALS_BIND_LOCALHOST` | `true` | Bind Lambda/CodeBuild/ECS credential HTTP servers to `127.0.0.1` |
| `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER` | `false` | Honor `X-Floci-CloudTrail-Source-Ip` for CloudTrail `sourceIPAddress` only |
| `FLOCI_CTF_CLOUDTRAIL_INJECTION_ENABLED` | `false` | Operator-only `POST /_floci/cloudtrail/events*` for synthetic audit events |

### Managed policy version timing

**`iam:GetPolicyVersion`:** Scopes to `arn:aws:iam::ACCOUNT:policy/NAME` from `PolicyArn`. Callers can read a pending policy document before publishing.

**`iam:CreatePolicyVersion`:** With `SetAsDefault=true`, the new document applies on the **next** HTTP API call from that principal. Same-request `GetSecretValue` or `kms:Decrypt` after `CreatePolicyVersion` in one process still evaluates the previous default until the following round trip. Regression: `CreatePolicyVersionGrantsSecretReadIntegrationTest`.

The repository `docker-compose.yml` enables IAM enforcement, strict mode, and SigV4 validation by default. Export operator credentials on the host before starting Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
docker compose up
```

Compose enables federated token validation. Configure an HMAC secret or RSA public key for each lab issuer when you need cryptographic verification. A lab that intentionally needs unsigned web identity tokens must turn off IAM strict enforcement (or both enforcement and `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS`) explicitly. Setting only `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=false` while Compose keeps strict IAM on still requires federated crypto via `AuthPosture`. When validation is on, unsigned JWTs and `alg=none` are rejected.

`AuthPosture` (`core/common/auth`) is the single derived reader for IAM enforcement, strict mode, SigV4 required, federated crypto required, and egress block. Main `application.yml` stays permissive; Quarkus profile `ctf` (`application-ctf.yml` / `QUARKUS_PROFILE=ctf`) and Compose turn full CTF posture on. When `FLOCI_AUTH_VALIDATE_SIGNATURES=true`, `RequestContext.accessKeyId` used by in-process PassRole is set only after SigV4 or S3 presign verification succeeds. Regression: `CtfProfilePostureIntegrationTest`.

S3 presigned URLs use the same SigV4 query-string model as AWS. Sign with `aws s3 presign` using participant or operator IAM credentials, or use Floci's `PreSignedUrlGenerator` (requires `FLOCI_AUTH_ROOT_*` for built-in URL generation).

### Operator workflow

1. **Start Floci** with the CTF env vars set. Keep the root access key ID and secret known only to operators.
2. **Provision resources** using the root credentials (bypass IAM enforcement when the ID and secret both match):
   ```bash
   export AWS_ENDPOINT_URL=http://localhost:4566
   export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
   export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

   aws iam create-user --user-name participant-user
   aws iam create-access-key --user-name participant-user
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

**Credential material:** Access key IDs, secret access keys, STS session secrets/tokens, and container workload credentials (Lambda/CodeBuild/ECS/IMDS) are generated with `java.security.SecureRandom`, not `ThreadLocalRandom`. See OWASP Cryptographic Storage guidance on CSPRNGs for security-sensitive values.

**Policy glob matching:** `IamPolicyEvaluator.globMatches` uses an `O(n*m)` dynamic-programming matcher for `*` and `?` so multi-wildcard Resource or Condition patterns cannot trigger exponential recursive backtracking against long literal ARNs. Regression: `IamPolicyEvaluatorTest.globMatchesPathologicalMultiWildcardCompletesInLinearTime`.

**Condition keys and set operators:** `IamEnforcementFilter.buildConditionContext` populates `aws:RequestedRegion`, `aws:CurrentTime`, and `aws:EpochTime` in addition to principal/source keys. `IamPolicyEvaluator` supports `ForAllValues:` and `ForAnyValue:` multi-value condition operators. Regression: `IamEnforcementFilterTest`, `IamConditionContextResolverTest`, `IamPolicyEvaluatorTest`.

**Inactive access keys:** `UpdateAccessKey` with `Status=Inactive` removes the key from SigV4 secret lookup. Inactive keys cannot authenticate. Regression: `IamServiceTest`.

**`iam:PassRole`:** Creating Step Functions state machines, Scheduler schedules, EventBridge Pipes, ECS task definitions (task + execution roles), EC2 instances with an instance profile, and Lambda functions (`CreateFunction` / `UpdateFunctionConfiguration` Role) evaluates `iam:PassRole` on the role ARN (in addition to the service create action), with `iam:PassedToService` set to the target service principal. Under IAM enforcement, a missing or unresolved caller is denied (fail-closed), matching `authorizeCallerAction`. The configured root access key skips PassRole evaluation. Role trust-policy checks at PassRole time are not implemented yet. Regressions: `PassRoleFailsClosedWithoutCallerTest`, `EcsTaskRoleRequiresPassRoleTest`, `Ec2InstanceProfilePassRoleTest`, `LambdaCreateFunctionPassRoleTest`, `ComputePassRoleGateTest`.

**CloudFormation in-process IAM:** Privileged IAM create actions and `iam:AttachRolePolicy` (role `ManagedPolicyArns`, policy `Roles`) authorize the stack creator via `InProcessIamAuthorizer` with `aws:CalledVia=cloudformation.amazonaws.com`. Regression: `CloudFormationResourceProvisionerIamGateTest`.

**Tagging multi-ARN:** `tagging:TagResources` / `UntagResources` evaluate each ARN in `ResourceARNList`. When no ARN-prefixed entries remain, the builder returns UNRESOLVED (denied under strict). Regression: `TaggingIamScopedIntegrationTest`, `UnresolvedResourceStrictModeTest`.

**Cognito OAuth routes:** `/cognito-idp/oauth2/token` and `/cognito-idp/oauth2/userInfo` are not SigV4 APIs. Real Cognito uses `client_secret_basic` (HTTP Basic with `client_id:client_secret`) or `client_secret_post` for the token endpoint, and a Bearer access token for userInfo ([token endpoint](https://docs.aws.amazon.com/cognito/latest/developerguide/token-endpoint.html)). Floci skips IAM policy evaluation on these paths and lets `CognitoOAuthController` / `CognitoUserInfoController` validate registered app-client credentials and access-token signatures. They are **not** listed in `SecurityBypassPaths` as health or internal routes. Under strict enforcement, unauthenticated calls to other paths are denied; OAuth routes still require client credentials or a verified Bearer access token at the controller. A Cognito-issued Bearer JWT does **not** satisfy SigV4 on S3, IAM, or other emulated services — `IamEnforcementFilter` rejects non-SigV4 `Authorization` headers on the data plane.

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
| `FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL` | `false` | Seed the optional `floci-deployer` user and `floci` / `floci` access key (not seeded when enforcement is on in this fork) |
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
