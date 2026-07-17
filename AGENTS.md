# AGENTS.md: floci-ctf

Guidance for AI agents and operators in this repository. **floci-ctf** is a security-hardened fork of [Floci](https://github.com/floci-io/floci) for CTF and security exercises. It is not stock upstream `floci/floci:latest`.

Human-readable fork summary: [README.md](./README.md). IAM detail: [docs/services/iam.md](./docs/services/iam.md#ctf-hardening).

---

## CTF fork overview

| Item | Value |
|---|---|
| Language | Java 25 |
| Framework | Quarkus 3.36.0 |
| Latest upstream merge | 1.5.33 + tip `fba4d8f5` (2026-07-15) |
| Port | 4566 (HTTP API). Image has no `EXPOSE`. Challenge Compose publishes (default `4566` only). |
| Config prefix | `floci.*` / `FLOCI_*` |
| Image tag (local) | `floci:local` |

**First principles (override upstream defaults when they conflict):**

1. Preserve CTF hardening on upstream merges: IAM enforcement, strict mode, SigV4 validation, no baked-in `test`/`test`.
2. Match AWS semantics where Floci can model them (auth, presign, STS trust, resource policies).
3. Keep diffs narrow; reuse `AwsException`, `StorageFactory`, protocol controllers.
4. Ship docs and tests with behavior changes (`README.md`, this file, `docs/services/iam.md` when IAM changes).
5. Prioritize core CTF surface: IAM, STS, S3, SQS, SNS, DynamoDB, Lambda, KMS, Secrets Manager.

**Fork-only HTTP auth (`core.common`):** `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths`, `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode`, `ContainerEnvHardening`, `OperatorCredentialEnv`, `ClientSourceIpResolver`, `AccountResolver`, `AccountContextFilter`, `CtfVelocityEngineFactory` (VTL `SecureUberspector` sandbox).

**Related fork deltas:** `PreSignedUrlFilter`, `PreSignedUrlGenerator` (SigV4 with operator root AKIA, not upstream account-id signing), `ResourcePolicyResolver`, `PolicyPrincipalMatcher`, `ResourceArnBuilder`, `AssumeRoleTrustPolicyEvaluator`, `StsQueryHandler`, `SecretsManagerKmsSupport`, `EksTokenValidator`, `InProcessTargetAuthorizer`.

---

## Using `floci:local` (operators)

Build from this repo (not upstream `floci/floci:latest`):

```bash
docker build -f docker/Dockerfile -t floci:local .
```

`docker/Dockerfile` declares no `EXPOSE`. Publish ports from challenge Compose (or `docker run -p`), not from image metadata. Root Compose maps `4566:4566` only. See [docs/configuration/ports.md](./docs/configuration/ports.md#ctf-fork-this-repository).

Set operator env on the **host**, then start Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
docker compose up -d
```

Compose enables (do not turn off for CTF): `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED`, `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED`, `FLOCI_AUTH_VALIDATE_SIGNATURES`, `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` (use `all` to hide `/health` from players), and `FLOCI_CTF_BLOCK_PRIVATE_OUTBOUND_URLS` for SNS HTTP(S), API Gateway HTTP integrations, and ALB IP or hostname targets.

### Operator vs participant

| Role | Credentials | Behavior |
|------|-------------|----------|
| **Operator** | `FLOCI_AUTH_ROOT_*` | Bypasses IAM enforcement for provisioning; must SigV4; never give to players |
| **Participant** | IAM `create-access-key` | Subject to IAM + SigV4; `test`/`test` and unregistered keys fail |

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
# Operator provisioning
aws iam create-user --user-name participant-user
aws iam create-access-key --user-name participant-user
aws sts get-caller-identity   # expect arn:aws:iam::ACCOUNT:user/participant-user, not :root
```

### Fork vs upstream (summary)

| Topic | Upstream | This fork |
|-------|----------|-----------|
| Default creds | `test`/`test` baked in; optional `floci`/`floci` deployer | None in `docker/Dockerfile`; `floci`/`floci` deployer not seeded when IAM enforcement is on (`seed-deployer-principal` gated) |
| Image `EXPOSE` | Upstream may declare API / proxy ports | None. Challenge Compose publishes host ports |
| IAM enforcement | Off by default | On in `docker-compose.yml` |
| SigV4 | Off by default | On with Compose profile |
| Strict mode | N/A | Denies missing auth, unmapped actions, bad presign |
| Internal routes | Open | `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` returns 404 on `/_floci/*`, `/_localstack/*`, `/_aws/*` |
| ASIA session token | Optional header | `x-amz-security-token` stored and validated for temporary creds when SigV4 is on |
| `aws:sourceip` | Client `X-Forwarded-For` | Default ignores forwarded headers; set `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` behind a real proxy |
| `GetCallerIdentity` | Often account `:root` | Calling principal ARN for IAM users |
| Presigned URL signing | `X-Amz-Credential` may use 12-digit account id as access key id | Generator signs with operator root AKIA + SigV4; `AccountContextFilter` still resolves account from inbound presigned `X-Amz-Credential` |
| Container env | User can set `AWS_*` | `ContainerEnvHardening` strips credential keys |

### Health and internal endpoints

| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | `/health` | `/_floci/*`, `/_localstack/*`, `/_aws/*` |
|-------------------------------------|-----------|----------------------------------------|
| `false` | 200 | reachable |
| `true` (default) | 200 | 404 |
| `all` | 404 | 404 |

Operator smoke: `GET http://localhost:4566/health` (not `/_floci/health` unless hide is `false`).

### Common operator mistakes

- Using `test`/`test` like upstream docs
- Root access key ID without paired secret (operator SigV4 fails)
- Presigned URLs signed with unknown access keys (only registered IAM keys or operator root verify)
- Giving operator root creds to players
- Expecting `GetCallerIdentity` to return `:root` for IAM user keys
- Expecting Redis/RDS/ECR host ports from root Compose or image `EXPOSE` (challenge Compose must publish them)
- Expecting player `AWS_*` in Lambda/ECS/CodeBuild env (stripped)

---

## IAM and scoped resources

When IAM enforcement is on, identity policies use AWS-shaped **resource ARNs** from the request (`ResourceArnBuilder`), not always `*`.

| Action | Policy `Resource` | Request target |
|--------|-------------------|----------------|
| `iam:CreateAccessKey` | `arn:aws:iam::ACCOUNT:user/name` | `UserName` in form body |
| `dynamodb:GetItem` / `Query` | `arn:aws:dynamodb:REGION:ACCOUNT:table/name` (and `.../index/name` for GSI) | `TableName`, `IndexName`, or `RequestItems` key in JSON |
| `dynamodb:PutItem` | `arn:aws:dynamodb:REGION:ACCOUNT:table/name` | `TableName` in JSON body |
| `dynamodb:PartiQL*` | Same table ARN(s) | `Statement` SQL (`FROM`/`JOIN`/`INTO`/`UPDATE` tables) on `ExecuteStatement`; all referenced tables on multi-table statements; each batch entry on `BatchExecuteStatement` |
| `secretsmanager:GetSecretValue` | `arn:aws:secretsmanager:REGION:ACCOUNT:secret:path/*` (path prefix) or `secret:name-*` / `secret:name-??????` (single secret; AWS six-char suffix) | `SecretId`; IAM uses stored full ARN when secret exists |
| `kms:Decrypt` | `arn:aws:kms:REGION:ACCOUNT:key/KEY-ID` | `KeyId` or Floci `kms:v2:` blob in `CiphertextBlob` |
| `sqs:ReceiveMessage` | `arn:aws:sqs:REGION:ACCOUNT:queue` | `QueueUrl` (Query form or JSON 1.0 body) |
| `sqs:ListQueues` | `*` (list API per AWS) | Query `Action=ListQueues` or JSON 1.0 `AmazonSQS.ListQueues`; IAM deny returns `AccessDenied` (not `ServiceNotAvailable`) |
| `sns:Subscribe` | `arn:aws:sns:REGION:ACCOUNT:topic` | `TopicArn` |
| `sns:Publish` | `arn:aws:sns:REGION:ACCOUNT:topic` | `TopicArn` (Query or JSON); identity OR topic resource policy |
| `ssm:GetParameter` | `arn:aws:ssm:REGION:ACCOUNT:parameter/path` | `Name` |
| `cloudformation:DescribeStacks` | `arn:aws:cloudformation:REGION:ACCOUNT:stack/NAME/*` | `StackName` |
| `s3:GetObjectVersion` | `arn:aws:s3:::bucket/key` | `versionId` query param |
| `s3:ListBucketVersions` | `arn:aws:s3:::bucket` | `?versions` on bucket GET |
| `sts:AssumeRole` | Role ARN + trust on role | `sts:AssumeRole` on role; trust `sts:ExternalId` when set |
| `eks:CreateNodegroup` | `arn:aws:eks:REGION:ACCOUNT:nodegroup/CLUSTER/*` | `POST /clusters/{name}/node-groups` |
| `athena:CreateWorkGroup` | `arn:aws:athena:REGION:ACCOUNT:workgroup/name` | `Name` in JSON body on `CreateWorkGroup` |
| `iot:UpdateThingShadow` / `GetThingShadow` | `arn:aws:iot:REGION:ACCOUNT:thing/name` | `POST`/`GET` `/things/{name}/shadow` (SigV4 scope `iotdata`) |
| `cloudtrail:StopLogging` | `arn:aws:cloudtrail:REGION:ACCOUNT:trail/name` | `Name` in JSON body |
| `cloudtrail:LookupEvents` | `arn:aws:cloudtrail:REGION:ACCOUNT:trail/*` when body has no trail name; named trail when `Name` / `TrailARN` present | JSON body (`LookupEvents` has no per-trail filter; IAM scopes the API) |
| `iam:GetPolicyVersion` | `arn:aws:iam::ACCOUNT:policy/name` | `PolicyArn` in form body |
| `iam:CreatePolicyVersion` | `arn:aws:iam::ACCOUNT:policy/name` | `PolicyArn` in form body |
| `guardduty:GetFindings` | `arn:aws:guardduty:REGION:ACCOUNT:detector/id` | `DetectorId` in JSON body |
| `config:PutConfigRule` | `arn:aws:config:REGION:ACCOUNT:config-rule/name` | `ConfigRule.ConfigRuleName` in JSON body |
| `rds-data:ExecuteStatement` | `arn:aws:rds:REGION:ACCOUNT:cluster/name` | `resourceArn` in JSON body (REST routes) |
| `elasticmapreduce:DescribeCluster` | `arn:aws:elasticmapreduce:REGION:ACCOUNT:cluster/id` | `ClusterId`, `JobFlowId`, `ClusterArn`, or `JobFlowIds[]` in JSON (`X-Amz-Target`) |
| `wafv2:GetWebACL` | `arn:aws:wafv2:REGION:ACCOUNT:regional/webacl/*/id` (or name wildcard on create) | `Id`, `Name`, `Scope`, or direct ARN fields in JSON |
| `scheduler:GetSchedule` | `arn:aws:scheduler:REGION:ACCOUNT:schedule/group/name` | `Name`, `GroupName`, path `/schedules/`, or `groupName` query |
| `pipes:DescribePipe` | `arn:aws:pipes:REGION:ACCOUNT:pipe/name` | `Name` in JSON or path `/v1/pipes/` |
| `kafka:DescribeCluster` | `arn:aws:kafka:REGION:ACCOUNT:cluster/name/*` | cluster ARN in path (`/v1/clusters/`, `/api/v2/clusters/`) or `clusterName` in JSON |
| `securityhub:GetFindings` | `arn:aws:securityhub:REGION:ACCOUNT:hub/default` | hub default; `Findings[].ProductArn` on batch import/update |
| `apigatewayv2:GetApi` | `arn:aws:apigateway:REGION::/apis/id` | `ApiId` in JSON body |
| `codebuild:BatchGetProjects` | `arn:aws:codebuild:REGION:ACCOUNT:project/name` | `projectName` / `ProjectName` in JSON |
| `codedeploy:GetDeployment` | `arn:aws:codedeploy:REGION:ACCOUNT:deploymentgroup:app/group` | `applicationName`, `deploymentGroupName` in JSON |
| `acm:DescribeCertificate` | `arn:aws:acm:REGION:ACCOUNT:certificate/*` or full cert ARN | `CertificateArn` in JSON |
| `backup:DescribeBackupVault` | `arn:aws:backup:REGION:ACCOUNT:backup-vault:name` | `BackupVaultName`, vault ARNs, or path `/backup-vaults/` |
| `route53:GetHostedZone` | `arn:aws:route53:::hostedzone/id` | path `/hostedzone/` or `/healthcheck/` |
| `cloudfront:GetDistribution` | `arn:aws:cloudfront::ACCOUNT:distribution/id` | path `/2020-05-31/distribution/`; invalidation scopes to parent distribution |
| `bedrock:Converse` / `InvokeModel` | `arn:aws:bedrock:REGION::foundation-model/model-id` | path `/model/{modelId}/converse` or `/invoke` |
| `transfer:DescribeServer` | `arn:aws:transfer:REGION:ACCOUNT:server/id` | `ServerId` in JSON; `user/server/user` when `UserName` set |
| `transcribe:GetTranscriptionJob` | `arn:aws:transcribe:REGION:ACCOUNT:transcription-job/name` | `TranscriptionJobName` or `VocabularyName` (JSON) |
| `cur:PutReportDefinition` | `arn:aws:cur:REGION:ACCOUNT:definition/name` | `ReportName` or `ReportDefinition.ReportName` (JSON) |
| `bcm-data-exports:GetExport` | `arn:aws:bcm-data-exports:REGION:ACCOUNT:export/name` | `ExportArn` or `Export.Name` (JSON) |
| `appconfig:GetApplication` | `arn:aws:appconfig:REGION:ACCOUNT:application/id` | REST path `/applications/{id}` and nested env/profile paths |
| `appconfig:StartConfigurationSession` | `arn:aws:appconfig:REGION:ACCOUNT:application/.../configuration/...` | `ApplicationIdentifier`, `EnvironmentIdentifier`, `ConfigurationProfileIdentifier` (JSON) |
| `textract:GetDocumentTextDetection` | `arn:aws:textract:REGION:ACCOUNT:job/id` | `JobId` (JSON); sync detect APIs use `*` per AWS |
| `tagging:TagResources` | caller `ResourceARNList[]` ARNs | Floci evaluates each listed ARN (multi-ARN deny like EMR); AWS SAR uses `*` |

**AWS-intentional `*` (no per-resource ARN in IAM):** `pricing` / `api.pricing`, `ce` query APIs, `ec2messages` (use condition keys on instance ARN). List-only APIs (`List*`, `DescribeReportDefinitions`, `ListExports`) use service wildcards where AWS does, including `sqs:ListQueues`.

**Secrets Manager + KMS (single-layer envelopes):** When a CMK is attached, plaintext is encrypted once into base64 `SecretBinary` (`kms:v2:` wire format). Inputs that are already KMS ciphertext (raw UTF-8 or base64-wrapped `kms:v2:` / `kms:` blobs) are stored without re-wrapping. `kms:Decrypt` unwraps nested legacy envelopes (depth cap) so one call yields application plaintext. See [secrets-manager.md](./docs/services/secrets-manager.md#kms-wrapped-secretbinary).

**EMR `JobFlowIds[]` multi-cluster evaluation:** `TerminateJobFlows` and similar calls with multiple `JobFlowIds[]` entries build one cluster ARN per ID (`ResourceArnBuilder.buildAllEmrClusterResources`). `IamEnforcementFilter` evaluates identity policy against every derived ARN; explicit Deny on any cluster denies the request.

**Resource policies:** S3, Lambda, SQS, SNS, KMS, Secrets Manager, and EventBridge bus policies merge on HTTP (identity OR resource Allow; explicit Deny wins). Account `:root` in a resource policy does **not** authorize every IAM user. With IAM enforcement on, SNS topics get **no** open default topic policy.

**Not on HTTP:** in-process Step Functions / API Gateway integrations, Cognito OAuth (`/oauth2/*`). S3 presigned POST bypasses `IamEnforcementFilter` missing-auth; `S3Controller` validates policy conditions and SigV4 policy signature when form fields are present.

**In-process IAM:** When `floci.services.iam.enforcement-enabled=true`, `InProcessIamAuthorizer` always denies SFN/APIGW JSON-body calls without an execution role (state machine `roleArn` or integration `credentials`). `InProcessTargetAuthorizer` covers delivery paths: Pipes/Scheduler/EventBridge, SNS/S3/SES notifications, Lambda ESM pollers, Logs subscriptions (filter `roleArn` for Kinesis/Firehose), ELB/API Gateway/Cognito/CodeDeploy Lambda invoke, service S3 delivery (CloudTrail, Config, Firehose, VPC flow logs), and CUR/BCM Parquet emit. Strict mode is not required for the missing-role check; when a role or service principal is present, identity and resource policies are evaluated like HTTP.

---

## CTF implementation map

| Area | Primary files |
|------|---------------|
| HTTP IAM + SigV4 | `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths`, `OperatorCredentialEnv`, `AnonymousAccessGate` |
| Account context | `AccountResolver`, `AccountContextFilter`, `RegionResolver` (presigned `X-Amz-Credential`, 12-digit AKID, STS session keys) |
| Identity policies | `IamPolicyEvaluator`, `IamActionRegistry`, `IamService`, `ResourceArnBuilder` |
| Resource policies | `ResourcePolicyResolver`, `PolicyPrincipalMatcher` |
| STS / federated trust | `StsQueryHandler`, `AssumeRoleTrustPolicyEvaluator`, `FederatedTokenParser`, `SamlAssertionSignatureVerifier`, `PolicyPrincipalMatcher` |
| S3 SigV4 presign | `PreSignedUrlGenerator`, `PreSignedUrlFilter`, `SigV4RequestValidator`, `SigV4aPresignSupport`, `SigV4aPublicKeyResolver` |
| API Gateway integrations | `ApiGatewayExecuteController`, `AwsServiceRouter` (JSON credentials for IAM; path-style SQS query `invokeQuery` + Lambda path invoke; CloudTrail audit on query integrations) |
| Scoped IAM ARNs | `IamActionRegistry`, `ResourceArnBuilder`, `SnsService`, `SecretsManagerKmsSupport` |
| KMS grants (HTTP) | `KmsService.isGrantAuthorized`, `IamEnforcementFilter` grant fallback |
| In-process IAM | `InProcessIamAuthorizer`, `InProcessTargetAuthorizer`, `AslExecutor` (SFN aws-sdk KMS/Secrets/S3), `AwsServiceRouter`, `Integration.credentials` |
| In-process CloudTrail audit | `InProcessCloudTrailRecorder`, `CloudTrailEventRecorder` (SQS `queueUrl` from Query form and JSON 1.0/1.1 bodies), wired in SFN/APIGW/EventBridge/SNS/Firehose/Config/EC2 flow logs |
| Cognito OAuth gate | `SecurityBypassPaths`, `IamEnforcementFilter` (OAuth paths exempt SigV4; Bearer cannot bypass data plane) |
| Federated STS gate | `SecurityBypassPaths.isFederatedStsAssumeRequest`, `IamEnforcementFilter` (unsigned WebIdentity/SAML form posts skip strict missing-auth; trust in `StsQueryHandler`) |
| EKS token webhook | `EksTokenValidator`, `EksTokenWebhookController` |
| Containers | `LaunchedContainerAwsEnv`, `OperatorCredentialEnv`, `ContainerEnvHardening`, `ContainerCredentialsHttpServer`, `ContainerLauncher`, `LambdaContainerCredentialsServer`, `EcsContainerManager`, `EcsContainerCredentialsServer`, `CodeBuildContainerCredentialsServer`, `CodeBuildRunner`; regressions `LaunchedContainerAwsEnvTest`, `ContainerLauncherTest`, `EcsContainerManagerAwsBaselineTest`, `LambdaContainerCredentialsIamIntegrationTest`, `EcsContainerCredentialsIamIntegrationTest`, `CodeBuildContainerCredentialsServerTest` |
| Internal routes | `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode` |
| Compose / image | `docker-compose.yml`, `docker/Dockerfile` (no `test`/`test`) |
| RDS Data API | `RdsDataController`, `RdsDataService`, `RdsDataConnectionFactory`, `RdsDataResourceResolver`, `RdsDataFieldMapper` |
| EMR | `EmrHandler`, `EmrService`, `services/emr/model/*` |
| WAFv2 | `WafV2Handler`, `WafV2Service`, `services/wafv2/model/*` |

**Do not assume:** `IamAuthorizationService`, `StsCallerGuard` exist as separate classes (HTTP enforcement is in `IamEnforcementFilter`).

**Known gaps (prioritize next):**

- CloudFormation provisioner IAM gates privileged create APIs, not every privilege path or resource type.
- WebSocket IAM is enforced at `$connect` (AWS-shaped). Later routes rely on the established connection.

**Recently closed (CTF security / test stability):**

| Gap | Status | Regression |
|-----|--------|------------|
| SigV4 `Credential=` smuggling without `AWS4-HMAC-SHA256` prefix | Closed | `SigV4CredentialSmugglingBypassIntegrationTest` |
| Blank Lambda `Role` / CodeBuild `serviceRole` injects operator `AWS_*` under enforcement | Closed | `LambdaBlankRoleOperatorCredentialIntegrationTest`, `CodeBuildBlankServiceRoleIntegrationTest`, `ContainerLauncherTest` |
| `PolicyPrincipalMatcher` service principal substring (non-SLR assumed-role session) | Closed | `PolicyPrincipalMatcherTest` |
| Duck / Athena / S3 Select uses operator S3 keys under IAM enforcement | Closed | `AthenaDuckOperatorS3BypassIntegrationTest` |
| In-process IAM gaps (IoT rules, Secrets rotation, CodePipeline, CFN `Custom::`, SFN `ecs:runTask` + ItemReader S3) | Closed | `InProcessTargetAuthorizerTest` |
| ASIA session account not used for IAM resource ARNs | Closed | `IamEnforcementFilterTest` |
| S3 route-scope overclaim exclusions incomplete | Closed | `IamActionRegistryTest` (exclude `/lambda-url`, not `/lambda` prefix, so buckets like `lambda-*` stay S3-scoped) |
| EventBridge `StartReplay` allows cross-bus destination | Closed | `EventBridgeReplayIntegrationTest` |
| RDS Data database name JDBC URL injection | Closed | `RdsDataConnectionFactoryTest` |
| JSON 1.1 SigV4 credential scope vs `X-Amz-Target` service split | Closed | `IamJson11CredentialScopeSplitIntegrationTest` |
| Kinesis `POST .*` catch-all mis-routing IAM on unrelated REST paths | Closed | `IamKinesisCatchAllRouteScopeIntegrationTest` |
| APIGW path-style SQS `invokeQuery` bypassing in-process IAM | Closed | `ApiGatewaySqsQueryIamBypassIntegrationTest` |
| EC2 Network ACL Query API handlers missing | Closed | `Ec2IntegrationTest` network ACL tests |
| Presigned POST/GET operator root secret shadowed by stale IAM key | Closed | `S3PresignedPostIntegrationTest`, `PreSignedUrlIntegrationTest`, `PreSignedUrlRootSecretPrecedenceIntegrationTest` |
| SigV4 validation (wrong secret, tampered auth, ASIA without session token) | Closed | `SigV4ValidationFilterIntegrationTest` |
| `PreSignedUrlFilter` unknown AKIA and expired presigned GET | Closed | `PreSignedUrlFilterIntegrationTest` |
| `SecurityBypassPaths` internal, OAuth, and presigned POST classification | Closed | `SecurityBypassPathsTest` |
| `OperatorCredentialEnv` blank-skip and snapshot helpers | Closed | `OperatorCredentialEnvTest` |
| `GetCallerIdentity` caller ARN (IAM user, assumed role, operator root) | Closed | `StsGetCallerIdentityIntegrationTest` |
| Presigned S3 GET identity-policy deny after signature verification | Closed | `IamEnforcementPresignedS3DenyIntegrationTest` |
| Presigned S3 GET bucket-policy deny after signature verification | Closed | `S3PresignedBucketPolicyDenyIntegrationTest` |
| SNS no default topic policy when IAM enforcement is on | Closed | `SnsTopicNoDefaultPolicyIntegrationTest` |
| SNS topic `:root` principal does not authorize arbitrary IAM users | Closed | `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest` |
| SQS resource-policy-only Allow (no identity policy) | Closed | `SqsResourcePolicyOnlyAllowIntegrationTest` |
| Secrets Manager rotation must not double-wrap KMS ciphertext | Closed | `SecretsManagerRotationKmsIntegrationTest` |
| Scoped IAM for `codebuild`, `codedeploy`, `acm`, `backup`, `route53` | Closed | `CodeBuildIamScopedIntegrationTest`, `CodeDeployIamScopedIntegrationTest`, `AcmIamScopedIntegrationTest`, `BackupIamScopedIntegrationTest`, `Route53IamScopedIntegrationTest` |
| ECS task container credentials IAM-scoped S3 access | Closed | `EcsContainerCredentialsIamIntegrationTest` |
| CodeBuild container credentials server lifecycle and URIs | Closed | `CodeBuildContainerCredentialsServerTest` |
| Lambda Runtime API port `9200` bind conflicts in full test suites | Closed | `PortAllocatorTest`, `LambdaReactiveSyncIntegrationTest` |
| Windows Docker socket / TLS cert paths / ZIP backslash extraction | Closed | `DockerClientProducerTest`, `TlsIntegrationTest`, `ZipExtractorTest` |
| SQS `ReceiveMessage` scoped IAM (JSON 1.0 `QueueUrl`) | Closed | `SqsReceiveMessageScopedQueueIntegrationTest` |
| Secrets Manager path-prefix IAM wildcards (`secret:path/*`) | Closed | `SecretsManagerGetSecretValueScopedArnIntegrationTest`, `ResourceArnBuilderTest` |
| Secrets Manager single-layer KMS `SecretBinary` envelope | Closed | `SecretsManagerKmsEnvelopeIntegrationTest`, `SecretsManagerKmsSupportTest` |
| S3 / APIGW / Lambda anonymous access under strict IAM | Closed | `S3PublicBucketPolicyAnonymousGetIntegrationTest`, `ApiGatewayNoneAuthAnonymousInvokeIntegrationTest`, `LambdaFunctionUrlNoneAuthIntegrationTest` |
| `AnonymousAccessGate` bypass regressions (private S3, `AWS_IAM` APIGW/Lambda URL, `NONE` URL without resource policy) | Closed | `AnonymousAccessGateBypassIntegrationTest` |
| API Gateway deploy + stage lifecycle | Closed | `ApiGatewayDeploymentAndTestInvokeIntegrationTest` |
| API Gateway `TestInvokeMethod` without stage deploy | Closed | `ApiGatewayDeploymentAndTestInvokeIntegrationTest` |
| API Gateway `TestInvokeMethod` with `AWS_PROXY` Lambda integration | Closed | `ApiGatewayDeploymentAndTestInvokeIntegrationTest` |
| Lambda APIGW invoke `SourceArn` resource policy | Closed | `ApiGatewayLambdaSourceArnPermissionIntegrationTest` |
| Lambda execution-role creds on Compose bridge (link-local `extra_hosts`, explicit port in `FULL_URI`, no `RELATIVE_URI` on 9171) | Closed | `ContainerLauncherTest`, `ContainerCredentialsUriBuilderTest`, `ContainerCredentialsHostSetupTest`, `LambdaContainerCredentialsIamIntegrationTest` |
| ECR registry reconcile on Compose bridge (`5100` published, adopt path backend port, `list-images` after host `docker push`) | Closed | `EcrDockerPushIntegrationTest`, `EcrRegistryManagerTest` |
| STS `AssumeRole` same-account caller identity (trust-only unless explicit Deny) | Closed | `StsAssumeRoleCallerIdentityPolicyIntegrationTest`, `AssumeRoleTrustPolicyIntegrationTest` |
| IAM policy glob matching exponential backtracking DoS | Closed | `IamPolicyEvaluatorTest`, `IamEnforcementIntegrationTest` |
| Predictable IAM/STS/container credentials from `ThreadLocalRandom` | Closed | `IamService`, `StsQueryHandler`, `ContainerCredentialsHttpServer`, `Ec2MetadataServer`, `EcsContainerCredentialsServer` (`SecureRandom`) |
| KMS `GenerateDataKey` / grant tokens from `ThreadLocalRandom` | Closed | `KmsService` (`secureRandom`) |
| Presigned POST unknown condition operators fail-closed | Closed | `S3PresignedPostIntegrationTest` |
| OIDC multi-value `aud` trust conditions + federated `nbf`/SAML sig floor | Closed | `FederatedTokenParserTest`, `AssumeRoleTrustPolicyEvaluatorTest`, `StsWebIdentityTrustIntegrationTest` |
| EKS `k8s-aws-v1.*` token SigV4 verify on presigned STS GetCallerIdentity | Closed | `EksTokenSigV4IntegrationTest`, `EksTokenValidatorTest` |
| STS federated `InvalidIdentityToken`, SAML response fidelity, trust Deny, SAML expiry | Closed | `StsWebIdentityTrustIntegrationTest`, `FederatedTokenParserTest`, `AssumeRoleTrustPolicyEvaluatorTest` |
| IoT / iotdata IAM action mapping (strict mode unmapped-action deny) | Closed | `IotIamScopedIntegrationTest`, `LambdaContainerCredentialsIamIntegrationTest`, `IamActionRegistryTest`, `ResourceArnBuilderTest` |
| STS `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML` form post without SigV4 under strict IAM (filter bypass) | Closed | `SecurityBypassPathsTest` |
| STS federated crypto required under IAM strict / Compose CTF (unsigned deny) | Closed | `StsWebIdentityStrictUnsignedIntegrationTest` |
| SAML XSW: unsigned forged Assertion before signed Assertion | Closed | `SamlWrappedAssertionRejectedTest`, `SamlAssertionSignatureVerifierTest` |
| STS `AssumeRole` missing role ASIA mint under IAM strict | Closed | `StsAssumeRoleMissingRoleStrictIntegrationTest` |
| ECR repository policy on control-plane IAM (`DescribeRepositories` scoped ARN) | Closed | `EcrRepositoryPolicyControlPlaneIntegrationTest`, `ResourcePolicyResolverTest`, `ResourceArnBuilderTest` |
| Multi-table PartiQL `ExecuteStatement` IAM (JOIN / multiple FROM targets) | Closed | `DynamoDbExecuteStatementScopedIntegrationTest`, `ResourceArnBuilderTest` |
| `BatchExecuteStatement` per-statement table ARN scoping | Closed | `DynamoDbBatchExecuteStatementScopedIntegrationTest` |
| In-process KMS grant fallback (`InProcessIamAuthorizer`) | Closed | `InProcessIamAuthorizerTest` |
| SigV4a presign ECDSA-P256 verification (GET query URLs + POST policy) | Closed | `SigV4aPresignSupportTest`, `SigV4aPresignedUrlIntegrationTest`, `S3PresignedPostIntegrationTest` |
| SAML assertion XML-DSig against pinned IdP metadata PEMs | Closed | `SamlAssertionSignatureVerifierTest`, `StsSamlSignatureValidationIntegrationTest`, `FederatedTokenParserTest` |
| ECR docker push/pull IAM via registry auth proxy (`/v2/*`) | Closed | `EcrRegistryAuthServiceTest`, `EcrRegistryRouteResolverTest`, `EcrRegistryPolicyDataPlaneIntegrationTest` |
| Presigned POST `in` / `not-eq` condition operators | Closed | `S3PresignedPostIntegrationTest` |
| Container path sandboxing | Closed | ECS host volumes require explicit allowed roots, Lambda hot-reload requires an allowlist, CodeBuild artifacts remain in the workspace, and S3 validates bucket names before filesystem use |
| Outbound private-address HTTP destinations | Closed | `OutboundUrlGuard` on SNS HTTP(S), API Gateway HTTP proxy integrations (REST and WebSocket after stage-var substitution), HTTP API JWT JWKS/OIDC fetches, and ALB IP or hostname targets (`OutboundUrlGuardTest`, `HttpProxyInvokerTest`, `JwtAuthorizerVerifierTest`, `WebSocketIntegrationInvokerSubstitutionTest`) |
| HTTP API JWT authorizer signature checks | Closed | Unsigned and `alg=none` tokens are rejected. HS256 uses the CTF HMAC secret when set (`JwtAuthorizerVerifierTest`) |
| KMS symmetric encrypt envelope authenticity | Closed | New ciphertext uses authenticated AES-GCM (`kms:v3:`). Legacy `kms:v2:` and `kms:` envelopes remain decryptable (`KmsServiceTest`, `SecretsManagerKmsEnvelopeIntegrationTest`) |
| KMS Decrypt KeyId vs CiphertextBlob binding | Closed | IAM scopes Decrypt to the blob CMK, mismatched KeyId returns `IncorrectKeyException` (`KmsDecryptScopedKeyIntegrationTest`, `ResourceArnBuilderTest`) |
| SAML assertion XML DOCTYPE / entity expansion | Closed | `SamlAssertionSignatureVerifier` rejects DOCTYPE and external entities (`SamlAssertionSignatureVerifierTest`) |
| Cognito inbound access-token signature checks | Closed | Self-service APIs and userInfo verify RS256 against the pool signing key (`CognitoUserInfoIntegrationTest`, `GlobalSignOutIntegrationTest`) |
| S3 POST and bucket sub-resource IAM mapping | Closed | `IamActionRegistry` maps `DeleteObjects`, multipart POST, and `?policy`/`?acl`/`?lifecycle` (and related) to the correct `s3:*` actions (`IamActionRegistryTest`) |
| HTTP API JWT JWKS / OIDC fetch SSRF | Closed | `JwtAuthorizerVerifier` calls `OutboundUrlGuard` before JWKS and discovery GETs (`JwtAuthorizerVerifierTest`) |
| IAM `ForAllValues:` / `ForAnyValue:` set operators | Closed | `IamPolicyEvaluator` evaluates multi-value condition operators (`IamPolicyEvaluatorTest`) |
| TagResources non-ARN entries treated as `*` | Closed | Tagging path skips non-ARN `ResourceARNList` entries instead of falling back to `*` (`TaggingIamScopedIntegrationTest`, `IamEnforcementFilterTest`) |
| Scheduler universal target ARN under-scope | Closed | `ScheduleInvoker` authorizes the concrete target ARN (`ScheduleInvokerTest`) |
| REST CUSTOM authorizer Statement under-eval | Closed | `ApiGatewayExecuteController` evaluates all policy Statements (`IamEnforcementFilterTest` / APIGW execute path) |
| Cognito userInfo ignores revoked tokens | Closed | `CognitoUserInfoController` rejects revoked access tokens (`CognitoUserInfoIntegrationTest`) |
| Inactive IAM access keys still authenticate | Closed | `IamService.findSecretKey` ignores inactive keys (`IamServiceTest`) |
| Cognito unknown `AuthFlow` issues tokens | Closed | `CognitoAuthFlowHandler` rejects unrecognized flows (`CognitoAuthFlowHandlerTest`) |
| S3 CopyObject / UploadPartCopy source IAM | Closed | Second evaluation of `s3:GetObject` (or versioned Get) on the copy source (`IamEnforcementFilterTest`) |
| Missing `aws:RequestedRegion` / `aws:CurrentTime` / `aws:EpochTime` | Closed | `buildConditionContext` populates these keys (`IamEnforcementFilterTest`, `IamConditionContextResolverTest`) |
| `iam:PassRole` missing on create paths | Closed | PassRole checked when creating SFN / Scheduler / Pipes / Lambda resources that take a role (`IamEnforcementFilterTest`, related service tests) |
| CloudFormation TemplateURL S3 IAM gap | Closed | Template fetch evaluates caller S3 IAM (`CloudFormationIntegrationTest`) |
| S3 `BypassGovernanceRetention` without IAM | Closed | Object lock bypass requires `s3:BypassGovernanceRetention` (`S3BypassGovernanceRetentionIamIntegrationTest`) |
| WebSocket `$connect` without SigV4 / IAM | Closed | `$connect` requires SigV4 and IAM when enforcement is on (`WebSocketConnectIamGateIntegrationTest`) |
| CloudFormation provisioner create IAM gates | Closed | Privileged create APIs gated via in-process IAM (`CloudFormationResourceProvisionerIamGateTest`). Residual: not every CFN resource type is gated |
| EventBridge bus resource policies ignored | Closed | `ResourcePolicyResolver` loads `events` bus policies (`ResourcePolicyResolverTest`) |
| EventBridge `PutEvents` bus ARN under-scope | Closed | Per-entry `EventBusName` ARNs via `ResourceArnBuilder` (`ResourceArnBuilderTest`) |
| Lambda `CreateEventSourceMapping` function ARN under-scope | Closed | `FunctionName` from JSON body scopes IAM (`ResourceArnBuilderTest`) |
| CloudWatch Logs `StartQuery` multi-group under-scope | Closed | Each `logGroupNames` entry is evaluated (`ResourceArnBuilderTest`, Logs handler tests) |
| DynamoDB Streams `StreamArn` under-scope | Closed | Streams APIs use `StreamArn` (TableName still preferred when both present) (`ResourceArnBuilderTest`) |
| IoT MQTT CONNECT / topic IAM | Closed | Real CONNECT auth plus topic IAM when enforcement is on (`IotMqttBrokerServiceTest`, `IotMqttConnectAuthPolicyTest`) |
| IoT MQTT AKID password not bound to secret | Closed | Password must match stored secret access key (or root secret); mismatch/missing secret fails closed (`MqttPasswordMustMatchSecretTest`). Residual: full MQTT SigV4 / `iot:Connect` parity out of scope |
| CodeDeploy lifecycle AccessDenied completed as Succeeded | Closed | Hook invoke AccessDenied fails the lifecycle event (`CodeDeployHookDenyFailsDeploymentTest`) |
| Pipes Lambda enrichment IAM | Closed | Enrichment invoke uses `InProcessTargetAuthorizer` (`PipesTargetInvokerTest`) |
| Pipes Kafka source IAM | Closed | Kafka poll path authorizes via `InProcessTargetAuthorizer` (`PipesPollerTest`) |
| DynamoDB BatchWrite/Get and Transact wildcard fallback | Closed | Multi-table / nested table ARNs evaluated (`ResourceArnBuilderTest`, DynamoDB handler tests) |
| Secrets Manager `BatchGetSecretValue` multi-secret IAM | Closed | Each secret id evaluated (`ResourceArnBuilderTest`, Secrets Manager tests) |
| WebSocket HTTP_PROXY after stage-var substitution | Closed | `OutboundUrlGuard` runs on the resolved URL (`WebSocketIntegrationInvokerSubstitutionTest`) |

**Configuration reference:** [docs/configuration/environment-variables.md](./docs/configuration/environment-variables.md#ctf-hardening), [docs/configuration/advanced/application-yml.md](./docs/configuration/advanced/application-yml.md#ctf-fork-settings).

---

## Audit services map

Compose audit defaults (in addition to CTF security env): `FLOCI_STORAGE_MODE=hybrid`, `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`.

**Instance-keyed grading:** Audit exercises grade live `lookup-events` output with provision-time `answers.json` fields (`eventTime`, `accessKeyId`, `VersionId`). Authoring detail: [docs/services/cloudtrail.md#live-audit-authoring](./docs/services/cloudtrail.md#live-audit-authoring).

| Area | Primary files / docs |
|------|----------------------|
| CloudTrail trail lifecycle | `CloudTrailService`, `CloudTrailJsonHandler`, [docs/services/cloudtrail.md](./docs/services/cloudtrail.md) |
| CloudTrail audit recording | `CloudTrailAuditFilter`, `CloudTrailAuditRequestFilter`, `CloudTrailAuditCoordinator`, `InProcessCloudTrailRecorder`, `CloudTrailEventRecorder`, `CloudTrailDeliveryService`, `CloudTrailEventStore` |
| CloudTrail operator injection | `CloudTrailEventInjectionController`, `CloudTrailEventInjectionService` (`FLOCI_CTF_CLOUDTRAIL_INJECTION_ENABLED`) |
| CloudTrail audit config | `EmulatorConfig.CloudTrailServiceConfig` (`audit-enabled`, `exclude-internal-paths`) |
| Config delivery / snapshots | `ConfigSnapshotDeliveryService`, `AwsConfigService`, [docs/services/config.md](./docs/services/config.md) |
| S3 access logging | `S3AccessLogService`, `S3AccessLogFormatter`, [docs/services/s3.md](./docs/services/s3.md#access-logging) |
| VPC Flow Logs | `Ec2FlowLogEmitter`, `Ec2Service`, `VpcFlowLogRecordFormatter` |
| CloudWatch Logs subscriptions | `CloudWatchLogsSubscriptionDispatcher` |
| GuardDuty detectors / findings | `GuardDutyService`, `GuardDutyCloudTrailHook`, [docs/services/guardduty.md](./docs/services/guardduty.md) |
| Security Hub ASFF import | `SecurityHubService`, `GuardDutyFindingSubscriber`, [docs/services/securityhub.md](./docs/services/securityhub.md) |
| Persistent exercise state | `StorageFactory`, `HybridStorage`, `./data` volume in `docker-compose.yml` |
| In-process CloudTrail audit | `InProcessCloudTrailRecorder`, `InProcessAuditContext`; SFN/APIGW/EventBridge/SNS/Firehose/Config/EC2/S3 access logs |
| E2E audit scenario | `CloudForensicsIntegrationTest`, `InProcessCloudTrailIntegrationTest`, `InternalServiceCloudTrailIntegrationTest`, `ForensicLabProfile` |
| SDK compatibility probes | [compatibility-tests/sdk-test-java](./compatibility-tests/sdk-test-java) (`ForensicLabCompatibilityTest`) |

**Audit regression (unit/integration):**

```bash
./mvnw test -Dtest=AssumedRoleAccountRoutingIntegrationTest,AccountContextFilterTest,IamServiceTest,CloudForensicsIntegrationTest,CloudTrailIntegrationTest,CloudTrailAuditIntegrationTest,CloudTrailTamperingAuditIntegrationTest,CloudTrailIamScopedIntegrationTest,CloudTrailLookupEventsScopedIamIntegrationTest,CloudTrailSqsAuditIntegrationTest,CloudTrailKmsDecryptAuditIntegrationTest,CloudTrailSnsPublishAuditIntegrationTest,CloudTrailDynamoDbPutItemAuditIntegrationTest,CloudTrailS3DeliveryIntegrationTest,CloudTrailFieldFidelityIntegrationTest,CloudTrailEventInjectionIntegrationTest,CloudTrailEventInjectionDisabledIntegrationTest,InProcessCloudTrailIntegrationTest,InternalServiceCloudTrailIntegrationTest,CloudTrailLookupEventsIntegrationTest,ConfigSnapshotDeliveryIntegrationTest,S3AccessLoggingIntegrationTest,S3AccessLogScheduledDeliveryIntegrationTest,S3AccessLogDeliveryIamIntegrationTest,S3AccessLogFormatterTest,S3AccessLogSourceIpParityIntegrationTest,S3AccessLogKeyBuilderTest,Ec2FlowLogsIntegrationTest,CloudWatchLogsSubscriptionIntegrationTest,GuardDutyIntegrationTest,SecurityHubIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbPutItemScopedIntegrationTest,SnsPublishScopedIamIntegrationTest,ClientSourceIpResolverTest
```

**Audit compatibility (running instance):**

```bash
cd compatibility-tests && just test-forensic-java
```

Requires `FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true` on the emulator (Compose default) and operator or IAM credentials in `.env`.

**Audit gaps closed on `floci:local`:**

| Gap | Status | Regression / doc |
|-----|--------|------------------|
| `cloudtrail:LookupEvents` IAM scoping | Closed | `CloudTrailLookupEventsScopedIamIntegrationTest`; [cloudtrail.md](./docs/services/cloudtrail.md#ctf-fork-notes) |
| `cloudtrail:StopLogging` audit + history | Closed | `CloudTrailTamperingAuditIntegrationTest` |
| `sourceIPAddress` authoring hooks | Closed | `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` + `X-Forwarded-For`; alternate `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER`; [Live audit authoring](./docs/services/cloudtrail.md#live-audit-authoring) |
| SQS `ListQueues` IAM deny shape | Closed | `SqsListQueuesIamIntegrationTest`; IAM runs before service-disabled short-circuit |
| SQS audit (`ReceiveMessage`, `SendMessage`, `PurgeQueue`) with `requestParameters.queueUrl` | Closed | Query and JSON 1.0 protocols; `CloudTrailSqsAuditIntegrationTest` |
| SQS `SendMessage` audit `requestParameters.messageBody` | Closed | Actual payload recorded (not redacted); `CloudTrailSqsAuditIntegrationTest` |
| Trail S3 delivery `aws:SourceArn` and `s3:x-amz-acl` bucket policy | Closed | `cloudtrail.amazonaws.com` `s3:PutObject` honors trail ARN and `bucket-owner-full-control` ACL conditions; `CloudTrailS3DeliveryIntegrationTest` |
| S3 `ListObjectsV2` audit `eventName` | Closed | `?list-type=2` records `ListObjectsV2` (not `ListBucket`); `CloudTrailFieldFidelityIntegrationTest`, `CloudTrailEventRecorderTest` |
| `GetEventSelectors` with defaults | Closed | `CloudTrailIntegrationTest`; [cloudtrail.md](./docs/services/cloudtrail.md#trail-lifecycle) |
| `lookup-events` tail visibility under concurrent audit | Closed | `LookupEvents` awaits in-flight HTTP audit recordings; `CloudTrailAuditCoordinator` |
| `ListAllMyBuckets` vs bucket-scoped audit ordering | Closed | Request-arrival `eventTime` plus monotonic index timestamps; `CloudTrailFieldFidelityIntegrationTest` |
| `lookup-events` pagination, `eventTime` precision, same-second order | Closed | Millisecond `eventTime`; insertion order within same second; `CloudTrailFieldFidelityIntegrationTest`, `CloudTrailLookupEventsIntegrationTest`; [LookupEvents](./docs/services/cloudtrail.md#lookupevents) |
| Presigned GET (SigV4 query URLs) | Closed | `PreSignedUrlCtfIntegrationTest`, `SigV4RequestValidatorTest`, `PreSignedUrlFilterIntegrationTest`; header fallback for signed `x-amz-*` |
| Presigned GET IAM identity deny and bucket-policy deny after sig verify | Closed | `IamEnforcementPresignedS3DenyIntegrationTest`, `S3PresignedBucketPolicyDenyIntegrationTest` |
| Presigned POST under strict IAM | Closed | `S3PresignedPostCtfIntegrationTest`; policy expiration; no unauthenticated multipart bypass |
| `GetSessionToken` session-policy intersection | Closed | Pure `(identity OR resource) AND session` in `IamPolicyEvaluator`; `StsGetSessionTokenIntersectionIntegrationTest`, `IamEnforcementIntegrationTest` |
| `additionalEventData` / `tlsDetails` on HTTP audit | Closed | SigV4 auth metadata; TLS when `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` + `X-Forwarded-Proto: https`; `CloudTrailEventRecorderTest` |
| Per-instance event index isolation | Documented | `CloudTrailEventStore` teardown in [Live audit authoring](./docs/services/cloudtrail.md#cloudtraileventstore-lifecycle-and-teardown) |
| Operator event injection API | Closed | `CloudTrailEventInjectionIntegrationTest`; [cloudtrail.md](./docs/services/cloudtrail.md#operator-event-injection-api) |
| SNS fan-out E2E | Closed | `SnsSubscribeReceiveIamIntegrationTest.fanOutWithExplicitTopicAndQueueResourcePolicies`; [sns.md](./docs/services/sns.md#ctf-fork-sns-to-sqs-fan-out-closed) |
| SNS no default topic policy under IAM enforcement | Closed | `SnsTopicNoDefaultPolicyIntegrationTest`; `:root` principal does not authorize IAM users: `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest` |
| SQS resource-policy-only Allow (identity policy absent) | Closed | `SqsResourcePolicyOnlyAllowIntegrationTest` |
| `iam:CreatePolicyVersion` timing | Closed | `CreatePolicyVersionGrantsSecretReadIntegrationTest`; [iam.md](./docs/services/iam.md#managed-policy-version-timing) |
| KMS single-layer `SecretBinary` envelope | Closed (AWS-aligned) | No double-wrap; one `kms:Decrypt` yields plaintext; pre-wrapped and accidental double-base64 normalized; rotation `PutSecretValue` does not re-wrap KMS ciphertext; `SecretsManagerKmsEnvelopeIntegrationTest`, `SecretsManagerKmsSupportTest`, `SecretsManagerRotationKmsIntegrationTest`; [secrets-manager.md](./docs/services/secrets-manager.md#kms-wrapped-secretbinary) |
| SQS JSON 1.0 `ReceiveMessage` scoped IAM | Closed (AWS-aligned) | `ResourceArnBuilder.buildSqsArn` reads JSON `QueueUrl`/`QueueName`; `SqsReceiveMessageScopedQueueIntegrationTest` |
| Secrets Manager path-prefix IAM wildcards | Closed (AWS-aligned) | Use `secret:path/*` not `secret:path-*`; stored ARN suffix; `SecretsManagerGetSecretValueScopedArnIntegrationTest`, `ResourceArnBuilderTest` |
| API Gateway VTL ProcessBuilder RCE | Closed | `CtfVelocityEngineFactory` + `SecureUberspector`; `VtlProcessBuilderSandboxTest` |
| API Gateway IAM scope-to-route mismatch | Closed | `IamActionRegistry.resolveRestRouteScope`; `ApiGatewayIamScopeBypassIntegrationTest` |
| API Gateway data-plane IAM (`execute-api:Invoke`) | Closed | `execute-api` / `_user_request_` rules; `ApiGatewayExecuteApiScopeIntegrationTest` |
| JSON 1.1 SigV4 scope vs `X-Amz-Target` service split | Closed | `ResolvedServiceCatalog` target scope in `IamActionRegistry`; `IamJson11CredentialScopeSplitIntegrationTest` |
| REST route scope catch-all (`kinesis POST .*`) / missing `apigatewayv2` rules | Closed | Removed catch-all; `/v2/` rules + `isS3BucketStylePath`; `IamKinesisCatchAllRouteScopeIntegrationTest` |
| API Gateway path-style query integration in-process IAM | Closed | `AwsServiceRouter.invokeQuery(..., roleArn)` + `InProcessIamAuthorizer.authorizeQuery`; `ApiGatewaySqsQueryIamBypassIntegrationTest` |
| KMS `Decrypt` audit `requestParameters.keyId` (explicit KeyId or envelope blob) | Closed | `CloudTrailKmsDecryptAuditIntegrationTest`; [cloudtrail.md](./docs/services/cloudtrail.md#data-plane-requestparameters-http-audit) |
| SNS `Publish` audit `requestParameters.topicArn` | Closed | `CloudTrailSnsPublishAuditIntegrationTest` |
| DynamoDB `PutItem` audit `requestParameters.tableName` | Closed | `CloudTrailDynamoDbPutItemAuditIntegrationTest` |
| S3 access log Remote IP vs CloudTrail `sourceIPAddress` | Closed | Shared `ClientSourceIpResolver`; `S3AccessLogSourceIpParityIntegrationTest`; [s3.md](./docs/services/s3.md#access-logging) |
| `dynamodb:PutItem` scoped IAM | Closed | `DynamoDbPutItemScopedIntegrationTest` |
| `sns:Publish` scoped IAM | Closed | `SnsPublishScopedIamIntegrationTest` |

**Still open (downstream / out of emulator scope):** None from the prior SigV4a / SAML metadata / ECR data-plane / presigned POST operator backlog.

**Recently closed (S3 presign parity):**

| Gap | Status | Regression |
|-----|--------|------------|
| SSE query params on presigned PUT (data plane + generator) | Closed | `S3PresignedPutSseIntegrationTest`, `PreSignedUrlGeneratorTest`, `SigV4RequestValidatorTest` |
| ASIA session token required on presigned URLs | Closed | `PreSignedUrlFilterIntegrationTest` |

---

## Enforcement surfaces

| Surface | Hardened with Compose CTF env? |
|---------|-------------------------------|
| HTTP `:4566` | Yes (`SigV4ValidationFilter` + `IamEnforcementFilter`) |
| S3 presigned query URLs | Yes (`PreSignedUrlFilter` SigV4; IAM or root credential secrets only) |
| RDS / ElastiCache / MemoryDB Redis TCP | Partial (token SigV4, not full IAM per query) |
| Cognito OAuth | Partial (client credentials on `/oauth2/token`; Cognito Bearer cannot call SigV4 data plane) |
| SFN / APIGW AWS integrations in-process | Yes when enforcement on (`InProcessIamAuthorizer` on JSON-body calls); CloudTrail audit via `InProcessCloudTrailRecorder` when audit enabled |
| Pipes / Scheduler in-process | Yes (`InProcessTargetAuthorizer`: pipe/schedule `roleArn` on source poll with extended SQS/Kinesis/DynamoDB Streams actions, target delivery, SQS `DeleteMessage` on ack) |
| EventBridge rule targets / archive replay | Yes (`InProcessTargetAuthorizer`: rule `roleArn` or `events.amazonaws.com` destination policy; replay uses `events:PutEvents` on destination bus) |
| SNS / S3 / SES notification delivery | Yes (`InProcessTargetAuthorizer`: `sns.amazonaws.com`, `s3.amazonaws.com`, `ses.amazonaws.com` on destination resource policies) |
| Lambda ESM pollers (SQS/Kinesis/DynamoDB Streams) | Yes (function execution role on `ReceiveMessage` / `GetQueueAttributes` / `GetRecords` / `DescribeStream` / `DeleteMessage`) |
| CloudWatch Logs subscriptions | Yes (`logs.amazonaws.com` on Lambda; filter `roleArn` required for Kinesis/Firehose) |
| CUR / BCM Parquet emit | Yes (`bcm-data-exports.amazonaws.com` `s3:PutObject` on staging and destination; legacy CUR uses `billingreports.amazonaws.com` with `s3:PutObject` + `s3:GetBucketPolicy`) |
| ELB / API Gateway / Cognito / CodeDeploy Lambda invoke | Yes (`elasticloadbalancing.amazonaws.com`, `apigateway.amazonaws.com`, `cognito-idp.amazonaws.com`, `codedeploy.amazonaws.com` on function resource policy) |
| CloudTrail / Config / Firehose / VPC flow logs S3 delivery | Yes (`authorizeServiceS3Put` for CloudTrail and Config (`s3:ListBucket` for Config); Firehose stream `RoleARN` identity policy on `s3:PutObject`; VPC flow logs use `delivery.logs.amazonaws.com`) |
| Inter-service delivery audit | CloudTrail audit when audit enabled (`invokedBy` AWSService events on Firehose, Config, flow logs, and other in-process delivery) |
| Lambda / CodeBuild / ECS runtime creds | Yes when enforcement on (creds on 9171/9172/9170; link-local `169.254.170.2:PORT` in `AWS_CONTAINER_CREDENTIALS_FULL_URI` with auto `extra_hosts`; `AWS_CONTAINER_CREDENTIALS_RELATIVE_URI` omitted on non-80 ports so botocore uses the explicit port; `LambdaContainerCredentialsIamIntegrationTest`, `EcsContainerCredentialsIamIntegrationTest`, `ContainerLauncherTest`) |

**CTF defaults:** `src/main/resources/application.yml` keeps IAM/SigV4 off for local dev; Compose turns them on. Test `application.yml` disables enforcement globally; dedicated `@QuarkusTestProfile` overrides cover CTF paths.

---

## Upstream sync

**Latest merge:** upstream **main** (13 commits through **`fba4d8f5`**, release **1.5.33**, merged 2026-07-15): EKS managed node groups and Fargate profiles, lifecycle teardown for process-bound containers, fail-fast validation of unwritable persistent paths, S3 ACL headers and explicit grants, S3 `ListBucket` IAM context for `s3:prefix`, `s3:delimiter`, and `s3:max-keys`, Scheduler SNS `MessageAttributes`, duplicate `EC2 ImportKeyPair` rejection, ELBv2 target health reasons, CloudFormation SAM `PackageType` / `ImageConfig` and ECS container secrets, and RDS `DBSubnetGroupNotFoundFault`. **CTF preserved:** `ScheduleInvoker` `InProcessTargetAuthorizer`, `EmulatorLifecycle` teardown behavior, `Ec2ContainerManager` container credential and environment hardening, and `IamEnforcementFilter` with `IamConditionContextResolver`.

**Previous merge:** upstream **main** (6 commits through **`483cc5b1`**, post **1.5.32**, pom still **1.5.32**, merged 2026-07-12): Cognito `GlobalSignOut` / `RevokeToken` with `jti` / `origin_jti`, S3 `GetBucketEncryption` default SSE-S3 and `DeleteBucketReplication`, Step Functions JSONata `Assign` workflow variables, API Gateway `_user_request_` header-forwarding regression test. **CTF preserved:** Cognito `InProcessTargetAuthorizer` on delivery paths and `AslExecutor` `InProcessIamAuthorizer` with CloudTrail on in-process SDK tasks.

**Previous merge:** upstream **main** (23 commits through **`f93e0290`**, release **1.5.32**, merged 2026-07-11): Lightsail, S3 auth enforcement (`enforce-auth`), IAM `UserName` default from calling access key, ECS secrets resolution (SM/SSM) + awsvpc dynamic host ports, CloudFormation provisioner registry, AppSync Phase 5, SES Contact CRUD, KMS `ListAliases` KeyId filter, Secrets Manager batch partial results, TLS `host.docker.internal` SAN. **CTF preserved:** full `IamEnforcementFilter`. `PreSignedUrlFilter` SigV4. `EcsContainerManager` `ContainerEnvHardening` + credentials server + `LaunchedContainerAwsEnv`. `ScheduleInvoker` `InProcessTargetAuthorizer`. `SecretsManagerKmsSupport`. GuardDuty/SecurityHub alongside Lightsail/Cloud Control.

**Previous merge:** upstream **main** (40 commits through **`ebf5a2e8`**, release **1.5.31**, merged 2026-07-10): Lambda read-only code volumes, ECS env baseline via `LaunchedContainerAwsEnv`, CloudWatch Logs Insights, EventBridge Firehose targets, Scheduler ECS `RunTask`, RDS Data API, EC2 images/snapshots, Cloud Control API, SQS XML errors, Smithy protocol claiming. **CTF preserved:** full `IamEnforcementFilter`; `LaunchedContainerAwsEnv` uses `OperatorCredentialEnv` (no `test`/`test`); Lambda/ECS container credential servers + `ContainerEnvHardening`; `InProcessTargetAuthorizer` on Pipes/EventBridge/Scheduler/ELB; ECR auth-proxy `resolveRegistryBaseUrl`; Floci Duck operator creds only; GuardDuty/SecurityHub alongside upstream Cloud Control.

**Previous merge:** upstream **main** (23 commits through **`38bf55d3`**, release **1.5.30**, merged 2026-07-04): Amazon MQ (RabbitMQ), Firehose `ExtendedS3DestinationDescription` / `UpdateDestination`, SES v2 ContactList CRUD, IAM AWS-managed policy resolution across accounts, STS session-policy enforcement and origin-account session lookup, ECR published host port on adopt, tagging persistence, S3/SNS root service-host routing, reactive wire-protocol claiming, remove Rust SDK compat suite. **CTF preserved:** full `IamEnforcementFilter` (resource policies, anonymous gate, presigned, federated STS unsigned path, IoT/`iotdata` scoping); Firehose `RoleARN` for in-process S3 delivery IAM; ECR registry auth proxy adopt path; Compose audit profile (`hybrid` storage + CloudTrail audit) plus upstream TLS enablement; `ServiceEnabledFilter` IAM-before-disabled ordering.

**Previous merge:** upstream **main** (4 commits through **`7f76009c`**, merged 2026-07-01; still **1.5.29**): CloudWatch Logs monotonic ingestion sequence for same-timestamp events, ELBv2 void query `Result` envelope, Step Functions execution account routing (`AslExecutor`), IAM `AssumeRole` trust policy enforcement when enforcement enabled (`AssumeRolePolicyEvaluator`, `IamService.findRole`). **CTF preserved:** `StsQueryHandler` keeps `AssumeRoleTrustPolicyEvaluator` path (externalId + federated trust); unknown roles stay permissive via `findRole` skip; CloudWatch `subscriptionDispatcher` retained alongside upstream `ingestionSequence`; `AssumeRoleTrustPolicyIntegrationTest` uses registered IAM users (strict mode rejects unregistered AKIDs).

**Previous merge:** upstream **main** (7 commits through **`c496091a`**, merged 2026-06-30; release **1.5.29**): Step Functions `aws-sdk` CloudFormation/EC2/S3 PutObject integrations, state reset/nuke endpoints (`Resettable`, `/_floci/state/reset`), `AmazonRDSEnhancedMonitoringRole` managed policy, idempotent ECS delete on stack delete, SES v2 optional `FromEmailAddress`. **CTF preserved:** in-process IAM on new SFN service tasks (CloudFormation, EC2 `DescribeRegions`, optimized S3 `PutObject`); `DynamoDbStreamsEventSourcePoller` keeps `InProcessTargetAuthorizer` with upstream `Resettable`; Secrets/KMS/S3 `aws-sdk` SFN handlers and `authorizeTask` on nested state machines; CloudTrail cursor pagination; IAM/SigV4/strict Compose profile.

**Previous merge:** upstream **main** (3 commits through **`f52b9209`**, merged 2026-06-28; pom **1.5.28**): AppSync VTL engine Phase 4 (`AppSyncVtlEngine`, `#if`/`#foreach`/`#set`, `$util` error helpers), ELBv2 resolvable local ALB DNS names via `EmbeddedDnsServer`, IAM assumed-role credential account routing (`SessionAccountLookup`, `originAccountId` on `SessionCredential`, `AccountContextFilter` session lookup). **CTF preserved:** `StsQueryHandler` trust validation and federated token checks; `GetCallerIdentity` caller ARN for IAM users; `GetSessionToken` session-policy intersection (`parentAccessKeyId`); CTF `registerSession` fields merged with upstream `originAccountId`; SigV4 presign generator (operator root AKIA).

**Previous merge:** upstream **main** (52 commits through **`aeb11d77`**, merged 2026-06-28; releases **1.5.27** and **1.5.28**): IoT Core, Elastic Beanstalk, MemoryDB ACLs, AppSync `$util` VTL runtime, EventBridge Pipes Kafka, S3 bucket logging, ECS EFS volumes, SES v1 delivery options, EC2 instance-type catalog, Cognito auth-flow fixes, Lambda SQS ESM fidelity, IAM managed-policy account context, CodeDeploy persistence, plus 1.5.27 items (CodePipeline, S3 Vectors, etc.). **CTF preserved:** SigV4 presign, strict IAM, Secrets Manager KMS envelopes, Cognito `InProcessTargetAuthorizer`, `ContainerEnvHardening`, EC2 flow logs.

**Previous merge:** upstream **main** (15 commits through **`9253ee82`**, merged 2026-06-23; release **1.5.27**): CodePipeline JSON 1.1 with local stage execution (S3, CodeBuild, CodeDeploy, Lambda, nested pipelines, manual approval), S3 Vectors REST JSON (vector buckets, indexes, put/get/query/delete vectors), KMS `KmsKeySpec` / `KmsKeyUsage` / `KmsMessageType` enums and key metadata algorithms, Cognito `AdminUserGlobalSignOut` token revocation (`RevokedTokenInfo` store), SES v1 configuration-set tracking options and reputation-metrics flags, EC2 Network ACL lifecycle (default ACL on VPC create, persisted `ec2-network-acls.json`), Secrets Manager automatic rotation lifecycle (`RotateSecret` + Lambda hook), hybrid/persistent storage for AWS Config rules/recorders/channels/tags, ECS durable resources (`StorageBackedMap`), CodeBuild projects/report groups/source credentials, EC2 spot and flow-log state unchanged.

**Earlier merge:** upstream **main** (18 commits post **1.5.26**, merged 2026-06-21): MemoryDB service (Valkey containers), Neptune openCypher via Neo4j backend (`NEPTUNE_DB_TYPE`), SES v2 dedicated IP pools and configuration-set option groups, API Gateway v2 cascade delete, CloudFormation SAM Globals merge and implicit API from Api events, DynamoDB TableId/TableClass/OnDemandThroughput/deletion protection/scan limits/filter expression fixes, ACM certificate persistence after restart, Athena partition keys in table metadata, DocDB/Neptune container shutdown on emulator stop, EC2 empty `stateReason` omitted in DescribeInstances.

**Earlier:** upstream **1.5.26** (24 commits, merged 2026-06-09; released 2026-06-19): presigned URL account context (#1413), Lambda SQS DLQ redrive (#1419), Cognito password recovery (#1415), EC2 Spot instances and embedded DNS (#1291, #1390), API Gateway SQS query integrations (#1385), CloudFormation provisioning expansion, Auto Scaling reconciliation/instance refresh, DocumentDB, SSM patch baselines and Run Command in EC2 containers.

```bash
git fetch upstream main
git merge upstream/main
```

Re-apply CTF behavior on conflicts (high risk after post-1.5.26 merges):

- Auth/account: `AccountResolver`, `AccountContextFilter`, auth filters, `ContainerEnvHardening`, `OperatorCredentialEnv`
- S3 presign: `PreSignedUrlGenerator` (keep SigV4 + root AKIA; do not take upstream account-id signing)
- IAM/STS: `StsQueryHandler`, `IamService`, `SessionCredential` (merge CTF caller-identity + `originAccountId`), `ResourcePolicyResolver`, `ResourceArnBuilder`, `PolicyPrincipalMatcher`, `IamActionRegistry`
- APIGW: `ApiGatewayExecuteController`, `AwsServiceRouter` (keep JSON `integration.credentials`, query `invokeQuery` IAM, Lambda path routing, and CloudTrail audit)
- Cognito: `CognitoService`, `CognitoAuthFlowHandler` (keep `InProcessTargetAuthorizer` on delivery paths; preserve revoked-token checks on `AdminUserGlobalSignOut` / `GlobalSignOut` / `RevokeToken` and `jti` / `origin_jti`)
- Step Functions: `AslExecutor`, `JsonataEvaluator` (keep `InProcessIamAuthorizer` and CloudTrail on aws-sdk tasks across JSONata `Assign`)
- EC2: `Ec2Service`, `Ec2QueryHandler`, `Ec2ContainerManager`, `Ec2MetadataServer` (flow logs + persisted spot requests; Network ACL storage; empty `stateReason` omission)
- APIGW v2: `ApiGatewayV2Service` (cascade delete)
- CloudFormation: `SamTransformProcessor`, `CloudFormationResourceProvisioner` (SAM Globals, implicit Api)
- DynamoDB: `DynamoDbService`, `ExpressionEvaluator` (TableId, scan limits, filter fixes)
- MemoryDB / Neptune / DocDB: `MemoryDbService`, `NeptuneService`, `NeptuneContainerManager`, `EmulatorLifecycle` (container shutdown)
- SES: `SesService`, `SesQueryHandler`, `SesController` (v1 tracking/reputation options; v2 dedicated IP pools and configuration-set option groups)
- KMS: `KmsService`, `KmsJsonHandler`, `KmsKeySpec` / `KmsKeyUsage` / `KmsMessageType` (keep grant fallback and CTF decrypt scoping)
- Secrets Manager: `SecretsManagerService`, `SecretsManagerJsonHandler`, `SecretsManagerKmsSupport` (single-layer envelopes; rotation must not re-wrap KMS ciphertext)
- CodePipeline: `CodePipelineService`, `CodePipelineJsonHandler` (storage-backed pipelines; in-process actions inherit IAM on integrated services)
- S3 Vectors: `S3VectorsService`, `S3VectorsController` (new REST host prefix; standard HTTP IAM/SigV4 path)
- IoT: `IotService`, `IotController`, `IotDataController`, `IotMqttBrokerService` (REST JSON + MQTT; HTTP IAM/SigV4 on control/data REST. When IAM enforcement is on, MQTT CONNECT requires real auth with AKID password bound to the stored secret, and topic publish/subscribe is IAM-gated)
- Elastic Beanstalk: `ElasticBeanstalkService`, `ElasticBeanstalkQueryHandler`
- MemoryDB ACLs: `MemoryDbService`, `MemoryDbHandler`, `services/memorydb/model/Acl`, `User`
- AppSync `$util`: `services/appsync/graphql/util/*`
- S3 bucket logging: `S3Controller`, `S3AccessLogService`
- EventBridge Pipes Kafka: `PipesService` (MSK and `smk://` sources)
- Storage persistence: `AwsConfigService`, `EcsService`, `CodeBuildService`, `Ec2Service`, `CodeDeployService` (hybrid flush intervals; do not bypass `StorageFactory`)
- ACM / Athena: certificate persistence, partition keys in table metadata
- `SnsService` (`iamEnforcementEnabled` gate on default topic policy)
- `EcsContainerManager`, `CodeBuildRunner` (`ContainerEnvHardening` in `buildEnvVars`)
- `docker-compose.yml`, `docker/Dockerfile`, `application.yml` (`floci.ctf` block)
- Tests: `PreSignedUrlIntegrationTest` (assert root AKIA in credential, not 12-digit account id); `AdminUserGlobalSignOutIntegrationTest`, `SecretsManagerRotationIntegrationTest`, `CodePipelineIntegrationTest`, `S3VectorsIntegrationTest`, `SesConfigurationSetTrackingOptionsV1IntegrationTest`, persistence tests for Config/ECS/CodeBuild/EC2

After merge: run CTF regression below; update `README.md` and this file; verify `git diff upstream/main HEAD -- docker-compose.yml docker/Dockerfile src/main/java/io/github/hectorvent/floci/core/common/ src/main/java/io/github/hectorvent/floci/services/sns/SnsService.java src/main/java/io/github/hectorvent/floci/services/cognito/CognitoService.java src/main/java/io/github/hectorvent/floci/services/ec2/Ec2Service.java src/main/java/io/github/hectorvent/floci/services/ec2/Ec2ContainerManager.java src/main/java/io/github/hectorvent/floci/services/secretsmanager/SecretsManagerService.java src/main/java/io/github/hectorvent/floci/services/kms/KmsService.java src/main/java/io/github/hectorvent/floci/services/ses/SesService.java src/main/java/io/github/hectorvent/floci/services/configservice/AwsConfigService.java src/main/java/io/github/hectorvent/floci/services/ecs/EcsService.java src/main/java/io/github/hectorvent/floci/services/codebuild/CodeBuildService.java`.

---

## CTF regression tests

**Core hardening:**

```bash
./mvnw test -Dtest=IamJson11CredentialScopeSplitIntegrationTest,IamKinesisCatchAllRouteScopeIntegrationTest,ApiGatewaySqsQueryIamBypassIntegrationTest,IamActionRegistryTest,ApiGatewayIamScopeBypassIntegrationTest,ApiGatewayExecuteApiScopeIntegrationTest,HealthServicesReportingIntegrationTest,CtfHideInternalEndpointsIntegrationTest,CtfComposeParityIntegrationTest,ContainerEnvHardeningTest,EksTokenValidatorTest,EksTokenSigV4IntegrationTest,IamEnforcementIntegrationTest,IamEnforcementFilterTest,StsAssumeRoleTrustIntegrationTest,SigV4RequestValidatorTest,PreSignedUrlIntegrationTest,PreSignedUrlAccountResolutionIntegrationTest,S3PresignedPostIntegrationTest,IamPolicyEvaluatorTest,FederatedTokenParserTest,SecurityBypassPathsTest,OperatorCredentialEnvTest,SigV4ValidationFilterIntegrationTest,PreSignedUrlFilterIntegrationTest,PreSignedUrlRootSecretPrecedenceIntegrationTest,StsGetCallerIdentityIntegrationTest,AnonymousAccessGateBypassIntegrationTest,S3PublicBucketPolicyAnonymousGetIntegrationTest,ApiGatewayNoneAuthAnonymousInvokeIntegrationTest,LambdaFunctionUrlNoneAuthIntegrationTest,SamlAssertionSignatureVerifierTest,OutboundUrlGuardTest,PathSandboxTest,JwtAuthorizerVerifierTest,CodeBuildArtifactPathTest,CognitoUserInfoIntegrationTest,CognitoAuthFlowHandlerTest,S3BypassGovernanceRetentionIamIntegrationTest,WebSocketConnectIamGateIntegrationTest,CloudFormationResourceProvisionerIamGateTest,IotMqttBrokerServiceTest,IotMqttConnectAuthPolicyTest,IamConditionContextResolverTest,IamServiceTest,ScheduleInvokerTest,TaggingIamScopedIntegrationTest,PipesTargetInvokerTest,PipesPollerTest,ResourcePolicyResolverTest,ResourceArnBuilderTest,WebSocketIntegrationInvokerSubstitutionTest
```

**Scoped IAM + realism (enforcement profile tests):**

```bash
./mvnw test -Dtest=IamEnforcementIntegrationTest,ResourceArnBuilderTest,IamActionRegistryTest,PolicyPrincipalMatcherTest,ResourcePolicyResolverTest,StsAssumeRoleTrustIntegrationTest,StsWebIdentityTrustIntegrationTest,StsWebIdentityStrictUnsignedIntegrationTest,StsWebIdentityTrustHmacValidationIntegrationTest,StsGetSessionTokenIntersectionIntegrationTest,StsSessionPolicyS3EnforcementIntegrationTest,StsGetFederationTokenIntersectionIntegrationTest,StsGetCallerIdentityIntegrationTest,CtfComposeParityIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbGetItemQueryScopedIntegrationTest,DynamoDbPutItemScopedIntegrationTest,DynamoDbExecuteStatementScopedIntegrationTest,DynamoDbBatchExecuteStatementScopedIntegrationTest,S3ObjectVersioningIamIntegrationTest,PreSignedUrlIntegrationTest,PreSignedUrlAccountResolutionIntegrationTest,PreSignedUrlRootSecretPrecedenceIntegrationTest,PreSignedUrlFilterIntegrationTest,S3PresignedPostIntegrationTest,S3PresignedBucketPolicyDenyIntegrationTest,IamEnforcementPresignedS3DenyIntegrationTest,SqsReceiveMessageScopedQueueIntegrationTest,SqsListQueuesIamIntegrationTest,SqsResourcePolicyOnlyAllowIntegrationTest,SnsSubscribeReceiveIamIntegrationTest,SnsPublishScopedIamIntegrationTest,SnsTopicNoDefaultPolicyIntegrationTest,SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest,SecretsManagerKmsEnvelopeIntegrationTest,SecretsManagerKmsSupportTest,SecretsManagerGetSecretValueScopedArnIntegrationTest,SecretsManagerRotationKmsIntegrationTest,CloudTrailSqsAuditIntegrationTest,StepFunctionsScopedSdkIamIntegrationTest,ApiGatewaySqsIntegrationTest,ApiGatewayIamScopeBypassIntegrationTest,ApiGatewayExecuteApiScopeIntegrationTest,IamJson11CredentialScopeSplitIntegrationTest,IamKinesisCatchAllRouteScopeIntegrationTest,ApiGatewaySqsQueryIamBypassIntegrationTest,IotIamScopedIntegrationTest,VtlProcessBuilderSandboxTest,CognitoOAuthIamEnforcementIntegrationTest,CognitoUserInfoIntegrationTest,GlobalSignOutIntegrationTest,InProcessIamAuthorizerTest,InProcessTargetAuthorizerTest,InProcessTargetIamIntegrationTest,InProcessIamEnforcementIntegrationTest,LambdaContainerCredentialsServerTest,LambdaContainerCredentialsIamIntegrationTest,EcsContainerCredentialsIamIntegrationTest,CodeBuildContainerCredentialsServerTest,CodeBuildIamScopedIntegrationTest,CodeBuildBlankServiceRoleIntegrationTest,LambdaBlankRoleOperatorCredentialIntegrationTest,AthenaDuckOperatorS3BypassIntegrationTest,CodeDeployIamScopedIntegrationTest,AcmIamScopedIntegrationTest,BackupIamScopedIntegrationTest,Route53IamScopedIntegrationTest,SigV4ValidationFilterIntegrationTest,SecurityBypassPathsTest,OperatorCredentialEnvTest,IamPolicyEvaluatorTest,FederatedTokenParserTest,SamlAssertionSignatureVerifierTest,AnonymousAccessGateBypassIntegrationTest,S3PublicBucketPolicyAnonymousGetIntegrationTest,ApiGatewayNoneAuthAnonymousInvokeIntegrationTest,LambdaFunctionUrlNoneAuthIntegrationTest,CognitoAuthFlowHandlerTest,S3BypassGovernanceRetentionIamIntegrationTest,WebSocketConnectIamGateIntegrationTest,CloudFormationResourceProvisionerIamGateTest,IotMqttBrokerServiceTest,IotMqttConnectAuthPolicyTest,IamConditionContextResolverTest,IamServiceTest,ScheduleInvokerTest,TaggingIamScopedIntegrationTest,PipesTargetInvokerTest,PipesPollerTest,WebSocketIntegrationInvokerSubstitutionTest,JwtAuthorizerVerifierTest,OutboundUrlGuardTest,IamEnforcementFilterTest
```

**E2E against running instance:**

```bash
./mvnw test -pl compatibility-tests/sdk-test-java -Dtest=IamEnforcementTest
cd compatibility-tests && just test-forensic-java
```

On Windows with Docker Desktop, Floci auto-falls back to `npipe:////./pipe/docker_engine` when the configured default is `unix:///var/run/docker.sock` and `DOCKER_HOST` is unset. You can still set `DOCKER_HOST` explicitly before container tests if needed.

### CTF fuzz harness (`tools/fuzz/`)

Separate Maven project under [`tools/fuzz/`](./tools/fuzz/) (not part of default `./mvnw test`). Security-first oracles (auth bypass, policy under-scope, credential escalation, sandbox escape) plus crash/hang secondary.

```bash
./mvnw install -DskipTests
./mvnw -f tools/fuzz/pom.xml test
# or: ./tools/fuzz/scripts/run-unit.sh | run-unit.ps1

# Live operator campaigns (CTF Compose + AWS_ENDPOINT_URL); never put root creds in corpora/
./tools/fuzz/scripts/run-operator.sh
```

Details: [`tools/fuzz/README.md`](./tools/fuzz/README.md). Per-service matrix: [`tools/fuzz/coverage.yaml`](./tools/fuzz/coverage.yaml). Findings land in `tools/fuzz/findings/` then graduate to `src/test` PoC/regression tests.

---

## CI workflows

| Workflow | Job | When | Notes |
|----------|-----|------|-------|
| `.github/workflows/ci.yml` | `test` | PR/push to `main` (`src/**`, `pom.xml`) | Full unit and integration suite |
| `.github/workflows/ci.yml` | `ctf-regression` | Same triggers | CTF hardening subset via `@QuarkusTest` profiles |
| `.github/workflows/ci.yml` | `dependency-scan` | Same triggers | Trivy `pom.xml` scan, CRITICAL/HIGH, report-only (`exit-code: 0`) |
| `.github/workflows/compatibility.yml` | `compat-test` | PR (`compatibility-tests/**`, Dockerfiles) | Permissive Floci for upstream SDK parity |
| `.github/workflows/compatibility.yml` | `ctf-compat-java` | Same triggers | `IamEnforcementTest` with IAM + strict + SigV4 env |

The `tools/fuzz/` harness is operator/local only (not a CI job). Run via [`tools/fuzz/README.md`](./tools/fuzz/README.md).

**Local CTF compat (broader than CI):** from `compatibility-tests/`, `just test-ctf-java` runs `IamEnforcementTest`, `CloudMapIamEnforcementIntegrationTest`, and `AppSyncIamEnforcementIntegrationTest` against a CTF-configured instance.

---

## Project overview (general Floci)

Floci is a Java-based local AWS emulator on Quarkus. Goal: full AWS SDK and CLI compatibility through real AWS wire protocols.

- Port: 4566
- Stack: Java 25, Quarkus 3.36.0, JUnit 5, RestAssured, Jackson, Docker for Lambda/RDS/ElastiCache/MemoryDB/Neptune/DocumentDB

---

## First principles (implementation)

1. Preserve AWS protocol compatibility
2. Match AWS SDK and CLI behavior
3. Reuse existing Floci patterns
4. Prefer correctness over convenience
5. Keep changes narrow and testable

Critical rules: no custom endpoint shapes; no convenience wire-format changes; no broad refactors unless required.

---

## Architecture

- **Controller / Handler:** parses protocol input, produces AWS-compatible responses
- **Service:** business logic, throws `AwsException`
- **Model:** domain objects

**Core infrastructure:** `EmulatorConfig`, `ServiceRegistry`, `StorageBackend` + `StorageFactory`, `AwsJson11Controller`, `AwsQueryController`, `AwsException` + `AwsExceptionMapper`, `EmulatorLifecycle`

**Packages:** `io.github.hectorvent.floci.config`, `core.common`, `core.storage`, `lifecycle`, `services.<service>`

---

## AWS protocol rules

| Protocol | Services | Request | Response | Implementation |
|----------|----------|---------|----------|----------------|
| Query | SQS, SNS, IAM, STS, RDS, ... | form POST + `Action` | XML | `AwsQueryController` |
| JSON 1.1 | SSM, KMS, Secrets Manager, ... | POST + `X-Amz-Target` | JSON | `AwsJson11Controller` |
| REST JSON | Lambda, API Gateway, SES V2 | REST paths | JSON | JAX-RS |
| REST XML | S3 | REST paths | XML | JAX-RS |
| TCP | ElastiCache, MemoryDB, RDS, Neptune, DocumentDB | raw | native | proxies |

Use `XmlBuilder` / `XmlParser` (not regex). JSON errors follow AWS shapes.

---

## Storage rules

Modes: `memory`, `persistent`, `hybrid`, `wal`. Always use `StorageFactory`. Update `EmulatorConfig`, main and test `application.yml`, and lifecycle hooks when adding storage behavior.

---

## Configuration rules

Config under `floci.*` / `FLOCI_*`. Update `EmulatorConfig`, YAML, and docs for user-facing changes.

---

## Build and run

```bash
./mvnw quarkus:dev
./mvnw test
./mvnw clean package -DskipTests
```

Focused upstream-style test example:

```bash
./mvnw test -Dtest=SsmIntegrationTest
```

Compatibility suite: `./compatibility-tests/` (prefer AWS SDK clients over raw HTTP).

---

## Testing rules

- Unit: `*ServiceTest.java`; integration: `*IntegrationTest.java`
- Test protocol-affecting changes; prefer SDK validation
- **CTF fork:** add or update IAM enforcement integration tests when changing scoping or filter behavior

---

## Error handling

Services throw `AwsException`. Query/REST XML use `AwsExceptionMapper`. JSON 1.1 returns structured AWS errors.

---

## Service implementation pattern

1. Identify AWS protocol
2. Reuse existing service pattern
3. Thin controllers, `AwsException` in services
4. Update config, storage, docs, tests together

---

## Adding a new AWS service

Create `services/<svc>/` with Controller, Service, `model/`; register in `ServiceRegistry`; wire `EmulatorConfig`, YAML, `StorageFactory`, tests, docs.

---

## Code style

Constructor injection; minimal comments; braces on all conditionals; match existing patterns.

---

## Logging

JBoss Logging; avoid noisy hot-path logs.

---

## Pull request guidelines

Focused changes; update docs when user-visible; conventional commits (`feat:`, `fix:`, `docs:`, `chore:`). No `Co-Authored-By` for AI tools.

---

## Agent workflow

### Before editing

1. CTF fork: confirm whether change touches auth or upstream-shared code
2. Identify service and protocol; mirror existing implementation
3. Check `EmulatorConfig`, YAML, docs impact
4. New `:4566` routes must pass JAX-RS filters unless explicitly a bypass surface

### Before finishing

1. Run relevant tests (CTF regression if auth/IAM touched)
2. Update `README.md` and this file for user-visible CTF behavior
3. No custom endpoints; verify config and docs

### When behavior is unclear

Prefer AWS behavior, then existing Floci behavior, then compatibility test expectations.

---

## Common mistakes

- Non-AWS endpoints
- Bypassing `StorageFactory`
- Wire format changes without tests
- Forgetting YAML updates
- Testing only with raw HTTP
- Reverting CTF gates on upstream merge (`SnsService` topic policy, `PolicyPrincipalMatcher` `:root`, `ContainerEnvHardening`)
