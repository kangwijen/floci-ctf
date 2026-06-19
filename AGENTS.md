# AGENTS.md: floci-ctf

Guidance for AI agents and operators in this repository. **floci-ctf** is a security-hardened fork of [Floci](https://github.com/floci-io/floci) for CTF and security exercises. It is not stock upstream `floci/floci:latest`.

Human-readable fork summary: [README.md](./README.md). IAM detail: [docs/services/iam.md](./docs/services/iam.md#ctf-hardening).

---

## CTF fork overview

| Item | Value |
|---|---|
| Language | Java 25 |
| Framework | Quarkus 3.36.0 |
| Upstream release | 1.5.26 (released 2026-06-19) |
| Port | 4566 (HTTP API) |
| Config prefix | `floci.*` / `FLOCI_*` |
| Image tag (local) | `floci:local` |

**First principles (override upstream defaults when they conflict):**

1. Preserve CTF hardening on upstream merges: IAM enforcement, strict mode, SigV4 validation, no baked-in `test`/`test`.
2. Match AWS semantics where Floci can model them (auth, presign, STS trust, resource policies).
3. Keep diffs narrow; reuse `AwsException`, `StorageFactory`, protocol controllers.
4. Ship docs and tests with behavior changes (`README.md`, this file, `docs/services/iam.md` when IAM changes).
5. Prioritize core CTF surface: IAM, STS, S3, SQS, SNS, DynamoDB, Lambda, KMS, Secrets Manager.

**Fork-only HTTP auth (`core.common`):** `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths`, `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode`, `ContainerEnvHardening`, `OperatorCredentialEnv`, `AccountResolver`, `AccountContextFilter`.

**Related fork deltas:** `PreSignedUrlFilter`, `PreSignedUrlGenerator` (SigV4 with operator root AKIA, not upstream account-id signing), `ResourcePolicyResolver`, `PolicyPrincipalMatcher`, `ResourceArnBuilder`, `AssumeRoleTrustPolicyEvaluator`, `StsQueryHandler`, `SecretsManagerKmsSupport`, `EksTokenAuthenticator`, `InProcessTargetAuthorizer`.

---

## Using `floci:local` (operators)

Build from this repo (not upstream `floci/floci:latest`):

```bash
docker build -f docker/Dockerfile -t floci:local .
```

Set operator env on the **host**, then start Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
docker compose up -d
```

Compose enables (do not turn off for CTF): `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED`, `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED`, `FLOCI_AUTH_VALIDATE_SIGNATURES`, `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` (use `all` to hide `/health` from players).

### Operator vs participant

| Role | Credentials | Behavior |
|------|-------------|----------|
| **Operator** | `FLOCI_AUTH_ROOT_*` | Bypasses IAM enforcement for provisioning; must SigV4; never give to players |
| **Participant** | IAM `create-access-key` | Subject to IAM + SigV4; `test`/`test` and unregistered keys fail |

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
# Operator provisioning
aws iam create-user --user-name player1
aws iam create-access-key --user-name player1
aws sts get-caller-identity   # expect arn:aws:iam::ACCOUNT:user/player1, not :root
```

### Fork vs upstream (summary)

| Topic | Upstream | This fork |
|-------|----------|-----------|
| Default creds | `test`/`test` baked in; optional `floci`/`floci` deployer | None in `docker/Dockerfile`; `floci`/`floci` deployer not seeded when IAM enforcement is on (`seed-deployer-principal` gated) |
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
- Expecting player `AWS_*` in Lambda/ECS/CodeBuild env (stripped)

---

## IAM and scoped resources

When IAM enforcement is on, identity policies use AWS-shaped **resource ARNs** from the request (`ResourceArnBuilder`), not always `*`.

| Action | Policy `Resource` | Request target |
|--------|-------------------|----------------|
| `iam:CreateAccessKey` | `arn:aws:iam::ACCOUNT:user/name` | `UserName` in form body |
| `dynamodb:GetItem` / `Query` | `arn:aws:dynamodb:REGION:ACCOUNT:table/name` (and `.../index/name` for GSI) | `TableName`, `IndexName`, or `RequestItems` key in JSON |
| `dynamodb:PartiQL*` | Same table ARN | `Statement` SQL (`FROM`/`INTO`/`UPDATE` table) on `ExecuteStatement` |
| `secretsmanager:GetSecretValue` | `arn:aws:secretsmanager:REGION:ACCOUNT:secret:name-*` | `SecretId` |
| `kms:Decrypt` | `arn:aws:kms:REGION:ACCOUNT:key/KEY-ID` | `KeyId` or Floci `kms:v2:` blob in `CiphertextBlob` |
| `sqs:ReceiveMessage` | `arn:aws:sqs:REGION:ACCOUNT:queue` | `QueueUrl` (Query form or JSON 1.0 body) |
| `sqs:ListQueues` | `*` (list API per AWS) | Query `Action=ListQueues` or JSON 1.0 `AmazonSQS.ListQueues`; IAM deny returns `AccessDenied` (not `ServiceNotAvailable`) |
| `sns:Subscribe` | `arn:aws:sns:REGION:ACCOUNT:topic` | `TopicArn` |
| `ssm:GetParameter` | `arn:aws:ssm:REGION:ACCOUNT:parameter/path` | `Name` |
| `cloudformation:DescribeStacks` | `arn:aws:cloudformation:REGION:ACCOUNT:stack/NAME/*` | `StackName` |
| `s3:GetObjectVersion` | `arn:aws:s3:::bucket/key` | `versionId` query param |
| `s3:ListBucketVersions` | `arn:aws:s3:::bucket` | `?versions` on bucket GET |
| `sts:AssumeRole` | Role ARN + trust on role | `sts:AssumeRole` on role; trust `sts:ExternalId` when set |
| `eks:CreateNodegroup` | `arn:aws:eks:REGION:ACCOUNT:nodegroup/CLUSTER/*` | `POST /clusters/{name}/node-groups` |
| `athena:CreateWorkGroup` | `arn:aws:athena:REGION:ACCOUNT:workgroup/name` | `Name` in JSON body on `CreateWorkGroup` |
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

**Resource policies:** S3, Lambda, SQS, SNS, KMS, Secrets Manager policies merge on HTTP (identity OR resource Allow; explicit Deny wins). Account `:root` in a resource policy does **not** authorize every IAM user. With IAM enforcement on, SNS topics get **no** open default topic policy.

**Not on HTTP:** in-process Step Functions / API Gateway integrations, Cognito OAuth (`/oauth2/*`). S3 presigned POST bypasses `IamEnforcementFilter` missing-auth; `S3Controller` validates policy conditions and SigV4 policy signature when form fields are present.

**In-process IAM:** When `floci.services.iam.enforcement-enabled=true`, `InProcessIamAuthorizer` always denies SFN/APIGW JSON-body calls without an execution role (state machine `roleArn` or integration `credentials`). `InProcessTargetAuthorizer` covers delivery paths: Pipes/Scheduler/EventBridge, SNS/S3/SES notifications, Lambda ESM pollers, Logs subscriptions (filter `roleArn` for Kinesis/Firehose), ELB/API Gateway/Cognito/CodeDeploy Lambda invoke, service S3 delivery (CloudTrail, Config, Firehose, VPC flow logs), and CUR/BCM Parquet emit. Strict mode is not required for the missing-role check; when a role or service principal is present, identity and resource policies are evaluated like HTTP.

---

## CTF implementation map

| Area | Primary files |
|------|---------------|
| HTTP IAM + SigV4 | `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths` |
| Account context | `AccountResolver`, `AccountContextFilter`, `RegionResolver` (presigned `X-Amz-Credential`, 12-digit AKID, STS session keys) |
| Identity policies | `IamPolicyEvaluator`, `IamActionRegistry`, `IamService`, `ResourceArnBuilder` |
| Resource policies | `ResourcePolicyResolver`, `PolicyPrincipalMatcher` |
| STS / federated trust | `StsQueryHandler`, `AssumeRoleTrustPolicyEvaluator`, `FederatedTokenParser`, `PolicyPrincipalMatcher` |
| S3 SigV4 presign | `PreSignedUrlGenerator`, `PreSignedUrlFilter`, `SigV4RequestValidator.validatePresignedUrl` |
| API Gateway integrations | `ApiGatewayExecuteController`, `AwsServiceRouter` (JSON credentials for IAM; query-protocol SQS path-style from upstream 1.5.26) |
| Scoped IAM ARNs | `IamActionRegistry`, `ResourceArnBuilder`, `SnsService`, `SecretsManagerKmsSupport` |
| KMS grants (HTTP) | `KmsService.isGrantAuthorized`, `IamEnforcementFilter` grant fallback |
| In-process IAM | `InProcessIamAuthorizer`, `InProcessTargetAuthorizer`, `AslExecutor` (SFN aws-sdk KMS/Secrets/S3), `AwsServiceRouter`, `Integration.credentials` |
| In-process CloudTrail audit | `InProcessCloudTrailRecorder`, `CloudTrailEventRecorder` (SQS `queueUrl` from Query form and JSON 1.0/1.1 bodies), wired in SFN/APIGW/EventBridge/SNS/Firehose/Config/EC2 flow logs |
| Cognito OAuth gate | `SecurityBypassPaths`, `IamEnforcementFilter` (OAuth paths exempt SigV4; Bearer cannot bypass data plane) |
| Containers | `ContainerEnvHardening`, `ContainerCredentialsHttpServer`, `ContainerLauncher`, `LambdaContainerCredentialsServer`, `EcsContainerManager`, `EcsContainerCredentialsServer`, `CodeBuildContainerCredentialsServer`, `CodeBuildRunner` |
| Internal routes | `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode` |
| Compose / image | `docker-compose.yml`, `docker/Dockerfile` (no `test`/`test`) |
| RDS Data API | `RdsDataController`, `RdsDataService`, `RdsDataConnectionFactory`, `RdsDataResourceResolver`, `RdsDataFieldMapper` |
| EMR | `EmrHandler`, `EmrService`, `services/emr/model/*` |
| WAFv2 | `WafV2Handler`, `WafV2Service`, `services/wafv2/model/*` |

**Do not assume:** `IamAuthorizationService`, `StsCallerGuard` exist as separate classes (HTTP enforcement is in `IamEnforcementFilter`).

**Known gaps (prioritize next):**

- Presigned POST, SigV4a, SSE query params in S3 presign
- Federated JWT/SAML full crypto validation (structural parse only unless `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=true`)
- OIDC provider-prefixed condition keys beyond default `aud`/`sub`/`amr` mapping
- Multi-table PartiQL / `BatchExecuteStatement` (only first table in batch used for ARN)
- In-process IAM grants not checked (`InProcessIamAuthorizer` uses identity + resource policies only)
- Operator event injection API for CloudTrail is not implemented

**Configuration reference:** [docs/configuration/environment-variables.md](./docs/configuration/environment-variables.md#ctf-hardening), [docs/configuration/advanced/application-yml.md](./docs/configuration/advanced/application-yml.md#ctf-fork-settings).

---

## Forensic services map

Compose forensic defaults (in addition to CTF security env): `FLOCI_STORAGE_MODE=hybrid`, `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`.

**Instance-keyed grading:** Forensics labs grade live `lookup-events` output with provision-time `answers.json` fields (`eventTime`, `accessKeyId`, `VersionId`). Authoring detail: [docs/services/cloudtrail.md#live-forensics-authoring](./docs/services/cloudtrail.md#live-forensics-authoring).

| Area | Primary files / docs |
|------|----------------------|
| CloudTrail trail lifecycle | `CloudTrailService`, `CloudTrailJsonHandler`, [docs/services/cloudtrail.md](./docs/services/cloudtrail.md) |
| CloudTrail audit recording | `CloudTrailAuditFilter`, `InProcessCloudTrailRecorder`, `CloudTrailEventRecorder`, `CloudTrailDeliveryService`, `CloudTrailEventStore` |
| CloudTrail audit config | `EmulatorConfig.CloudTrailServiceConfig` (`audit-enabled`, `exclude-internal-paths`) |
| Config delivery / snapshots | `ConfigSnapshotDeliveryService`, `AwsConfigService`, [docs/services/config.md](./docs/services/config.md) |
| S3 access logging | `S3AccessLogService`, `S3AccessLogFormatter`, [docs/services/s3.md](./docs/services/s3.md#access-logging) |
| VPC Flow Logs | `Ec2FlowLogEmitter`, `Ec2Service`, `VpcFlowLogRecordFormatter` |
| CloudWatch Logs subscriptions | `CloudWatchLogsSubscriptionDispatcher` |
| GuardDuty detectors / findings | `GuardDutyService`, `GuardDutyCloudTrailHook`, [docs/services/guardduty.md](./docs/services/guardduty.md) |
| Security Hub ASFF import | `SecurityHubService`, `GuardDutyFindingSubscriber`, [docs/services/securityhub.md](./docs/services/securityhub.md) |
| Persistent lab state | `StorageFactory`, `HybridStorage`, `./data` volume in `docker-compose.yml` |
| In-process CloudTrail audit | `InProcessCloudTrailRecorder`, `InProcessAuditContext`; SFN/APIGW/EventBridge/SNS/Firehose/Config/EC2/S3 access logs |
| E2E forensic scenario | `CloudForensicsIntegrationTest`, `InProcessCloudTrailIntegrationTest`, `InternalServiceCloudTrailIntegrationTest`, `ForensicLabProfile` |
| SDK compatibility probes | [compatibility-tests/sdk-test-java](./compatibility-tests/sdk-test-java) (`ForensicLabCompatibilityTest`) |

**Forensic regression (unit/integration):**

```bash
./mvnw test -Dtest=CloudForensicsIntegrationTest,CloudTrailIntegrationTest,CloudTrailAuditIntegrationTest,CloudTrailTamperingAuditIntegrationTest,CloudTrailIamScopedIntegrationTest,CloudTrailLookupEventsScopedIamIntegrationTest,CloudTrailSqsAuditIntegrationTest,InProcessCloudTrailIntegrationTest,InternalServiceCloudTrailIntegrationTest,CloudTrailLookupEventsIntegrationTest,ConfigSnapshotDeliveryIntegrationTest,S3AccessLoggingIntegrationTest,Ec2FlowLogsIntegrationTest,CloudWatchLogsSubscriptionIntegrationTest,GuardDutyIntegrationTest,SecurityHubIntegrationTest
```

**Forensic compatibility (running instance):**

```bash
cd compatibility-tests && just test-forensic-java
```

Requires `FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true` on the emulator (Compose default) and operator or IAM credentials in `.env`.

**Forensic gaps closed on `floci:local`:**

| Gap | Status | Regression / doc |
|-----|--------|------------------|
| `cloudtrail:LookupEvents` IAM scoping | Closed | `CloudTrailLookupEventsScopedIamIntegrationTest`; [cloudtrail.md](./docs/services/cloudtrail.md#ctf-fork-notes) |
| `cloudtrail:StopLogging` audit + history | Closed | `CloudTrailTamperingAuditIntegrationTest` |
| `sourceIPAddress` authoring hooks | Closed | `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` + `X-Forwarded-For`; alternate `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER`; [Live forensics authoring](./docs/services/cloudtrail.md#live-forensics-authoring) |
| SQS `ListQueues` IAM deny shape | Closed | `SqsListQueuesIamIntegrationTest`; IAM runs before service-disabled short-circuit |
| SQS audit (`ReceiveMessage`, `SendMessage`, `PurgeQueue`) with `requestParameters.queueUrl` | Closed | Query and JSON 1.0 protocols; `CloudTrailSqsAuditIntegrationTest` |
| `lookup-events` pagination and `eventTime` format | Closed | `CloudTrailLookupEventsIntegrationTest`; [LookupEvents](./docs/services/cloudtrail.md#lookupevents) |
| Per-instance event index isolation | Documented | `CloudTrailEventStore` teardown in [Live forensics authoring](./docs/services/cloudtrail.md#cloudtraileventstore-lifecycle-and-teardown) |
| SNS fan-out E2E | Closed | `SnsSubscribeReceiveIamIntegrationTest.fanOutWithExplicitTopicAndQueueResourcePolicies`; [sns.md](./docs/services/sns.md#ctf-fork-sns-to-sqs-fan-out-closed) |
| `iam:CreatePolicyVersion` timing | Closed | `CreatePolicyVersionGrantsSecretReadIntegrationTest`; [iam.md](./docs/services/iam.md#managed-policy-version-timing) |
| KMS single-layer `SecretBinary` envelope | Closed | No double-wrap; one `kms:Decrypt` yields plaintext; `SecretsManagerKmsEnvelopeIntegrationTest`; [secrets-manager.md](./docs/services/secrets-manager.md#kms-wrapped-secretbinary) |

**Still open (do not grade player steps on these):** presigned GET, presigned POST, `GetSessionToken` session-policy intersection. Operator event injection API for CloudTrail is not implemented (future).

---

## Enforcement surfaces

| Surface | Hardened with Compose CTF env? |
|---------|-------------------------------|
| HTTP `:4566` | Yes (`SigV4ValidationFilter` + `IamEnforcementFilter`) |
| S3 presigned query URLs | Yes (`PreSignedUrlFilter` SigV4; IAM or root credential secrets only) |
| RDS / ElastiCache Redis TCP | Partial (token SigV4, not full IAM per query) |
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
| Lambda / CodeBuild / ECS runtime creds | Yes when enforcement on (creds on 9171/9172/9170; link-local `169.254.170.2` URIs with `extra_hosts`; `LambdaContainerCredentialsIamIntegrationTest`) |

**CTF defaults:** `src/main/resources/application.yml` keeps IAM/SigV4 off for local dev; Compose turns them on. Test `application.yml` disables enforcement globally; dedicated `@QuarkusTestProfile` overrides cover CTF paths.

---

## Upstream sync

**Latest merge:** upstream **1.5.26** (24 commits, merged 2026-06-09; released 2026-06-19): presigned URL account context (#1413), Lambda SQS DLQ redrive (#1419), Cognito password recovery (#1415), EC2 Spot instances and embedded DNS (#1291, #1390), API Gateway SQS query integrations (#1385), CloudFormation provisioning expansion, Auto Scaling reconciliation/instance refresh, DocumentDB, SSM patch baselines and Run Command in EC2 containers. **CTF preserved:** SigV4 presign generator (operator root AKIA), `seedDeployerPrincipal` off when enforcement on, strict IAM, flow logs + spot persistence, Cognito auth flows via `InProcessTargetAuthorizer`, APIGW JSON integration credentials.

```bash
git fetch upstream main
git merge upstream/main
```

Re-apply CTF behavior on conflicts (high risk after 1.5.26):

- Auth/account: `AccountResolver`, `AccountContextFilter`, auth filters, `ContainerEnvHardening`, `OperatorCredentialEnv`
- S3 presign: `PreSignedUrlGenerator` (keep SigV4 + root AKIA; do not take upstream account-id signing)
- IAM/STS: `StsQueryHandler`, `IamService`, `ResourcePolicyResolver`, `ResourceArnBuilder`, `PolicyPrincipalMatcher`, `IamActionRegistry`
- APIGW: `ApiGatewayExecuteController`, `AwsServiceRouter` (keep JSON `integration.credentials` + CloudTrail audit)
- Cognito: `CognitoService` (keep `InProcessTargetAuthorizer` on delivery paths)
- EC2: `Ec2Service`, `Ec2QueryHandler`, `Ec2MetadataServer` (flow logs + persisted spot requests)
- `SnsService` (`iamEnforcementEnabled` gate on default topic policy)
- `SecretsManagerKmsSupport`, `EcsContainerManager` (`ContainerEnvHardening` in `buildEnvVars`)
- `docker-compose.yml`, `docker/Dockerfile`, `application.yml` (`floci.ctf` block)
- Tests: `PreSignedUrlIntegrationTest` (assert root AKIA in credential, not 12-digit account id)

After merge: run CTF regression below; update `README.md` and this file; verify `git diff upstream/main HEAD -- docker-compose.yml docker/Dockerfile src/main/java/io/github/hectorvent/floci/core/common/ src/main/java/io/github/hectorvent/floci/services/sns/SnsService.java`.

---

## CTF regression tests

**Core hardening:**

```bash
./mvnw test -Dtest=HealthServicesReportingIntegrationTest,CtfHideInternalEndpointsIntegrationTest,CtfComposeParityIntegrationTest,ContainerEnvHardeningTest,EksTokenAuthenticatorTest,IamEnforcementIntegrationTest,IamEnforcementFilterTest,StsAssumeRoleTrustIntegrationTest,SigV4RequestValidatorTest,PreSignedUrlIntegrationTest,PreSignedUrlAccountResolutionIntegrationTest,S3PresignedPostIntegrationTest,IamPolicyEvaluatorTest,FederatedTokenParserTest
```

**Scoped IAM + realism (enforcement profile tests):**

```bash
./mvnw test -Dtest=IamEnforcementIntegrationTest,ResourceArnBuilderTest,IamActionRegistryTest,PolicyPrincipalMatcherTest,ResourcePolicyResolverTest,StsAssumeRoleTrustIntegrationTest,StsWebIdentityTrustIntegrationTest,StsWebIdentityTrustHmacValidationIntegrationTest,StsGetSessionTokenIntersectionIntegrationTest,StsGetFederationTokenIntersectionIntegrationTest,CtfComposeParityIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbGetItemQueryScopedIntegrationTest,DynamoDbExecuteStatementScopedIntegrationTest,DynamoDbBatchExecuteStatementScopedIntegrationTest,S3ObjectVersioningIamIntegrationTest,PreSignedUrlIntegrationTest,PreSignedUrlAccountResolutionIntegrationTest,S3PresignedPostIntegrationTest,SqsReceiveMessageScopedQueueIntegrationTest,SqsListQueuesIamIntegrationTest,SnsSubscribeReceiveIamIntegrationTest,SecretsManagerKmsEnvelopeIntegrationTest,CloudTrailSqsAuditIntegrationTest,StepFunctionsScopedSdkIamIntegrationTest,ApiGatewaySqsIntegrationTest,CognitoOAuthIamEnforcementIntegrationTest,InProcessIamAuthorizerTest,InProcessTargetAuthorizerTest,InProcessTargetIamIntegrationTest,InProcessIamEnforcementIntegrationTest,LambdaContainerCredentialsServerTest,LambdaContainerCredentialsIamIntegrationTest,IamPolicyEvaluatorTest,FederatedTokenParserTest
```

**E2E against running instance:**

```bash
./mvnw test -pl compatibility-tests/sdk-test-java -Dtest=IamEnforcementTest
cd compatibility-tests && just test-forensic-java
```

On Windows with Docker Desktop, set `DOCKER_HOST` so Maven can reach Docker before container tests (for example `npipe:////./pipe/docker_engine` in PowerShell). Default `floci.docker.docker-host` is `unix:///var/run/docker.sock`.

---

## CI workflows

| Workflow | Job | When | Notes |
|----------|-----|------|-------|
| `.github/workflows/ci.yml` | `test` | PR/push to `main` (`src/**`, `pom.xml`) | Full unit and integration suite |
| `.github/workflows/ci.yml` | `ctf-regression` | Same triggers | CTF hardening subset via `@QuarkusTest` profiles |
| `.github/workflows/ci.yml` | `dependency-scan` | Same triggers | Trivy `pom.xml` scan, CRITICAL/HIGH, report-only (`exit-code: 0`) |
| `.github/workflows/compatibility.yml` | `compat-test` | PR (`compatibility-tests/**`, Dockerfiles) | Permissive Floci for upstream SDK parity |
| `.github/workflows/compatibility.yml` | `ctf-compat-java` | Same triggers | `IamEnforcementTest` with IAM + strict + SigV4 env |

**Local CTF compat (broader than CI):** from `compatibility-tests/`, `just test-ctf-java` runs `IamEnforcementTest`, `CloudMapIamEnforcementIntegrationTest`, and `AppSyncIamEnforcementIntegrationTest` against a CTF-configured instance.

---

## Project overview (general Floci)

Floci is a Java-based local AWS emulator on Quarkus. Goal: full AWS SDK and CLI compatibility through real AWS wire protocols.

- Port: 4566
- Stack: Java 25, Quarkus 3.36.0, JUnit 5, RestAssured, Jackson, Docker for Lambda/RDS/ElastiCache

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
| TCP | ElastiCache, RDS | raw | native | proxies |

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
