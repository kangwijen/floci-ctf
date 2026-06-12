# AGENTS.md: floci-ctf

Guidance for AI agents and operators in this repository. **floci-ctf** is a security-hardened fork of [Floci](https://github.com/floci-io/floci) for CTF and security exercises. It is not stock upstream `floci/floci:latest`.

Human-readable fork summary: [README.md](./README.md). IAM detail: [docs/services/iam.md](./docs/services/iam.md#ctf-hardening).

---

## CTF fork overview

| Item | Value |
|---|---|
| Language | Java 25 |
| Framework | Quarkus 3.36.0 |
| Upstream release | 1.5.24+ (post-merge) |
| Port | 4566 (HTTP API) |
| Config prefix | `floci.*` / `FLOCI_*` |
| Image tag (local) | `floci:local` |

**First principles (override upstream defaults when they conflict):**

1. Preserve CTF hardening on upstream merges: IAM enforcement, strict mode, SigV4 validation, no baked-in `test`/`test`.
2. Match AWS semantics where Floci can model them (auth, presign, STS trust, resource policies).
3. Keep diffs narrow; reuse `AwsException`, `StorageFactory`, protocol controllers.
4. Ship docs and tests with behavior changes (`README.md`, this file, `docs/services/iam.md` when IAM changes).
5. Prioritize core CTF surface: IAM, STS, S3, SQS, SNS, DynamoDB, Lambda, KMS, Secrets Manager.

**Fork-only HTTP auth (`core.common`):** `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths`, `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode`, `ContainerEnvHardening`, `OperatorCredentialEnv`.

**Related fork deltas:** `PreSignedUrlFilter`, `ResourcePolicyResolver`, `PolicyPrincipalMatcher`, `ResourceArnBuilder`, `AssumeRoleTrustPolicyEvaluator`, `StsQueryHandler`, `SecretsManagerKmsSupport`, `EksTokenAuthenticator`.

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
| Default creds | `test`/`test` baked in | None in `docker/Dockerfile` |
| IAM enforcement | Off by default | On in `docker-compose.yml` |
| SigV4 | Off by default | On with Compose profile |
| Strict mode | N/A | Denies missing auth, unmapped actions, bad presign |
| Internal routes | Open | `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` returns 404 on `/_floci/*`, `/_localstack/*`, `/_aws/*` |
| ASIA session token | Optional header | `x-amz-security-token` stored and validated for temporary creds when SigV4 is on |
| `aws:sourceip` | Client `X-Forwarded-For` | Default ignores forwarded headers; set `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` behind a real proxy |
| `GetCallerIdentity` | Often account `:root` | Calling principal ARN for IAM users |
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
| `sqs:ReceiveMessage` | `arn:aws:sqs:REGION:ACCOUNT:queue` | `QueueUrl` |
| `sns:Subscribe` | `arn:aws:sns:REGION:ACCOUNT:topic` | `TopicArn` |
| `ssm:GetParameter` | `arn:aws:ssm:REGION:ACCOUNT:parameter/path` | `Name` |
| `cloudformation:DescribeStacks` | `arn:aws:cloudformation:REGION:ACCOUNT:stack/NAME/*` | `StackName` |
| `s3:GetObjectVersion` | `arn:aws:s3:::bucket/key` | `versionId` query param |
| `s3:ListBucketVersions` | `arn:aws:s3:::bucket` | `?versions` on bucket GET |
| `sts:AssumeRole` | Role ARN + trust on role | `sts:AssumeRole` on role; trust `sts:ExternalId` when set |
| `eks:CreateNodegroup` | `arn:aws:eks:REGION:ACCOUNT:nodegroup/CLUSTER/*` | `POST /clusters/{name}/node-groups` |
| `athena:CreateWorkGroup` | `arn:aws:athena:REGION:ACCOUNT:workgroup/name` | `Name` in JSON body on `CreateWorkGroup` |

**Resource policies:** S3, Lambda, SQS, SNS, KMS, Secrets Manager policies merge on HTTP (identity OR resource Allow; explicit Deny wins). Account `:root` in a resource policy does **not** authorize every IAM user. With IAM enforcement on, SNS topics get **no** open default topic policy.

**Not on HTTP:** in-process Step Functions / API Gateway integrations, Cognito OAuth (`/oauth2/*`). S3 presigned POST bypasses `IamEnforcementFilter` missing-auth; `S3Controller` validates policy conditions and SigV4 policy signature when form fields are present.

**In-process IAM:** When `floci.services.iam.enforcement-enabled=true`, `InProcessIamAuthorizer` always denies SFN/APIGW calls without an execution role (state machine `roleArn` or integration `credentials`). Strict mode is not required for that check; when a role ARN is present, identity and resource policies are evaluated like HTTP.

---

## CTF implementation map

| Area | Primary files |
|------|---------------|
| HTTP IAM + SigV4 | `IamEnforcementFilter`, `SigV4ValidationFilter`, `SigV4RequestValidator`, `SecurityBypassPaths` |
| Identity policies | `IamPolicyEvaluator`, `IamActionRegistry`, `IamService`, `ResourceArnBuilder` |
| Resource policies | `ResourcePolicyResolver`, `PolicyPrincipalMatcher` |
| STS / federated trust | `StsQueryHandler`, `AssumeRoleTrustPolicyEvaluator`, `FederatedTokenParser`, `PolicyPrincipalMatcher` |
| S3 SigV4 presign | `PreSignedUrlGenerator`, `PreSignedUrlFilter`, `SigV4RequestValidator.validatePresignedUrl` |
| Scoped IAM ARNs | `IamActionRegistry`, `ResourceArnBuilder`, `SnsService`, `SecretsManagerKmsSupport` |
| KMS grants (HTTP) | `KmsService.isGrantAuthorized`, `IamEnforcementFilter` grant fallback |
| In-process IAM | `InProcessIamAuthorizer`, `AslExecutor` (SFN aws-sdk KMS/Secrets/S3), `AwsServiceRouter`, `Integration.credentials` |
| Cognito OAuth gate | `SecurityBypassPaths`, `IamEnforcementFilter` (OAuth paths exempt SigV4; Bearer cannot bypass data plane) |
| Containers | `ContainerEnvHardening`, `ContainerCredentialsHttpServer`, `ContainerLauncher`, `LambdaContainerCredentialsServer`, `EcsContainerManager`, `EcsContainerCredentialsServer`, `CodeBuildContainerCredentialsServer`, `CodeBuildRunner` |
| Internal routes | `CtfInternalEndpointFilter`, `CtfHideInternalEndpointsMode` |
| Compose / image | `docker-compose.yml`, `docker/Dockerfile` (no `test`/`test`) |

**Do not assume:** `IamAuthorizationService`, `StsCallerGuard` exist as separate classes (HTTP enforcement is in `IamEnforcementFilter`).

**Configuration reference:** [docs/configuration/environment-variables.md](./docs/configuration/environment-variables.md#ctf-hardening), [docs/configuration/advanced/application-yml.md](./docs/configuration/advanced/application-yml.md#ctf-fork-settings).

---

## Forensic services map

Compose forensic defaults (in addition to CTF security env): `FLOCI_STORAGE_MODE=hybrid`, `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`.

| Area | Primary files / docs |
|------|----------------------|
| CloudTrail trail lifecycle | `CloudTrailService`, `CloudTrailJsonHandler`, [docs/services/cloudtrail.md](./docs/services/cloudtrail.md) |
| CloudTrail audit recording | `CloudTrailAuditFilter`, `CloudTrailEventRecorder`, `CloudTrailDeliveryService`, `CloudTrailEventStore` |
| CloudTrail audit config | `EmulatorConfig.CloudTrailServiceConfig` (`audit-enabled`, `exclude-internal-paths`) |
| Config delivery / snapshots | `ConfigSnapshotDeliveryService`, `AwsConfigService`, [docs/services/config.md](./docs/services/config.md) |
| S3 access logging | `S3AccessLogService`, `S3AccessLogFormatter`, [docs/services/s3.md](./docs/services/s3.md#access-logging) |
| VPC Flow Logs | `Ec2FlowLogEmitter`, `Ec2Service`, `VpcFlowLogRecordFormatter` |
| CloudWatch Logs subscriptions | `CloudWatchLogsSubscriptionDispatcher` |
| GuardDuty detectors / findings | `GuardDutyService`, `GuardDutyCloudTrailHook`, [docs/services/guardduty.md](./docs/services/guardduty.md) |
| Security Hub ASFF import | `SecurityHubService`, `GuardDutyFindingSubscriber`, [docs/services/securityhub.md](./docs/services/securityhub.md) |
| Persistent lab state | `StorageFactory`, `HybridStorage`, `./data` volume in `docker-compose.yml` |
| E2E forensic scenario | `CloudForensicsIntegrationTest`, `ForensicLabProfile` |
| SDK compatibility probes | [compatibility-tests/sdk-test-java](./compatibility-tests/sdk-test-java) (`ForensicLabCompatibilityTest`) |

**Forensic regression (unit/integration):**

```bash
./mvnw test -Dtest=CloudForensicsIntegrationTest,CloudTrailIntegrationTest,CloudTrailAuditIntegrationTest,CloudTrailLookupEventsIntegrationTest,ConfigSnapshotDeliveryIntegrationTest,S3AccessLoggingIntegrationTest,Ec2FlowLogsIntegrationTest,CloudWatchLogsSubscriptionIntegrationTest,GuardDutyIntegrationTest,SecurityHubIntegrationTest
```

**Forensic compatibility (running instance):**

```bash
cd compatibility-tests && just test-forensic-java
```

Requires `FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true` on the emulator (Compose default) and operator or IAM credentials in `.env`.

---

## Enforcement surfaces

| Surface | Hardened with Compose CTF env? |
|---------|-------------------------------|
| HTTP `:4566` | Yes (`SigV4ValidationFilter` + `IamEnforcementFilter`) |
| S3 presigned query URLs | Yes (`PreSignedUrlFilter` SigV4; IAM or root credential secrets only) |
| RDS / ElastiCache Redis TCP | Partial (token SigV4, not full IAM per query) |
| Cognito OAuth | Partial (client credentials on `/oauth2/token`; Cognito Bearer cannot call SigV4 data plane) |
| SFN / APIGW in-process | Yes when enforcement on (`InProcessIamAuthorizer`; SFN aws-sdk KMS/Secrets/S3 tasks) |
| Lambda / CodeBuild / ECS runtime creds | Yes when enforcement on (creds on 9171/9172/9170; link-local `169.254.170.2` URIs with `extra_hosts`; `LambdaContainerCredentialsIamIntegrationTest`) |

**CTF defaults:** `src/main/resources/application.yml` keeps IAM/SigV4 off for local dev; Compose turns them on. Test `application.yml` disables enforcement globally; dedicated `@QuarkusTestProfile` overrides cover CTF paths.

---

## Upstream sync

```bash
git fetch upstream main
git merge upstream/main
```

Re-apply CTF behavior on conflicts:

- Auth filters, `ContainerEnvHardening`, `OperatorCredentialEnv`
- IAM/STS: `StsQueryHandler`, `IamService`, `ResourcePolicyResolver`, `ResourceArnBuilder`, `PolicyPrincipalMatcher`, `IamActionRegistry`
- `SnsService` (`iamEnforcementEnabled` gate on default topic policy)
- `SecretsManagerKmsSupport`, `EcsContainerManager` (`ContainerEnvHardening` in `buildEnvVars`)
- `docker-compose.yml`, `docker/Dockerfile`, `application.yml` (`floci.ctf` block)

After merge: run CTF regression below; update `README.md` and this file; verify `git diff upstream/main HEAD -- docker-compose.yml docker/Dockerfile src/main/java/io/github/hectorvent/floci/core/common/ src/main/java/io/github/hectorvent/floci/services/sns/SnsService.java`.

---

## CTF regression tests

**Core hardening:**

```bash
./mvnw test -Dtest=HealthServicesReportingIntegrationTest,CtfHideInternalEndpointsIntegrationTest,CtfComposeParityIntegrationTest,ContainerEnvHardeningTest,EksTokenAuthenticatorTest,IamEnforcementIntegrationTest,IamEnforcementFilterTest,StsAssumeRoleTrustIntegrationTest,SigV4RequestValidatorTest,PreSignedUrlIntegrationTest,S3PresignedPostIntegrationTest,IamPolicyEvaluatorTest,FederatedTokenParserTest
```

**Scoped IAM + realism (enforcement profile tests):**

```bash
./mvnw test -Dtest=IamEnforcementIntegrationTest,ResourceArnBuilderTest,IamActionRegistryTest,PolicyPrincipalMatcherTest,ResourcePolicyResolverTest,StsAssumeRoleTrustIntegrationTest,StsWebIdentityTrustIntegrationTest,StsWebIdentityTrustHmacValidationIntegrationTest,StsGetSessionTokenIntersectionIntegrationTest,StsGetFederationTokenIntersectionIntegrationTest,CtfComposeParityIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbGetItemQueryScopedIntegrationTest,DynamoDbExecuteStatementScopedIntegrationTest,DynamoDbBatchExecuteStatementScopedIntegrationTest,S3ObjectVersioningIamIntegrationTest,PreSignedUrlIntegrationTest,S3PresignedPostIntegrationTest,SqsReceiveMessageScopedQueueIntegrationTest,SnsSubscribeReceiveIamIntegrationTest,SecretsManagerKmsEnvelopeIntegrationTest,StepFunctionsScopedSdkIamIntegrationTest,CognitoOAuthIamEnforcementIntegrationTest,InProcessIamAuthorizerTest,LambdaContainerCredentialsServerTest,LambdaContainerCredentialsIamIntegrationTest,IamPolicyEvaluatorTest,FederatedTokenParserTest
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
