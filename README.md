<p align="center">
  <img src="floci-black.svg#gh-light-mode-only" alt="Floci" width="500" />
  <img src="floci-white.svg#gh-dark-mode-only" alt="Floci" width="500" />
</p>

<p align="center">
  <strong>Light, fluffy, and always free</strong><br />
  No account. No auth token. No feature gates. Just <code>docker compose up</code>.
</p>

<p align="center">
  <a href="https://github.com/floci-io/floci/releases/latest"><img src="https://img.shields.io/github/v/release/floci-io/floci?label=latest%20release&color=blue" alt="Latest Release"></a>
  <a href="https://github.com/floci-io/floci/actions/workflows/release.yml"><img src="https://img.shields.io/github/actions/workflow/status/floci-io/floci/release.yml?label=build" alt="Build Status"></a>
  <a href="https://hub.docker.com/r/floci/floci"><img src="https://img.shields.io/docker/pulls/floci/floci?label=docker%20pulls" alt="Docker Pulls"></a>
  <a href="https://hub.docker.com/r/floci/floci"><img src="https://img.shields.io/docker/image-size/floci/floci/latest?label=image%20size" alt="Docker Image Size"></a>
  <a href="https://opensource.org/licenses/MIT"><img src="https://img.shields.io/badge/license-MIT-green" alt="License: MIT"></a>
  <a href="https://github.com/floci-io/floci/stargazers"><img src="https://img.shields.io/github/stars/floci-io/floci?style=flat" alt="GitHub Stars"></a>
</p>

# Floci CTF

A security-hardened fork of [Floci](https://github.com/floci-io/floci) (upstream **1.5.24** + 20 post-release commits merged **2026-06-13**, Quarkus **3.36.0**) for capture-the-flag and security exercises. Same local AWS emulator on port **4566**, with IAM enforcement, strict policy mode, SigV4 validation, and CTF-specific controls so participants cannot rely on permissive `test`/`test` credentials, unsigned requests, or internal introspection routes.

For service coverage, architecture, SDK examples, and general configuration, use the [upstream Floci README](https://github.com/floci-io/floci/blob/main/README.md) and [docs](https://floci.io/floci/). For operators, agents, and `floci:local` behavior, see [AGENTS.md](./AGENTS.md).

## What changed

| Area | Upstream Floci | This fork |
|---|---|---|
| IAM enforcement | Off by default | On in `docker-compose.yml` |
| Strict IAM mode | Off by default | On: denies unregistered keys and unknown action mappings |
| SigV4 on API calls | Off by default | On: validates `Authorization` signatures |
| Operator bypass | N/A | `FLOCI_AUTH_ROOT_*` pair bypasses enforcement for provisioning |
| S3 pre-signed URLs | Default HMAC secret | SigV4 query auth; signed with IAM access keys or operator root pair |
| Docker image defaults | `test`/`test` baked in | No default credentials in `docker/Dockerfile` |
| Payload hashing | N/A | SigV4 validator hashes request bodies when `x-amz-content-sha256` is absent |
| `sts:GetCallerIdentity` / `GetSessionToken` | Evaluated like any action | Policy-exempt (AWS parity): no Allow required; SigV4 and registered keys still apply |
| `sts:GetCallerIdentity` response | Often returns account `:root` | Returns the **calling principal** (IAM user, assumed role, federated user, operator root, or 12-digit account id) |
| Role trust `sts:ExternalId` | Not enforced | Trust policy conditions evaluated on `AssumeRole` |
| Resource-based policies | Not enforced on HTTP | S3/Lambda/SQS/SNS/KMS/Secrets resource policies in `IamEnforcementFilter`; presigned S3 uses SigV4 query auth then evaluates bucket policy; `NotPrincipal` supported; account `:root` in resource policies does **not** directly allow IAM users (identity policy still required) |
| Scoped IAM `Resource` ARNs | Most requests use `*` | `ResourceArnBuilder` maps per-service ARNs for S3, IAM, DynamoDB, KMS, SQS, SNS, SSM, STS, and more on HTTP `:4566` |
| Health `services` map | Lists all services as `running` or `available` | Only **enabled** services appear as `running`; disabled services omitted |
| Internal introspection routes | `/_floci/*`, `/_localstack/*`, `/health` open | Default `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS=true` hides `/_floci/*`, `/_localstack/*`, and `/_aws/*`; `all` also hides `/health` |
| Temporary creds (`ASIA*`) | Secret key alone | `x-amz-security-token` required and validated when SigV4 is on |
| Docker `HEALTHCHECK` | `/_floci/health` | `GET /health` (works when internal routes are hidden) |
| Container env (Lambda, ECS, CodeBuild) | Function/task/build env can set `AWS_*` | `ContainerEnvHardening` blocks credential keys and bypass URIs; execution/service/task roles get `AWS_CONTAINER_CREDENTIALS_FULL_URI` (ports 9171/9172/9170); operator env only when no role |
| EKS kubectl token webhook | Any `k8s-aws-v1.*` accepted as cluster-admin | Hidden under `/_floci/*` by default; with IAM enforcement on, requires plausible presigned STS `GetCallerIdentity` URL (`EksTokenAuthenticator`) |

**Fork-only code (high level):** `IamEnforcementFilter`, `SigV4ValidationFilter`, `PreSignedUrlFilter` (SigV4 presign), `PolicyPrincipalMatcher`, `FederatedTokenParser`, `ResourcePolicyResolver`, `ResourceArnBuilder`, `AssumeRoleTrustPolicyEvaluator`, `InProcessIamAuthorizer`, `CtfInternalEndpointFilter`, `ContainerEnvHardening`, `LambdaContainerCredentialsServer`, `EcsContainerCredentialsServer`, `CodeBuildContainerCredentialsServer`, `EksTokenAuthenticator`, `SecretsManagerKmsSupport`. Map: [AGENTS.md](./AGENTS.md#ctf-implementation-map).

After each upstream merge, re-verify CTF hardening on conflict-prone files (`SnsService`, `EcsContainerManager`, `docker-compose.yml`, IAM filters). See [AGENTS.md](./AGENTS.md#upstream-sync).

## Quick start (operators)

Export operator secrets on the host, then start Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

docker compose up
```

All AWS services listen on `http://localhost:4566`. Use the root credentials only for operator provisioning. Issue participant credentials via IAM (`CreateAccessKey`) and scoped policies.

## Required environment variables

| Variable | Purpose |
|---|---|
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `true` in repo Compose: evaluate IAM on every call |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `true`: no permissive fall-through for unknown actions or missing auth |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `true`: verify SigV4 on inbound API requests |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | Operator access key (bypasses enforcement when paired with secret) |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | Operator secret for the root access key |
| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | Default `true`: `404` on `/_floci/*`, `/_localstack/*`, and `/_aws/*`; `all` also hides `/health`; set `false` for upstream-style introspection |
| `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` | Optional; default `false`. When `true`, `X-Forwarded-For` may set `aws:sourceip` in IAM conditions |
| `FLOCI_CTF_CONTAINER_CREDENTIALS_USE_LINK_LOCAL_URI` | Default `true`: inject `http://169.254.170.2/v2/credentials/...` URIs; workload containers need `extra_hosts: 169.254.170.2:host-gateway` |
| `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS` | Optional; default `false`. When `true`, structural JWT/SAML checks plus optional HS256/RS256 verification via `FLOCI_CTF_FEDERATED_JWT_*` |
| `FLOCI_DEFAULT_ACCOUNT_ID` | Optional; account id in IAM ARNs and `GetCallerIdentity` (default `000000000000`) |

These are set in [docker-compose.yml](./docker-compose.yml). Pass root credentials from the host as shown above.

## Operator workflow

1. Start Floci with the CTF env vars. Keep root credentials private.
2. Provision resources with the root pair (bypasses strict enforcement when both match):

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

aws iam create-user --user-name player1
aws iam create-access-key --user-name player1
# attach policies, create buckets, Lambda functions, etc.
```

3. Give participants IAM access keys from `CreateAccessKey`. They must sign every request with SigV4.
4. Confirm enforcement: wrong secret or unregistered keys should return HTTP 403.
5. Operator smoke (default hide hides `/_floci/health`):

```bash
curl -s http://localhost:4566/health | jq .services
```

6. Confirm identity shape (participant keys must **not** report account root unless that is intentional):

```bash
# As participant (briefing AKIA only — not operator root)
aws sts get-caller-identity --endpoint-url "$AWS_ENDPOINT_URL"
# Expect Arn like arn:aws:iam::ACCOUNT:user/player1 — not ...:root
```

Under strict mode, `test`/`test` and other unregistered keys are rejected. Only IAM identities allowed by policy (or the configured root pair) succeed.

**STS notes:** Participants do **not** need `sts:GetCallerIdentity` or `sts:GetSessionToken` in IAM policies (same as AWS). Operator `FLOCI_AUTH_ROOT_*` resolves to `arn:aws:iam::ACCOUNT:root`. Set `FLOCI_DEFAULT_ACCOUNT_ID` when using a non-default account id in ARNs.

## Forensic lab

The root [docker-compose.yml](./docker-compose.yml) layers forensic defaults on top of CTF hardening so audit artifacts and service metadata survive restarts:

| Variable | Compose value | Purpose |
|---|---|---|
| `FLOCI_STORAGE_MODE` | `hybrid` | Async flush of service state to `./data` (mounted at `/app/data`) |
| `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED` | `true` | Record HTTP and in-process API calls to active CloudTrail trails |

Operator setup for a typical evidence chain:

1. Start Compose with operator root credentials (see [Quick start](#quick-start-operators)).
2. Create an S3 bucket, optional SQS queue, and bucket notifications for trail delivery ([CloudTrail docs](./docs/services/cloudtrail.md)).
3. `CreateTrail`, `StartLogging`, and exercise the scenario; review gzip JSON under `AWSLogs/{account-id}/CloudTrail/...` in the trail bucket.
4. Use `LookupEvents` or Athena over trail objects to correlate player HTTP calls with **inter-service** activity (Step Functions tasks, EventBridge targets, Firehose flushes, Config snapshots) recorded with `invokedBy` service principals.

Inter-service audit (when audit is enabled and a trail is logging): Step Functions and API Gateway in-process SDK calls use the execution role plus `invokedBy` (`states.amazonaws.com`, `apigateway.amazonaws.com`). Internal delivery (Firehose to S3, SNS to SQS, CloudWatch Logs subscriptions, S3 access logs) uses `userIdentity.type=AWSService`. See [CloudTrail inter-service events](./docs/services/cloudtrail.md#inter-service-events-in-process-audit).

Hardening: IAM enforcement and SigV4 still apply independently of audit recording. `StopLogging` and `DeleteTrail` are audited and can trigger GuardDuty `DefenseEvasion` findings. CloudTrail IAM actions scope to trail ARNs (`cloudtrail:StopLogging` on `arn:aws:cloudtrail:...:trail/name`).

5. Optional: configure [AWS Config](./docs/services/config.md) delivery channels for configuration snapshots in S3.

Enable S3 access logging for data-plane evidence ([S3 access logging](./docs/services/s3.md#access-logging)). Optional [GuardDuty](./docs/services/guardduty.md) and [Security Hub](./docs/services/securityhub.md) aggregate findings from CloudTrail-driven rules and ASFF imports.

Forensic regression (with CTF core tests):

```bash
./mvnw test -Dtest=CloudForensicsIntegrationTest,CloudTrailIntegrationTest,CloudTrailAuditIntegrationTest,CloudTrailTamperingAuditIntegrationTest,CloudTrailIamScopedIntegrationTest,InProcessCloudTrailIntegrationTest,InternalServiceCloudTrailIntegrationTest,CloudTrailLookupEventsIntegrationTest,ConfigSnapshotDeliveryIntegrationTest,S3AccessLoggingIntegrationTest,Ec2FlowLogsIntegrationTest,CloudWatchLogsSubscriptionIntegrationTest,GuardDutyIntegrationTest,SecurityHubIntegrationTest,CtfComposeParityIntegrationTest,IamEnforcementIntegrationTest
```

Compatibility probes against a running instance ([compatibility-tests/README.md](./compatibility-tests/README.md)):

```bash
cd compatibility-tests && cp env.example .env
# set FLOCI_CTF_PROFILE=ctf, FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true, operator AWS_*
just test-forensic-java
```

Full map: [AGENTS.md forensic services](./AGENTS.md#forensic-services-map).

## Client tooling notes

The local image includes AWS CLI v1 on Alpine. With `FLOCI_AUTH_VALIDATE_SIGNATURES=true`, CLI v1 often returns `SignatureDoesNotMatch` even with valid credentials.

Prefer **boto3** (in the image) or **AWS CLI v2** on the host for operator scripts:

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

## Focused regression tests

**Core CTF hardening:**

```bash
./mvnw test -Dtest=HealthServicesReportingIntegrationTest,CtfHideInternalEndpointsIntegrationTest,ContainerEnvHardeningTest,EcsContainerCredentialsServerTest,LambdaContainerCredentialsServerTest,EksTokenAuthenticatorTest,IamEnforcementIntegrationTest,PolicyPrincipalMatcherTest,StsAssumeRoleTrustIntegrationTest,StsWebIdentityTrustIntegrationTest,SigV4RequestValidatorTest,PreSignedUrlIntegrationTest,StepFunctionsScopedSdkIamIntegrationTest,CognitoOAuthIamEnforcementIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbExecuteStatementScopedIntegrationTest
```

On Windows with Docker Desktop, set `$env:DOCKER_HOST = "npipe:////./pipe/docker_engine"` before tests that spawn containers.

## Documentation in this repo

| Topic | Location |
|---|---|
| Operators, agents, `floci:local` | [AGENTS.md](./AGENTS.md) |
| Fork delta summary (this file) | [README.md](./README.md) |
| CTF hardening and IAM behaviour | [docs/services/iam.md](./docs/services/iam.md#ctf-hardening) |
| Compose CTF profile | [docs/configuration/docker-compose.md](./docs/configuration/docker-compose.md#ctf-security-profile) |
| Forensic lab (CloudTrail, Config, storage) | [docs/services/cloudtrail.md](./docs/services/cloudtrail.md) |
| Compatibility / SDK forensic probes | [compatibility-tests/README.md](./compatibility-tests/README.md) |
| All `FLOCI_*` variables | [docs/configuration/environment-variables.md](./docs/configuration/environment-variables.md) |

Init scripts mounted under `/etc/localstack/init/` run unchanged. The `/_localstack/init` and `/_localstack/health` endpoints are still served. Once the emulator is up, the log also ends with a LocalStack-style `Ready.` line, so tooling that watches the log for it, such as the default wait strategy of Testcontainers' `LocalStackContainer`, works unchanged. Set `LOCALSTACK_PARITY=false` to opt out of automatic translation.

## Upstream highlights

Merged from [floci-io/floci](https://github.com/floci-io/floci) **1.5.24** and follow-on commits:

| Area | Change |
|---|---|
| Cloud Map | New `servicediscovery` management API and docs |
| CloudTrail | Trail lifecycle + audit delivery + LookupEvents |
| Forensic lab | CloudTrail audit, Config snapshots, S3 access logs, VPC Flow Logs, GuardDuty, Security Hub |
| Cognito | Verification code subsystem (SNS/SES inspection) |
| EC2 | Provisioning primitives (launch templates, NAT gateways, VPC endpoints) |
| KMS | Key state and description operations |
| S3 | Range response streaming; relative key rejection |
| AppSync | Phase 2: schema registry, AWS scalars, CRUDL completion |
| IAM | Standard EKS cluster and node group managed policies seeded |
| DynamoDB | Reserved keyword updates; SSE specification persistence |
| Glue | Table version checks enforced |
| Step Functions | `Catch` honored on Lambda task failures |
| EC2 | `AttachTime` in `describe-instances` network interface response |
| EKS | Managed node groups (create/describe/list/delete); IAM REST rules in fork |
| ELBv2 | `DescribeLoadBalancers` availability zones aligned with AWS |
| CloudFormation | `AWS::StepFunctions::StateMachine` provisioning |
| SES | Event publishing to Firehose, EventBridge, CloudWatch |
| EC2 VPC | Default security group and main route table on `CreateVpc` |
| Athena | `CreateWorkGroup` aligned with AWS; scoped `Name` ARN in fork |
| Glue | Catalog name normalization, `BatchDeleteTable`, column parameters |
| Core | `StorageBackedMap` for service state persistence |

**Post-1.5.24 merge (20 commits, 2026-06-13):**

| Area | Change |
|---|---|
| WAFv2 | Phase 1 management API (Web ACLs, IP sets, rule groups, associations, logging) |
| EMR | Phase 1 management API (clusters, steps, instance groups/fleets, security configurations) |
| RDS Data API | REST JSON execute and transaction routes against local RDS MySQL/MariaDB containers |
| Glue | Partition APIs; column statistics |
| SQS | `ApproximateNumberOfMessagesDelayed`; release in-flight long polls when queue deleted |
| ELBv2 | ALB two-AZ subnet rules; target resolution and persistence improvements |
| SES | v2 configuration set inline options; `MailFromAttributes` when MAIL FROM unset |
| EC2 | Image catalog embedded in native image, lazy load |
| MSK | `currentBrokerSoftwareInfo` in describe cluster response |
| Athena | `GetWorkGroup` aligned with AWS |
| Cognito | SRP `PASSWORD_VERIFIER` challenge includes `USERNAME` |
| S3 | SDK ranged-get coverage (upstream test) |

**CTF fork:** IAM enforcement applies to new HTTP surfaces (SigV4 + action mapping). `rds-data`, `elasticmapreduce`, and `wafv2` actions resolve from routes or `X-Amz-Target`; policy `Resource` scoping stays `*` until `ResourceArnBuilder` is extended (same pattern as most JSON 1.1 services).

## Upstream sync

This fork periodically merges [floci-io/floci](https://github.com/floci-io/floci) `main`. Preserve CTF behavior on overlapping files; do not revert IAM enforcement, strict mode, SigV4 validation, `ContainerEnvHardening`, or the SNS default-topic-policy gate when IAM enforcement is on.

**High-risk merge files:** `SnsService.java` (must keep `iamEnforcementEnabled` gate), `EcsContainerManager.java` (must keep `ContainerEnvHardening` on env), `IamEnforcementFilter.java`, `PolicyPrincipalMatcher.java`, `docker-compose.yml`, `docker/Dockerfile`.

**Post-merge regression:**

```bash
./mvnw test -Dtest=SigV4RequestValidatorTest,IamEnforcementIntegrationTest,StsAssumeRoleTrustIntegrationTest,ContainerEnvHardeningTest
```

## Upstream

- Source fork: [floci-io/floci](https://github.com/floci-io/floci)
- License: MIT (same as upstream)
