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

A security-hardened fork of [Floci](https://github.com/floci-io/floci) (currently merged with upstream **1.5.22**) for capture-the-flag and security exercises. Same local AWS emulator on port **4566**, with IAM enforcement, strict policy mode, SigV4 validation, and CTF-specific controls so participants cannot rely on permissive `test`/`test` credentials, unsigned requests, or internal introspection routes.

For service coverage, architecture, SDK examples, and general configuration, use the [upstream Floci README](https://github.com/floci-io/floci/blob/main/README.md) and [docs](https://floci.io/floci/). For operator setup, challenge images, and `floci:local` behavior, see [FLOCI.md](./FLOCI.md).

## What changed

| Area | Upstream Floci | This fork |
|---|---|---|
| IAM enforcement | Off by default | On in `docker-compose.yml` |
| Strict IAM mode | Off by default | On: denies unregistered keys and unknown action mappings |
| SigV4 on API calls | Off by default | On: validates `Authorization` signatures |
| Operator bypass | N/A | `FLOCI_AUTH_ROOT_*` pair bypasses enforcement for provisioning |
| S3 pre-signed URLs | Default HMAC secret | Requires `FLOCI_AUTH_PRESIGN_SECRET` (do not use the default) |
| Docker image defaults | `test`/`test` baked in | No default credentials in `docker/Dockerfile` |
| Payload hashing | N/A | SigV4 validator hashes request bodies when `x-amz-content-sha256` is absent |
| `sts:GetCallerIdentity` / `GetSessionToken` | Evaluated like any action | Policy-exempt (AWS parity): no Allow required; SigV4 and registered keys still apply |
| `sts:GetCallerIdentity` response | Often returns account `:root` | Returns the **calling principal** (IAM user, assumed role, federated user, operator root, or 12-digit account id) |
| Role trust `sts:ExternalId` | Not enforced | Trust policy conditions evaluated on `AssumeRole` |
| Identity policy `Resource` matching | Most requests use `*` | `ResourceArnBuilder` resolves per-service ARNs for identity policies |
| Resource-based policies | Not enforced on HTTP | S3/Lambda/SQS/SNS/KMS/Secrets resource policies in `IamEnforcementFilter`; presigned S3 evaluates bucket policy after HMAC; `NotPrincipal` supported; account `:root` in resource policies does **not** directly allow IAM users (identity policy still required) |
| Lab builder IAM (F1-F10) | Partial / ad hoc | S3 versioning IAM, scoped KMS/SQS/SNS/SSM/CFN/IAM/Secrets actions on HTTP `:4566` with integration tests; see [FLOCI.md](./FLOCI.md#lab-builder-capabilities-p0p1-http-sigv4-on-4566) |
| Health `services` map | Lists all services as `running` or `available` | Only **enabled** services appear as `running`; disabled services omitted |
| Internal introspection routes | `/_floci/*`, `/_localstack/*`, `/health` open | Default `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS=true` hides prefixed routes; `all` also hides `/health` |
| Container env (Lambda, ECS, CodeBuild) | Function/task/build env can set `AWS_*` | `ContainerEnvHardening` blocks credential keys in user-supplied env; only `OperatorCredentialEnv` injects host operator `AWS_*` (Lambda: applied last) |
| EKS kubectl token webhook | Any `k8s-aws-v1.*` accepted as cluster-admin | Hidden under `/_floci/*` by default; with IAM enforcement on, requires plausible presigned STS `GetCallerIdentity` URL (`EksTokenAuthenticator`) |

**Fork-only code (high level):** `IamEnforcementFilter`, `SigV4ValidationFilter`, `ResourcePolicyResolver`, `ResourceArnBuilder`, `AssumeRoleTrustPolicyEvaluator`, `CtfInternalEndpointFilter`, `ContainerEnvHardening`, `OperatorCredentialEnv`, `EksTokenAuthenticator`. Map: [AGENTS.md](./AGENTS.md#ctf-implementation-map).

## Quick start (operators)

Export operator secrets on the host, then start Compose:

```bash
export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
export FLOCI_AUTH_PRESIGN_SECRET="$(openssl rand -hex 32)"
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

docker compose up
```

All AWS services listen on `http://localhost:4566`. Use the root credentials only for challenge setup. Issue participant credentials via IAM (`CreateAccessKey`) and scoped policies.

## Required environment variables

| Variable | Purpose |
|---|---|
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `true` in repo Compose: evaluate IAM on every call |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `true`: no permissive fall-through for unknown actions or missing auth |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `true`: verify SigV4 on inbound API requests |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | Operator access key (bypasses enforcement when paired with secret) |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | Operator secret for the root access key |
| `FLOCI_AUTH_PRESIGN_SECRET` | HMAC secret for Floci S3 pre-signed URLs |
| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | Default `true`: `404` on `/_floci/*` and `/_localstack/*`; `all` also hides `/health`; set `false` for upstream-style introspection |
| `FLOCI_DEFAULT_ACCOUNT_ID` | Optional; account id in IAM ARNs and `GetCallerIdentity` (default `000000000000`) |

These are set in [docker-compose.yml](./docker-compose.yml). Pass root and pre-sign values from the host as shown above.

## Operator workflow

1. Start Floci with the CTF env vars. Keep root credentials private.
2. Provision resources with the root pair (bypasses strict enforcement when both match):

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"

aws iam create-user --user-name challenger
aws iam create-access-key --user-name challenger
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
# Expect Arn like arn:aws:iam::ACCOUNT:user/challenger — not ...:root
```

Under strict mode, `test`/`test` and other unregistered keys are rejected. Only IAM identities allowed by policy (or the configured root pair) succeed.

**STS notes for challenge authors**

- Participants do **not** need `sts:GetCallerIdentity` or `sts:GetSessionToken` in their IAM policies (same as AWS).
- Operator `FLOCI_AUTH_ROOT_*` and 12-digit account-style access keys still resolve to `arn:aws:iam::ACCOUNT:root`.
- Set `FLOCI_DEFAULT_ACCOUNT_ID` (or `floci.default-account-id`) when labs use a non-default account id (e.g. `222222222222`); IAM user ARNs and `GetCallerIdentity` use that account.

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
./mvnw test -Dtest=HealthServicesReportingIntegrationTest,CtfHideInternalEndpointsIntegrationTest,ContainerEnvHardeningTest,EksTokenAuthenticatorTest,IamEnforcementIntegrationTest,StsAssumeRoleTrustIntegrationTest,SigV4RequestValidatorTest,PreSignedUrlIntegrationTest
```

**Lab builder capabilities (F1-F10, HTTP IAM on `:4566`):**

```bash
./mvnw test -Dtest=S3ObjectVersioningIamIntegrationTest,KmsDecryptScopedKeyIntegrationTest,SnsSubscribeReceiveIamIntegrationTest,SqsReceiveMessageScopedQueueIntegrationTest,SsmGetParameterScopedArnIntegrationTest,CloudFormationDescribeStacksScopedIntegrationTest,IamGetPolicyScopedArnIntegrationTest,IamStrictUnmappedActionIntegrationTest,CreatePolicyVersionGrantsSecretReadIntegrationTest,SecretsManagerKmsEnvelopeIntegrationTest,IamActionRegistryTest,ResourceArnBuilderTest
```

On Windows with Docker Desktop, set `$env:DOCKER_HOST = "npipe:////./pipe/docker_engine"` before tests that spawn containers.

## Documentation in this repo

| Topic | Location |
|---|---|
| Operator guide (`floci:local`, players vs operator, F1-F10 matrix) | [FLOCI.md](./FLOCI.md) |
| CTF hardening and IAM behaviour | [docs/services/iam.md](./docs/services/iam.md#ctf-hardening) |
| Agent / implementation map | [AGENTS.md](./AGENTS.md) |
| Compose CTF profile | [docs/configuration/docker-compose.md](./docs/configuration/docker-compose.md#ctf-security-profile) |
| All `FLOCI_*` variables | [docs/configuration/environment-variables.md](./docs/configuration/environment-variables.md) |

## Upstream

- Source fork: [floci-io/floci](https://github.com/floci-io/floci)
- License: MIT (same as upstream)
