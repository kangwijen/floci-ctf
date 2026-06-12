# floci-compatibility-tests

Compatibility test suite for [floci-ctf](https://github.com/kangwijen/floci-ctf) — a security-hardened local AWS emulator fork (upstream **1.5.24**).

Verifies that standard AWS tooling (SDKs, CDK, OpenTofu/Terraform) works correctly against the emulator without modification. Tests run against a live Floci instance and use real AWS SDK clients — no mocks.

## Upstream 1.5.24 highlights

Merged from [floci-io/floci](https://github.com/floci-io/floci) tag **1.5.24**:

| Area | Change |
| --- | --- |
| CloudTrail | Trail lifecycle API |
| Cloud Map | `servicediscovery` management API |
| Cognito | Verification code subsystem |
| EC2 | Provisioning primitives, VPC Flow Logs (fork) |
| KMS | Key state and description operations |
| S3 | Range streaming; server access logging (fork) |
| Glue | Database tags, batch delete table |

`sdk-test-java` covers **CloudTrail** (`CloudTrailTest`), **Cloud Map** (`CloudMapTest`), and **AppSync** (`AppSyncTest`). Forensic lab probes: `ForensicLabCompatibilityTest`.

## CTF fork (floci-ctf)

The main **floci-ctf** repository enables IAM enforcement, strict mode, SigV4 validation, and forensic defaults in Compose:

| Compose variable | Value | Purpose |
| --- | --- | --- |
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `true` | IAM on every API call |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `true` | Deny unregistered keys |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `true` | SigV4 required |
| `FLOCI_STORAGE_MODE` | `hybrid` | Durable lab state in `./data` |
| `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED` | `true` | Live API audit to trail S3 buckets |

Most modules assume permissive `test`/`test` credentials in `.env`; against the hardened image you must:

1. Set `FLOCI_CTF_PROFILE=ctf` in `.env` (see `env.example`).
2. Export operator `FLOCI_AUTH_ROOT_*` (or participant IAM keys from `CreateAccessKey`).
3. Set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` to registered credentials.
4. Set `FLOCI_IAM_ENFORCEMENT=true` when targeting an enforcement-enabled instance.
5. For forensic probes, set `FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true` (Compose default).
6. Expect unsigned or `test`/`test` calls to return `403`.

Shared helpers: [`lib/ctf-env.sh`](lib/ctf-env.sh) (`apply_ctf_profile`, `apply_forensic_profile`).

### CTF-focused Java tests

| Test class | Purpose |
| --- | --- |
| `IamEnforcementTest` | Allow/deny IAM policy scenarios when enforcement is on |
| `CloudMapIamEnforcementIntegrationTest` | Cloud Map API under IAM enforcement |
| `AppSyncIamEnforcementIntegrationTest` | AppSync CreateGraphqlApi under IAM enforcement |
| `ForensicLabCompatibilityTest` | CloudTrail LookupEvents + S3 logs + GuardDuty/Security Hub JSON API (skips when audit off) |
| `CloudTrailTest` | Trail lifecycle via AWS SDK |

Run against a CTF Compose instance:

```bash
cp env.example .env
# edit .env: FLOCI_CTF_PROFILE=ctf, FLOCI_IAM_ENFORCEMENT=true, FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true, FLOCI_AUTH_ROOT_*, AWS_*

just test-ctf-java
just test-forensic-java
just test-ctf-forensic-java
```

## Quick Start

```bash
# Copy and configure environment
cp env.example .env

# Install dependencies
just setup

# Run all SDK tests (permissive profile)
just test-all

# CTF enforcement probes
just test-ctf-java

# Forensic lab probes (audit + LookupEvents + GuardDuty/Security Hub)
just test-forensic-java

# IaC compatibility (CDK, Terraform, OpenTofu)
just test-compat
```

## Test matrix

| Module | Language / tool | Command | CTF enforcement | Forensic |
| --- | --- | --- | --- | --- |
| [`sdk-test-python`](sdk-test-python/) | Python 3 / pytest | `just test-python` | permissive | trail lifecycle via boto3 optional |
| [`sdk-test-node`](sdk-test-node/) | TypeScript / vitest | `just test-typescript` | permissive | — |
| [`sdk-test-awscli`](sdk-test-awscli/) | Bash / bats-core | `just test-awscli` | sources `lib/ctf-env.sh` | — |
| [`sdk-test-java`](sdk-test-java/) | Java 17 / JUnit 5 | `just test-java` | permissive default | `just test-forensic-java` |
| [`sdk-test-java`](sdk-test-java/) | Java 17 / JUnit 5 | `just test-ctf-java` | **required** | optional in `test-ctf-forensic-java` |
| [`sdk-test-go`](sdk-test-go/) | Go 1.24 / go test | `just test-go` | permissive | — |
| [`sdk-test-rust`](sdk-test-rust/) | Rust / cargo-nextest | `just test-rust` | permissive | — |
| [`compat-cdk`](compat-cdk/) | AWS CDK v2 | `just test-cdk` | registered keys | deploy stacks with trail/S3 buckets |
| [`compat-terraform`](compat-terraform/) | Terraform | `just test-terraform` | registered keys | same |
| [`compat-opentofu`](compat-opentofu/) | OpenTofu | `just test-opentofu` | registered keys | same |

## Prerequisites

- **Floci running** on `http://localhost:4566` (or set `FLOCI_ENDPOINT`)
- **Docker** — required for Lambda invocation tests
- **just** — task runner for orchestration

## Configuration

All modules read from environment variables. Copy `env.example` to `.env` (loaded by `just` via `dotenv-load`):

```bash
FLOCI_ENDPOINT=http://localhost:4566
AWS_DEFAULT_REGION=us-east-1

# Permissive profile (default for most suite tests):
FLOCI_CTF_PROFILE=permissive
FLOCI_IAM_ENFORCEMENT=false
FLOCI_CLOUDTRAIL_AUDIT_ENABLED=false
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test

# CTF + forensic profile (floci-ctf Compose):
# FLOCI_CTF_PROFILE=ctf
# FLOCI_IAM_ENFORCEMENT=true
# FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true
# AWS_ACCESS_KEY_ID=AKIA...
# AWS_SECRET_ACCESS_KEY=...
# FLOCI_AUTH_ROOT_ACCESS_KEY_ID=AKIA...
# FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY=...
```

GuardDuty and Security Hub in floci-ctf use **JSON 1.1** (`X-Amz-Target`), not AWS SDK REST clients. Use `ForensicLabCompatibilityTest` or raw HTTP for those services.

## Running with Docker

Each module includes a `Dockerfile` for isolated execution:

```bash
docker build -t floci-sdk-java sdk-test-java/
docker run --rm --network host \
  -e FLOCI_ENDPOINT=http://localhost:4566 \
  -e FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true \
  -e AWS_ACCESS_KEY_ID=AKIA... \
  -e AWS_SECRET_ACCESS_KEY=... \
  floci-sdk-java mvn test -Dtest=ForensicLabCompatibilityTest
```

On macOS/Windows, use `host.docker.internal` instead of `localhost`.

## Exit Codes

All test runners exit `0` on full pass and non-zero if any test fails — suitable for CI pipelines.

## Related docs

- Fork operator guide: [../README.md](../README.md#forensic-lab)
- Agent map: [../AGENTS.md](../AGENTS.md#forensic-services-map)
- CloudTrail service: [../docs/services/cloudtrail.md](../docs/services/cloudtrail.md)
