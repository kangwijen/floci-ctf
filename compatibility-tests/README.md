# floci-compatibility-tests

Compatibility test suite for [floci-ctf](https://github.com/kangwijen/floci-ctf) — a security-hardened local AWS emulator fork.

Verifies that standard AWS tooling (SDKs, CDK, OpenTofu/Terraform) works correctly against the emulator without modification. Tests run against a live Floci instance and use real AWS SDK clients — no mocks.

## CTF fork (floci-ctf)

The main **floci-ctf** repository enables IAM enforcement, strict mode, and SigV4 validation in Compose. Most modules assume permissive `test`/`test` credentials in `.env`; against the hardened image you must:

1. Export operator `FLOCI_AUTH_ROOT_*` (or participant IAM keys from `CreateAccessKey`).
2. Set `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` to registered credentials.
3. Expect unsigned or `test`/`test` calls to return `403`.

`sdk-test-java` includes `IamEnforcementTest`, which **skips** when enforcement is off and runs allow/deny scenarios when `floci.services.iam.enforcement-enabled=true`. Run it against a CTF Compose instance:

```bash
export FLOCI_ENDPOINT=http://localhost:4566
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
cd sdk-test-java && mvn test -Dtest=IamEnforcementTest
```

S3 presign tests use the AWS SDK presigner and work when the signing access key is registered in IAM (or matches the operator root pair).

## Quick Start

```bash
# Install just (task runner)
# macOS: brew install just
# Linux: cargo install just

# Copy and configure environment
cp env.example .env

# Install dependencies
just setup

# Run all tests
just test-all

# Run specific SDK tests
just test-python
just test-typescript
just test-awscli
```

## Test Runners

| Module                                | Language       | Test Framework | Command                |
| ------------------------------------- | -------------- | -------------- | ---------------------- |
| [`sdk-test-python`](sdk-test-python/) | Python 3       | pytest         | `just test-python`     |
| [`sdk-test-node`](sdk-test-node/)     | TypeScript     | vitest         | `just test-typescript` |
| [`sdk-test-awscli`](sdk-test-awscli/) | Bash / AWS CLI | bats-core      | `just test-awscli`     |
| [`sdk-test-java`](sdk-test-java/)     | Java 17        | JUnit 5        | `just test-java`       |
| [`sdk-test-go`](sdk-test-go/)         | Go 1.24        | go test        | `just test-go`         |
| [`sdk-test-rust`](sdk-test-rust/)     | Rust           | cargo-nextest  | `just test-rust`       |

### IaC Compatibility

| Module                                  | Tool       | Command    |
| --------------------------------------- | ---------- | ---------- |
| [`compat-cdk`](compat-cdk/)             | AWS CDK v2 | `./run.sh` |
| [`compat-opentofu`](compat-opentofu/)   | OpenTofu   | `./run.sh` |
| [`compat-terraform`](compat-terraform/) | Terraform  | `./run.sh` |

## Prerequisites

- **Floci running** on `http://localhost:4566` (or set `FLOCI_ENDPOINT`)
- **Docker** — required for Lambda invocation tests
- **just** — task runner for orchestration

Per-module requirements:

| Module            | Requirements                        |
| ----------------- | ----------------------------------- |
| `sdk-test-python` | Python 3.9+, pip                    |
| `sdk-test-node`   | Node.js 20+, npm, vitest            |
| `sdk-test-awscli` | AWS CLI v2, bash, jq                |
| `sdk-test-java`   | Java 17+, Maven                     |
| `sdk-test-go`     | Go 1.24+                            |
| `sdk-test-rust`   | Rust (stable), Cargo, cargo-nextest |

## Setup

```bash
# Setup all SDKs
just setup

# Setup individual SDKs
just setup-python      # pip install -r requirements.txt
just setup-typescript  # npm install
just setup-awscli      # Clone bats-core, bats-support, bats-assert
```

## Running Tests

### All SDKs

```bash
just test-all
```

### Individual SDKs

```bash
# Python (pytest)
just test-python

# TypeScript (vitest)
just test-typescript

# AWS CLI (bats-core)
just test-awscli
```

Bats-based suites keep their normal console output and also write JUnit XML reports:

- `sdk-test-awscli/test-results/junit.xml`
- `compat-cdk/test-results/junit.xml`
- `compat-terraform/test-results/junit.xml`
- `compat-opentofu/test-results/junit.xml`

## Configuration

All modules read from environment variables (see `env.example`):

```bash
FLOCI_ENDPOINT=http://localhost:4566
AWS_DEFAULT_REGION=us-east-1

# Permissive mode (default for most suite tests):
AWS_ACCESS_KEY_ID=test
AWS_SECRET_ACCESS_KEY=test

# CTF fork: replace with IAM or operator root credentials
```

Copy `env.example` to `.env` and adjust for your Floci profile.

## Running with Docker

Each module includes a `Dockerfile` for isolated execution:

```bash
# Python
docker build -t floci-sdk-python sdk-test-python/
docker run --rm --network host floci-sdk-python pytest

# TypeScript
docker build -t floci-sdk-node sdk-test-node/
docker run --rm --network host floci-sdk-node npm test
```

On macOS/Windows, use `host.docker.internal` instead of `localhost`:

```bash
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-python pytest
```

## Exit Codes

All test runners exit `0` on full pass and non-zero if any test fails — suitable for CI pipelines.
