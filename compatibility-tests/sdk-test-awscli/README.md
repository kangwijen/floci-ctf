# sdk-test-awscli

Compatibility tests for [Floci](https://github.com/hectorvent/floci) using the **AWS CLI v2 (2.22.35)**.

Tests are plain bash scripts that call `aws` CLI commands with `--endpoint-url` pointed at the emulator.

## Services Covered

| Group              | Description                                          |
| ------------------ | ---------------------------------------------------- |
| `ssm`              | Parameter Store — put, get, path, tags               |
| `sqs`              | Queues, send/receive/delete, attributes              |
| `sns`              | Topics, publish, attributes                          |
| `s3`               | Buckets, objects, tagging, copy, delete              |
| `dynamodb`         | Tables, put/get/update/query/delete items            |
| `iam`              | Users, roles, create/get/delete                      |
| `sts`              | GetCallerIdentity                                    |
| `ses`              | Identities, sending, quotas, notification attributes |
| `secretsmanager`   | Create/get/put/list/tag/delete secrets               |
| `kms`              | Keys, aliases, encrypt/decrypt                       |
| `cognito`          | User pools, clients                                  |
| `s3-notifications` | S3 → SQS event notifications                         |
| `cloudmap`         | HTTP namespace create/list (servicediscovery)        |

## Requirements

- AWS CLI v2
- bash
- jq
- bats-core (installed via `just setup-awscli`)

## Running

```bash
# All groups (from compatibility-tests/)
just test-awscli

# Run bats directly
./lib/run-bats-with-junit.sh sdk-test-awscli/test/ sdk-test-awscli/test-results/junit.xml
```

## Configuration

Shared exports live in [`../lib/ctf-env.sh`](../lib/ctf-env.sh). Copy [`../env.example`](../env.example) to `.env` at the `compatibility-tests/` root when using `just`.

| Variable                | Default                 | Description                          |
| ----------------------- | ----------------------- | ------------------------------------ |
| `FLOCI_ENDPOINT`        | `http://localhost:4566` | Floci emulator endpoint              |
| `AWS_DEFAULT_REGION`    | `us-east-1`             | AWS region                           |
| `AWS_ACCESS_KEY_ID`     | `test`                  | SigV4 access key (see CTF fork below) |
| `AWS_SECRET_ACCESS_KEY` | `test`                  | SigV4 secret key (see CTF fork below) |

### CTF fork (floci-ctf)

Against the hardened Compose image with IAM enforcement, replace `test`/`test` with operator root or participant IAM keys. Unsigned or dummy credentials return `403`. Use `is_ctf_credentials()` and `apply_forensic_profile()` from `lib/ctf-env.sh` in shell helpers.

Forensic lab: after starting floci-ctf Compose, use `aws cloudtrail lookup-events` and `aws s3 ls s3://trail-bucket/AWSLogs/` with registered credentials (audit must be enabled on the emulator).

```bash
export FLOCI_ENDPOINT=http://localhost:4566
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
just test-awscli
```

## Docker

Build from the `compatibility-tests/` directory so `lib/ctf-env.sh` is included:

```bash
cd compatibility-tests
docker build -f sdk-test-awscli/Dockerfile -t floci-sdk-awscli .
docker run --rm --network host floci-sdk-awscli

# Custom endpoint (macOS/Windows)
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-awscli

# CTF fork credentials
docker run --rm --network host \
  -e AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID" \
  -e AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY" \
  floci-sdk-awscli
```
