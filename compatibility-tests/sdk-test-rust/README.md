# sdk-test-rust

Compatibility tests for [Floci](https://github.com/hectorvent/floci) using the **AWS SDK for Rust (1.8.15)**.

## Services Covered

| Group              | Description                                             |
| ------------------ | ------------------------------------------------------- |
| `ssm`              | Parameter Store — put, get, path                        |
| `sqs`              | Queues, send/receive/delete, visibility                 |
| `sns`              | Topics, subscriptions, publish                          |
| `s3`               | Buckets, objects, tagging, copy, delete                 |
| `s3-cors`          | CORS configuration                                      |
| `s3-notifications` | S3 event notifications                                  |
| `dynamodb`         | Tables, CRUD, batch                                     |
| `lambda`           | Create/invoke/update/delete functions                   |
| `iam`              | Users, roles, policies, access keys                     |
| `sts`              | GetCallerIdentity                                       |
| `kms`              | Keys, aliases, encrypt/decrypt                          |
| `secretsmanager`   | Create/get/put/list/delete secrets                      |
| `kinesis`          | Streams, shards, PutRecord/GetRecords                   |
| `cloudwatch`       | PutMetricData, ListMetrics, GetMetricStatistics, alarms |
| `cloudformation`   | Stack operations                                        |
| `cloudmap`         | HTTP namespace, service, instance registration        |

## Requirements

- Rust (stable)
- Cargo
- cargo-nextest

## Running

```bash
# All groups
cargo nextest run --profile ci

# Specific groups
cargo nextest run --profile ci -E 'test(ssm) | test(sqs) | test(s3)'

# Via just (from compatibility-tests/)
just test-rust
```

## Configuration

| Variable                | Default                 | Description             |
| ----------------------- | ----------------------- | ----------------------- |
| `FLOCI_ENDPOINT`        | `http://localhost:4566` | Floci emulator endpoint |
| `AWS_ACCESS_KEY_ID`     | `test`                  | IAM or operator root when enforcement is on |
| `AWS_SECRET_ACCESS_KEY` | `test`                  | Matching secret         |
| `AWS_DEFAULT_REGION`    | `us-east-1`             | Region                  |

### CTF fork ([floci-ctf](https://github.com/kangwijen/floci-ctf))

Most tests default to permissive `test`/`test` credentials. Against the hardened CTF image, export operator `FLOCI_AUTH_ROOT_*` or participant IAM keys as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. Cloud Map tests skip when `servicediscovery` is disabled in the emulator.

Audit exercise: see `sdk-test-java` `ForensicLabCompatibilityTest` and [compatibility-tests README](../README.md).

## Docker

```bash
docker build -t floci-sdk-rust .
docker run --rm --network host floci-sdk-rust

# Custom endpoint (macOS/Windows)
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-rust
```
