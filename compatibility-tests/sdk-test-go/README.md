# sdk-test-go

Compatibility tests for [Floci](https://github.com/hectorvent/floci) using the **AWS SDK for Go v2 (1.41.4)**.

## Services Covered

| Group              | Description                                             |
| ------------------ | ------------------------------------------------------- |
| `ssm`              | Parameter Store — put, get, label, history, path, tags  |
| `sqs`              | Queues, send/receive/delete, DLQ, visibility            |
| `sns`              | Topics, subscriptions, publish, SQS delivery            |
| `s3`               | Buckets, objects, tagging, copy, batch delete           |
| `s3-cors`          | CORS configuration                                      |
| `s3-notifications` | S3 → SQS event notifications                            |
| `dynamodb`         | Tables, CRUD, batch, TTL, tags                          |
| `lambda`           | Create/invoke/update/delete functions                   |
| `iam`              | Users, roles, policies, access keys                     |
| `sts`              | GetCallerIdentity, AssumeRole, GetSessionToken          |
| `secretsmanager`   | Create/get/put/list/delete secrets, versioning, tags    |
| `kms`              | Keys, aliases, encrypt/decrypt, data keys, sign/verify  |
| `kinesis`          | Streams, shards, PutRecord/GetRecords                   |
| `cloudwatch`       | PutMetricData, ListMetrics, GetMetricStatistics, alarms |
| `cloudmap`         | HTTP namespace, service, instance registration          |
| `rds-data`         | RDS Data API execute statements, transactions, result fields with SDK v1 and v2 |

## Requirements

- Go 1.24+

## Running

```bash
# All groups
gotestsum --junitfile test-results.xml ./tests/...

# Specific tests
go test ./tests/ -run TestSsm

# Via just (from compatibility-tests/)
just test-go
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

Audit exercise: with CloudTrail audit enabled on the emulator, verify trail buckets and `AWSLogs/` prefixes via the `s3` client after API activity (see [compatibility-tests README](../README.md)).

## Docker

```bash
docker build -t floci-sdk-go .
docker run --rm --network host floci-sdk-go

# Custom endpoint (macOS/Windows)
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-go
```
