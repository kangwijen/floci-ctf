# sdk-test-python

Compatibility tests for [Floci](https://github.com/hectorvent/floci) using **boto3 (1.37.1)**.

## Services Covered

| Group                   | Description                                                              |
| ----------------------- | ------------------------------------------------------------------------ |
| `ssm`                   | Parameter Store — put, get, label, history, path, tags                   |
| `sqs`                   | Queues, send/receive/delete, DLQ, visibility                             |
| `sns`                   | Topics, subscriptions, publish, SQS delivery                             |
| `s3`                    | Buckets, objects, tagging, copy, batch delete                            |
| `s3-cors`               | CORS configuration                                                       |
| `s3-notifications`      | S3 → SQS event notifications                                             |
| `dynamodb`              | Tables, CRUD, batch, TTL, tags                                           |
| `lambda`                | Create/invoke/update/delete functions                                    |
| `iam`                   | Users, roles, policies, access keys                                      |
| `sts`                   | GetCallerIdentity, AssumeRole, GetSessionToken                           |
| `secretsmanager`        | Create/get/put/list/delete secrets, versioning, tags                     |
| `kms`                   | Keys, aliases, encrypt/decrypt, data keys, sign/verify                   |
| `kinesis`               | Streams, shards, PutRecord/GetRecords                                    |
| `cloudwatch-metrics`    | PutMetricData, ListMetrics, GetMetricStatistics, alarms                  |
| `cloudformation-naming` | Auto physical name generation, explicit name precedence, cross-reference |
| `cognito`               | User pools, clients, AdminCreateUser, InitiateAuth, GetUser              |
| `cloudmap`              | HTTP namespace, service, instance registration                           |

## Requirements

- Python 3.9+
- pip

## Running

```bash
pip install -r requirements.txt

# All groups
pytest tests/ --junit-xml=test-results/junit.xml

# Specific tests
pytest tests/test_s3.py

# Via just (from compatibility-tests/)
just test-python
```

## Configuration

| Variable                | Default                 | Description             |
| ----------------------- | ----------------------- | ----------------------- |
| `FLOCI_ENDPOINT`        | `http://localhost:4566` | Floci emulator endpoint |
| `AWS_ACCESS_KEY_ID`     | `test`                  | IAM or operator root when enforcement is on |
| `AWS_SECRET_ACCESS_KEY` | `test`                  | Matching secret         |
| `AWS_DEFAULT_REGION`    | `us-east-1`             | Region                  |

### CTF fork (floci-ctf, this repository)

Most tests default to permissive `test`/`test` credentials. Against the hardened CTF image, export operator `FLOCI_AUTH_ROOT_*` or participant IAM keys as `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY`. Cloud Map tests skip when `servicediscovery` is disabled.

Audit exercise: with `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`, use boto3 `cloudtrail` client for trail lifecycle and `lookup_events` after API activity. GuardDuty/Security Hub require JSON 1.1 HTTP (see `sdk-test-java` `ForensicLabCompatibilityTest`).

## Docker

```bash
docker build -t floci-sdk-python .
docker run --rm --network host floci-sdk-python

# Custom endpoint (macOS/Windows)
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-python
```
