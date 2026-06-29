# sdk-test-java

Compatibility tests for **floci-ctf** (this repository) using the **AWS SDK for Java v2 (2.31.8)**.

Aligned with upstream Floci **1.5.24** and the **floci-ctf** security-hardened fork.

Runs against a live Floci instance — no mocks.

## Services Covered

| Test class                       | Description                                              |
| -------------------------------- | -------------------------------------------------------- |
| `SsmTest`                        | Parameter Store — put, get, path, tags                   |
| `SqsTest`                        | Queues, send/receive/delete, DLQ, visibility             |
| `SnsTest`                        | Topics, subscriptions, publish, SQS delivery             |
| `S3Test`                         | Buckets, objects, tagging, copy, multipart, batch delete |
| `DynamoDbTest`                   | Tables, CRUD, batch, TTL, tags, streams                  |
| `DynamoDbScanConditionTests`     | Scan filter and condition expressions                    |
| `LambdaTest`                     | Create/invoke/update/delete functions                    |
| `IamTest`                        | Users, roles, policies, access keys                      |
| `StsTest`                        | GetCallerIdentity, AssumeRole, GetSessionToken           |
| `SecretsManagerTest`             | Create/get/put/list/delete secrets, versioning, tags     |
| `KmsTest`                        | Keys, aliases, encrypt/decrypt, data keys, sign/verify   |
| `CloudWatchTest`                 | PutMetricData, ListMetrics, GetMetricStatistics, alarms  |
| `CloudMapTest`                   | Cloud Map namespaces, services, instances, discovery     |
| `CloudMapIamEnforcementIntegrationTest` | Cloud Map deny/allow under IAM enforcement |
| `CloudFormationVirtualHostTests` | Virtual host style S3 access via CloudFormation          |
| `ApigwSfnJsonataCrudlTests`      | API Gateway + Step Functions JSONata CRUDL integration   |
| `ApiGatewayV2WebSocketAndExtendedOpsTest` | API GW v2 WebSocket APIs, Update ops, Route/Integration Responses, Models, Tagging |
| `Ec2Tests`                       | EC2 instances, VPCs, security groups, subnets            |
| `AppSyncTest`                    | GraphQL API CRUDL, data sources, resolvers, functions, types, API keys, tags, schema validation |
| `AppSyncIamEnforcementIntegrationTest` | AppSync deny/allow under IAM enforcement |
| `EcsTests`                       | ECS clusters, task definitions, services                 |
| `CloudTrailTest`                 | Trail lifecycle (CreateTrail, StartLogging, DeleteTrail)   |
| `ForensicLabCompatibilityTest`   | Audit delivery, LookupEvents, S3 log objects, GuardDuty/Security Hub JSON API (skips when audit off) |
| `IamEnforcementTest`             | IAM allow/deny scenarios when enforcement is on          |

## Adding a New Test

Create a standard JUnit 5 test class in `src/test/java/com/floci/test/`. Tests run against a live Floci instance using real AWS SDK clients.

## Requirements

- Java 17+
- Maven

## Running

```bash
# All tests
mvn test -q

# Specific test class
mvn test -Dtest=S3Test

# Via just (from compatibility-tests/)
just test-java
```

## Configuration

| Variable         | Default                 | Description             |
| ---------------- | ----------------------- | ----------------------- |
| `FLOCI_ENDPOINT` | `http://localhost:4566` | Floci emulator endpoint |
| `AWS_ACCESS_KEY_ID` | `test` (permissive) | IAM or operator root when enforcement is on |
| `AWS_SECRET_ACCESS_KEY` | `test` (permissive) | Matching secret |
| `AWS_DEFAULT_REGION` | `us-east-1` | Region |

`TestFixtures` reads `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for all SDK clients. In permissive mode the defaults (`test`/`test`) work unchanged. Against **floci-ctf** Compose with IAM enforcement, export operator root or participant IAM keys before running tests.

### IAM enforcement (CTF fork)

`TestFixtures.isIamEnforcementEnabled()` probes at runtime (unsigned IAM user, `s3:ListAllMyBuckets` → 403 means enforcement is on).

`IamEnforcementTest` and `CloudMapIamEnforcementIntegrationTest` skip all cases when enforcement is off. Against **floci-ctf** Compose, set operator or provisioned IAM credentials and run:

```bash
export FLOCI_ENDPOINT=http://localhost:4566
export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
mvn test -Dtest=IamEnforcementTest
mvn test -Dtest=CloudMapIamEnforcementIntegrationTest
```

Other test classes still default to `test`/`test` and expect permissive mode unless you override credentials globally.

### Audit exercise (floci-ctf)

When the emulator runs with `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true` (Compose default):

```bash
export FLOCI_CLOUDTRAIL_AUDIT_ENABLED=true
mvn test -Dtest=ForensicLabCompatibilityTest,CloudTrailTest
```

Or `just test-forensic-java` from `compatibility-tests/`. Probes HTTP audit and trail delivery; in-process events (Firehose, EventBridge, SFN) appear in `LookupEvents` when those features are exercised in the main emulator test suite.

GuardDuty and Security Hub use Floci JSON 1.1 targets via `TestFixtures.postJson11`, not AWS SDK REST clients.

### CI (floci-ctf fork)

`.github/workflows/compatibility.yml` runs `ctf-compat-java` on pull requests: Floci starts with CTF Compose-equivalent env (IAM enforcement, strict mode, SigV4, CloudTrail audit) and executes `IamEnforcementTest` and `ForensicLabCompatibilityTest`.

Run the broader local probe set (adds Cloud Map, AppSync enforcement, and audit exercise probes):

```bash
cd compatibility-tests && just test-ctf-java
cd compatibility-tests && just test-forensic-java
cd compatibility-tests && just test-ctf-forensic-java
```

## Docker

```bash
docker build -t floci-sdk-java .
docker run --rm --network host floci-sdk-java

# Custom endpoint (macOS/Windows)
docker run --rm -e FLOCI_ENDPOINT=http://host.docker.internal:4566 floci-sdk-java
```
