# CloudTrail

**Protocol:** JSON 1.1 (`X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.*`)
**Endpoint:** `POST http://localhost:4566/`

Floci implements CloudTrail trail lifecycle, `LookupEvents`, and optional HTTP audit recording when `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`. Trails and their event selectors persist in Floci storage. For the canonical supported-operation count across all services, see [Services Overview](index.md).

## Supported Actions

| Action | Description |
|---|---|
| `CreateTrail` | Create a trail with an S3 bucket name and optional tags |
| `UpdateTrail` | Update bucket name and global/multi-region flags |
| `DescribeTrails` | List trails, optionally filtered by name |
| `StartLogging` | Mark a trail as logging |
| `StopLogging` | Stop logging on a trail |
| `DeleteTrail` | Delete a trail |
| `GetTrailStatus` | Return `IsLogging` and `LatestDeliveryTime` |
| `PutEventSelectors` | Accept event selector configuration |
| `GetEventSelectors` | Return event selectors; sensible defaults when none were configured |
| `LookupEvents` | Query indexed management events (time range, attributes, pagination) |

## Trail lifecycle

Typical operator flow for an audit exercise:

1. Create an S3 bucket (and optional SQS queue for near-real-time fan-out via bucket notifications).
2. Attach a bucket policy allowing `cloudtrail.amazonaws.com` to `s3:PutObject` under `AWSLogs/`. Optional `Condition` keys such as `StringEquals.aws:SourceArn` (trail ARN) are evaluated on delivery; mismatched trail ARNs are denied.
3. `CreateTrail` with `S3BucketName`, then `PutEventSelectors` (optional), then `StartLogging`.
4. `GetEventSelectors` returns configured selectors or defaults (`ReadWriteType=All`, `IncludeManagementEvents=true`, no data-resource selectors).
5. `GetTrailStatus` reports `IsLogging=true` and a `LatestDeliveryTime` after deliveries occur.

Trails persist in Floci storage (`cloudtrail-trails.json`) using the global or per-service storage mode. With `FLOCI_STORAGE_MODE=hybrid` (Compose audit default), trail metadata survives restarts under `./data` on the mounted volume.

## Audit recording

| Variable | Default (dev YAML) | Compose audit default | Description |
|---|---|---|---|
| `FLOCI_SERVICES_CLOUDTRAIL_ENABLED` | `true` | `true` | Enable the CloudTrail JSON API |
| `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED` | `false` | `true` | `CloudTrailAuditFilter` records signed management API calls when at least one trail is logging |
| `FLOCI_SERVICES_CLOUDTRAIL_EXCLUDE_INTERNAL_PATHS` | `/_floci,/_localstack,/_aws,/health` | same | Path prefixes skipped by the audit recorder |
| `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER` | `false` | `false` | When `true`, honor `X-Floci-CloudTrail-Source-Ip` for audit `sourceIPAddress` |
| `FLOCI_CTF_CLOUDTRAIL_INJECTION_ENABLED` | `false` | `false` | Operator-only `POST /_floci/cloudtrail/events*` (requires root AKID; still 404 when internal paths hidden) |

When `audit-enabled` is `true`, Floci emits CloudTrail-shaped management events for API traffic on port `4566` that is not matched by `exclude-internal-paths`. Events are indexed for `LookupEvents` and buffered to active trails (`IsLogging=true`) for S3 delivery.

`CloudTrailAuditFilter` records mutating CloudTrail control-plane calls (`CreateTrail`, `UpdateTrail`, `DeleteTrail`, `StartLogging`, `StopLogging`, `PutEventSelectors`) so tampering is visible in `LookupEvents` and S3 delivery. Read-only CloudTrail APIs (`LookupEvents`, `DescribeTrails`, `GetTrailStatus`) are skipped to avoid noise. Mutating CloudTrail calls bypass the active-trail gate so `StopLogging` is still indexed after the handler disables logging.

GuardDuty raises findings for `StopLogging` and `DeleteTrail` audit events when a detector is enabled (`DefenseEvasion:CloudTrail/*`).

Global services (IAM, STS, CloudFront, Route53, WAF) deliver to trails with `IncludeGlobalServiceEvents=true` even when the request region differs from the trail home region.

## Inter-service events (in-process audit)

When `audit-enabled` is `true` and at least one trail is logging, `InProcessCloudTrailRecorder` emits CloudTrail-shaped events for selected service-to-service calls that never hit the HTTP `:4566` filter. Events use `userIdentity.type=AWSService` with `invokedBy` set to the calling service.

| Caller | Target action | `eventSource` | `invokedBy` | Identity |
|---|---|---|---|---|
| Step Functions | aws-sdk / Lambda task | target service (e.g. `s3.amazonaws.com`) | `states.amazonaws.com` | AssumedRole (state machine role) |
| API Gateway integration | AWS proxy integration | target service | `apigateway.amazonaws.com` | AssumedRole (integration credentials) |
| Config snapshot delivery | S3 `PutObject` | `s3.amazonaws.com` | `config.amazonaws.com` | AWSService |
| EC2 VPC Flow Logs | S3 `PutObject` or CloudWatch Logs | `s3.amazonaws.com` / `logs.amazonaws.com` | `ec2.amazonaws.com` | AWSService |
| EventBridge | Lambda invoke | `lambda.amazonaws.com` | `events.amazonaws.com` | AWSService |
| EventBridge | SQS `SendMessage` | `sqs.amazonaws.com` | `events.amazonaws.com` |
| EventBridge | SNS `Publish` | `sns.amazonaws.com` | `events.amazonaws.com` |
| CloudWatch Logs subscription | Lambda / Firehose / Kinesis delivery | `lambda.amazonaws.com`, `firehose.amazonaws.com`, or `kinesis.amazonaws.com` | `logs.amazonaws.com` |
| SNS topic delivery | SQS / Lambda fan-out | `sqs.amazonaws.com` or `lambda.amazonaws.com` | `sns.amazonaws.com` |
| S3 access logging | Access log `PutObject` | `s3.amazonaws.com` | `s3.amazonaws.com` |
| Firehose S3 flush | Destination `PutObject` | `s3.amazonaws.com` | `firehose.amazonaws.com` |

These events are indexed for `LookupEvents` and delivered to active trails like HTTP audit records. Firehose destination `PutObject` events are recorded as data events (`eventCategory=Data`). For AWSService identities, `sourceIPAddress` and `userAgent` echo the `invokedBy` service endpoint.

In-process SQS targets (EventBridge `SendMessage`, API Gateway integrations, Step Functions aws-sdk tasks) record `requestParameters.queueUrl` even when callers pass PascalCase `QueueUrl` in JSON bodies; `CloudTrailEventRecorder.normalizeSqsAuditParameters` maps to the same lowercase keys as HTTP audit. Regression: `InProcessCloudTrailIntegrationTest` (`apigwRouterRecordsSqsSendMessageQueueUrl`, `eventBridgeInvokerRecordsSqsSendMessageQueueUrl`, `sfnStyleRecorderRecordsSqsSendMessageQueueUrl`).

## Event delivery and S3 layout

Delivered log objects use the AWS key layout:

```
s3://{bucket}/AWSLogs/{account-id}/CloudTrail/{region}/{yyyy}/{MM}/{dd}/{account-id}_CloudTrail_{region}_{yyyyMMddTHHmmssZ}.json.gz
```

Each object is a gzip-compressed JSON array of management events. Fields include `eventVersion`, `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userIdentity`, `requestParameters`, `responseElements`, `resources`, `eventCategory`, `managementEvent`, `readOnly`, and `eventID`.

HTTP audit events follow AWS CloudTrail record semantics where practical:

| Area | Behavior |
|---|---|
| Data vs management | S3 object APIs (`PutObject`, `GetObject`, `DeleteObject`, ...) and SQS data plane (`SendMessage`, `ReceiveMessage`, ...) set `eventCategory: Data` and `managementEvent: false`. `PurgeQueue` and control-plane APIs stay `Management`. |
| `resources` | Populated from `ResourceArnBuilder` with CloudFormation-style `type` (`AWS::S3::Object`, `AWS::SQS::Queue`, `AWS::IAM::Role`, `AWS::SecretsManager::Secret`, `AWS::CloudTrail::Trail`, ...). S3 object events also include the parent bucket ARN. |
| `requestParameters` | SQS data-plane calls (`ReceiveMessage`, `SendMessage`, `PurgeQueue`) include `queueUrl` on Query (`application/x-www-form-urlencoded`) and JSON 1.0 (`application/x-amz-json-1.0`) wire protocols. JSON 1.0 `PurgeQueue` (`X-Amz-Target: AmazonSQS.PurgeQueue`, body `QueueUrl`) records `requestParameters.queueUrl` and stays `eventCategory: Management`. `SendMessage` also records `messageBody` with the submitted payload. In-process SQS audit (`InProcessCloudTrailRecorder`) normalizes PascalCase `QueueUrl` / `MessageBody` to lowercase `queueUrl` / `messageBody` for HTTP parity. S3 `ListObjectsV2` (`?list-type=2`) records `eventName: ListObjectsV2` (v1 list APIs remain `ListBucket`). |
| `responseElements` | S3 versioned writes/deletes expose `x-amz-version-id` / `x-amz-delete-marker` from response headers. STS `AssumeRole` includes `credentials.accessKeyId` and `assumedRoleUser` (no secret key). IAM `CreateAccessKey` includes `accessKey` metadata. SQS `SendMessage` includes `messageId`. |
| `userIdentity` | IAM users include `sessionContext.attributes` (`mfaAuthenticated`, `creationDate`). Assumed-role sessions include `sessionContext.sessionIssuer`. |
| `additionalEventData` | SigV4 HTTP calls include `SignatureVersion` (`AWS4-HMAC-SHA256`) and `AuthenticationMethod` (`AuthHeader` or `QueryString`) when applicable. |
| `tlsDetails` | When `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` and `X-Forwarded-Proto: https`, includes synthetic `tlsVersion`, `cipherSuite`, and `clientProvidedHostHeader` (same pattern as S3 access logs). |

### Data-plane `requestParameters` (HTTP audit)

| Service | Event | Recorded fields | Notes |
|---------|-------|-----------------|-------|
| SQS | `SendMessage`, `ReceiveMessage`, ... | `queueUrl`, `messageBody` (SendMessage) | Data events when applicable |
| KMS | `Decrypt`, `Encrypt`, ... | `keyId`, `encryptionAlgorithm`, `encryptionContext` | `CiphertextBlob` / `Plaintext` omitted; `keyId` resolved from explicit `KeyId`, response `KeyId`, or Floci `kms:v2:` envelope; `encryptionContext` copied from request body when set |
| SNS | `Publish` | `topicArn` | Query and JSON bodies |
| DynamoDB | `PutItem`, `GetItem`, ... | `tableName` | JSON `TableName` normalized to lowercase AWS shape; Floci HTTP audit uses `eventCategory: Management` (AWS records data events only when trail data selectors include DynamoDB) |
| S3 | object APIs | `bucketName`, `key` | REST path derived |

`resources[]` includes `AWS::KMS::Key`, `AWS::SNS::Topic`, and `AWS::DynamoDB::Table` when the scoped ARN resolves.

Regression: `CloudTrailFieldFidelityIntegrationTest`, `CloudTrailSqsAuditIntegrationTest`, `CloudTrailKmsDecryptAuditIntegrationTest`, `CloudTrailSnsPublishAuditIntegrationTest`, `CloudTrailDynamoDbPutItemAuditIntegrationTest`, `CloudTrailS3DeliveryIntegrationTest`, `CloudTrailLookupEventsIntegrationTest`, `CloudTrailEventRecorderTest`.

`LatestDeliveryTime` on `GetTrailStatus` updates when events flush to the trail bucket (default buffer size: 10 events per trail).

## LookupEvents

`LookupEvents` searches the in-memory or persisted event index populated by the audit filter and test helpers. Supported `LookupAttributes` keys: `EventName`, `Username`, `ResourceName`, `EventSource`, `ReadOnly`. Results sort most recent first (`eventTime` descending). Events sharing the same second keep insertion order (most recently recorded first within that second). Before scanning, `LookupEvents` waits for in-flight HTTP audit recordings to finish so the last event in a concurrent burst is visible on the first poll.

**Pagination:** `MaxResults` defaults to 50 and is capped at 50 (values outside 1-50 return `InvalidMaxResultsException`). When more events match than fit in one page, the response includes an opaque `NextToken` cursor; pass it on the next `LookupEvents` call to continue. Each stored event appears at most once across all pages for a given query. Invalid or expired tokens return `InvalidNextTokenException`.

**`eventTime`:** Indexed and delivered events use UTC with millisecond precision (`YYYY-MM-DDTHH:MM:SS.sssZ`). HTTP audit events stamp `eventTime` at request arrival (not response-filter completion). The index enforces monotonic timestamps so `ListAllMyBuckets` and later bucket-scoped calls preserve caller order in `lookup-events` even when responses complete out of order.

For buckets without active trails, use `LookupEvents` or list `AWSLogs/...` objects after logging starts.

## Configuration

```yaml
floci:
  services:
    cloudtrail:
      enabled: true
      audit-enabled: false
      exclude-internal-paths:
        - /_floci
        - /_localstack
        - /_aws
        - /health
```

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

aws cloudtrail create-trail \
  --name audit-trail \
  --s3-bucket-name my-cloudtrail-bucket \
  --is-multi-region-trail

aws cloudtrail start-logging --name audit-trail

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
  --max-results 10

aws cloudtrail get-trail-status --name audit-trail
```

## Live audit authoring

Exercises that grade investigators with **live** `aws cloudtrail lookup-events` should follow this section when provisioning trails, activity sequences, and investigator policies.

### `sourceIPAddress` for graded IP outliers

`CloudTrailEventRecorder` sets `sourceIPAddress` on HTTP audit events:

| Priority | Mechanism | When to use |
|---|---|---|
| Primary | `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` and client `X-Forwarded-For` (first hop) | Trusted reverse proxy or provision script that sets distinct forwarded IPs per principal; **same IP used for S3 access log Remote IP** |
| Alternate | `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER=true` and `X-Floci-CloudTrail-Source-Ip` per request | Single-host Docker deployments without a proxy; does not affect IAM `aws:sourceip` |
| Default | Socket peer, then `127.0.0.1` | When neither header option is enabled; S3 access logs and CloudTrail share `ClientSourceIpResolver` |

When both alternate and primary are enabled, `X-Floci-CloudTrail-Source-Ip` wins if present. Regression profile: `CloudTrailForwardedHeadersAuditProfile`.

### Instance-keyed grading (`answers.json`)

Operators should not hard-code absolute timestamps or credential IDs in static verifier docs. At **provision** time, capture instance-specific values from `lookup-events` or S3 delivery and write them to `answers.json` (or equivalent verifier input), keyed by question id. Typical fields:

| Field | Source | Example use |
|---|---|---|
| `eventTime` | `StopLogging`, SQS write, or S3 mutating event | Time-order questions |
| `accessKeyId` | `userIdentity.accessKeyId` on an `AssumedRole` session | Actor attribution |
| `VersionId` | S3 `DeleteObject` / `PutObject` response or `ListObjectVersions` | Non-current version recovery |

Other IAM-scoped exercises use the same pattern where verifiers compare participant output to provision-time snapshots, not static CSV exports.

### `CloudTrailEventStore` lifecycle and teardown

The lookup index (`CloudTrailEventStore`, file `cloudtrail-events.json` under hybrid storage) is **global per emulator region**, not per trail. `StopLogging` does not wipe prior events; `StartLogging` does not reset history. Events from one exercise instance remain visible to the next unless operators isolate state.

**Teardown guidance for multi-instance hosts:**

1. Stop the emulator or remove the `./data` volume (or delete `cloudtrail/cloudtrail-events.json`) before provisioning the next exercise instance.
2. `DeleteTrail` removes trail metadata but does not purge the event index.
3. Prefer one emulator container or fresh data directory per team when running audit exercises back-to-back on the same host.

### Operator event injection API

When `FLOCI_CTF_CLOUDTRAIL_INJECTION_ENABLED=true` and `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS=false`, operators may inject synthetic CloudTrail events during provisioning without replaying full API sequences. Supports multi-day timelines with `preserveEventTime=true`.

| Route | Auth | Description |
|---|---|---|
| `POST /_floci/cloudtrail/events` | Operator root AKID (`FLOCI_AUTH_ROOT_ACCESS_KEY_ID`) + SigV4 when `FLOCI_AUTH_VALIDATE_SIGNATURES=true` | Inject one event |
| `POST /_floci/cloudtrail/events/batch` | Same | Inject multiple events in order |

Returns **404** when injection is disabled or when `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` hides `/_floci/*`. Returns **403** for missing auth, invalid SigV4, or non-root credentials.

Request body (single):

```json
{
  "region": "us-east-1",
  "preserveEventTime": true,
  "deliverToTrails": true,
  "event": {
    "eventName": "ConsoleLogin",
    "eventSource": "signin.amazonaws.com",
    "eventTime": "2026-03-15T14:30:00.000Z",
    "sourceIPAddress": "203.0.113.50",
    "userIdentity": { "type": "IAMUser", "userName": "example-user" }
  }
}
```

Batch requests use an `events` array instead of `event`. Required event fields: `eventName`, `eventSource`, and `eventTime` when `preserveEventTime=true`. `eventID` is generated when omitted.

`preserveEventTime=true` (default) keeps operator-supplied timestamps for graded `lookup-events` and S3 day paths. `deliverToTrails=false` indexes only (no S3 flush). Regression: `CloudTrailEventInjectionIntegrationTest`.

Compose defaults keep injection **off**; enable explicitly for provisioning hosts that expose `/_floci/*` to operators.

### Data-plane audit probe (running `floci:local`)

After `StartLogging`, exercise live APIs and confirm `lookup-events` `requestParameters` before authoring graded questions:

| API | Graded field candidate |
|-----|------------------------|
| `kms:Decrypt` | `requestParameters.keyId` (from explicit `KeyId`, response `KeyId`, or Floci `kms:v2:` envelope in `CiphertextBlob`) |
| `sns:Publish` | `requestParameters.topicArn` |
| `dynamodb:PutItem` | `requestParameters.tableName` |
| S3 `GetObject` + bucket logging | Access log `REST.GET.OBJECT`; Remote IP vs CloudTrail `sourceIPAddress` when `FLOCI_AUTH_TRUST_FORWARDED_HEADERS=true` |

Maven regression (no running instance):

```bash
./mvnw test -Dtest=S3AccessLoggingIntegrationTest,S3AccessLogDeliveryIamIntegrationTest,CloudForensicsIntegrationTest,KmsDecryptScopedKeyIntegrationTest,DynamoDbGetItemQueryScopedIntegrationTest,DynamoDbPutItemScopedIntegrationTest,SnsSubscribeReceiveIamIntegrationTest,SnsPublishScopedIamIntegrationTest,CloudTrailAuditIntegrationTest,CloudTrailKmsDecryptAuditIntegrationTest,CloudTrailSnsPublishAuditIntegrationTest,CloudTrailDynamoDbPutItemAuditIntegrationTest,S3AccessLogSourceIpParityIntegrationTest,ClientSourceIpResolverTest
```

### Investigator IAM

Grant `cloudtrail:LookupEvents` on `arn:aws:cloudtrail:REGION:ACCOUNT:trail/*` unless an investigator policy narrows to one trail. Regression: `CloudTrailLookupEventsScopedIamIntegrationTest`, `CloudTrailTamperingAuditIntegrationTest`, `CloudTrailSqsAuditIntegrationTest`.

## CTF fork notes

- Trail and lookup APIs honor IAM enforcement and SigV4 when Compose hardening is on.
  - `cloudtrail:StopLogging` scopes to `arn:aws:cloudtrail:REGION:ACCOUNT:trail/NAME` from the JSON `Name` field.
  - `cloudtrail:LookupEvents` scopes to `arn:aws:cloudtrail:REGION:ACCOUNT:trail/*` when the request body has no trail name (typical investigator `lookup-events` calls). Use `trail/NAME` only when policies must deny lookup on other trails.
- Investigator policies should allow `cloudtrail:LookupEvents` on `arn:aws:cloudtrail:REGION:ACCOUNT:trail/*` unless an exercise policy narrows access to one trail.
- `StopLogging` is always audited (mutating CloudTrail API bypasses the active-trail gate). Prior events remain in the index after logging stops; `StartLogging` does not wipe history.
- See [Live audit authoring](#live-audit-authoring) for `sourceIPAddress`, `answers.json` grading, event-store teardown, injection API, and pagination detail.
- SQS audit events include `requestParameters.queueUrl` for `ReceiveMessage`, `SendMessage`, and `PurgeQueue` on Query and JSON 1.0 wire protocols (`AmazonSQS.PurgeQueue` with JSON `QueueUrl` is Management, not Data). `SendMessage` records `requestParameters.messageBody` with the actual payload. In-process SQS delivery normalizes `QueueUrl` / `MessageBody` to `queueUrl` / `messageBody`. HTTP `AssumedRole` callers include `userIdentity.sessionContext.sessionIssuer`. Regression: `CloudTrailSqsAuditIntegrationTest` (including `sqsJson10PurgeQueueRecordsQueueUrl`), `InProcessCloudTrailIntegrationTest`.
- Trail S3 delivery honors bucket policy `aws:SourceArn` and `s3:x-amz-acl` conditions for the `cloudtrail.amazonaws.com` service principal. Delivery sets `bucket-owner-full-control` on log objects.
- `GetEventSelectors` is supported; trails without explicit selectors return sensible defaults.
- Audit Compose sets `FLOCI_STORAGE_MODE=hybrid` and `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`. See [README audit profile](../../README.md#audit-and-forensics-profile) and [AGENTS.md](../../AGENTS.md#audit-services-map).
