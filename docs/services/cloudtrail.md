# CloudTrail

**Protocol:** JSON 1.1 (`X-Amz-Target: com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.*`)
**Endpoint:** `POST http://localhost:4566/`

Floci implements CloudTrail trail lifecycle, `LookupEvents`, and optional HTTP audit recording when `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`. For the canonical supported-operation count across all services, see [Services Overview](index.md). CloudTrail is not yet listed in that matrix.

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
| `LookupEvents` | Query indexed management events (time range, attributes, pagination) |

## Trail lifecycle

Typical operator flow for a forensic lab:

1. Create an S3 bucket (and optional SQS queue for near-real-time fan-out via bucket notifications).
2. Attach a bucket policy allowing `cloudtrail.amazonaws.com` to `s3:PutObject` under `AWSLogs/`.
3. `CreateTrail` with `S3BucketName`, then `PutEventSelectors`, then `StartLogging`.
4. `GetTrailStatus` reports `IsLogging=true` and a `LatestDeliveryTime` after deliveries occur.

Trails persist in Floci storage (`cloudtrail-trails.json`) using the global or per-service storage mode. With `FLOCI_STORAGE_MODE=hybrid` (Compose forensic default), trail metadata survives restarts under `./data` on the mounted volume.

## Audit recording (forensic lab)

| Variable | Default (dev YAML) | Compose forensic default | Description |
|---|---|---|---|
| `FLOCI_SERVICES_CLOUDTRAIL_ENABLED` | `true` | `true` | Enable the CloudTrail JSON API |
| `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED` | `false` | `true` | `CloudTrailAuditFilter` records signed management API calls when at least one trail is logging |
| `FLOCI_SERVICES_CLOUDTRAIL_EXCLUDE_INTERNAL_PATHS` | `/_floci,/_localstack,/_aws,/health` | same | Path prefixes skipped by the audit recorder |

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

## Event delivery and S3 layout

Delivered log objects use the AWS key layout:

```
s3://{bucket}/AWSLogs/{account-id}/CloudTrail/{region}/{yyyy}/{MM}/{dd}/{account-id}_CloudTrail_{region}_{yyyyMMddTHHmmssZ}.json.gz
```

Each object is a gzip-compressed JSON array of management events. Fields include `eventVersion`, `eventTime`, `eventSource`, `eventName`, `awsRegion`, `sourceIPAddress`, `userIdentity`, `requestParameters`, `responseElements`, and `eventID`.

`LatestDeliveryTime` on `GetTrailStatus` updates when events flush to the trail bucket (default buffer size: 10 events per trail).

## LookupEvents

`LookupEvents` searches the in-memory or persisted event index populated by the audit filter and test helpers. Supported `LookupAttributes` keys: `EventName`, `Username`, `ResourceName`, `EventSource`, `ReadOnly`. `MaxResults` is capped at 50. Results sort most recent first.

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
  --name forensic-trail \
  --s3-bucket-name my-cloudtrail-bucket \
  --is-multi-region-trail

aws cloudtrail start-logging --name forensic-trail

aws cloudtrail lookup-events \
  --lookup-attributes AttributeKey=EventName,AttributeValue=PutObject \
  --max-results 10

aws cloudtrail get-trail-status --name forensic-trail
```

## CTF fork notes

- Trail and lookup APIs honor IAM enforcement and SigV4 when Compose hardening is on. `cloudtrail:StopLogging` and related actions scope to `arn:aws:cloudtrail:REGION:ACCOUNT:trail/NAME` from the JSON `Name` field (see [IAM scoped ARNs](iam.md#scoped-resource-arns)).
- Forensic Compose sets `FLOCI_STORAGE_MODE=hybrid` and `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`. See [README forensic lab](../../README.md#forensic-lab) and [AGENTS.md](../../AGENTS.md#forensic-services-map).
