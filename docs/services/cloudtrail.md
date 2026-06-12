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

`CloudTrailAuditFilter` skips CloudTrail API calls themselves to avoid recursion. Global services (IAM, STS, CloudFront, Route53, WAF) deliver to trails with `IncludeGlobalServiceEvents=true` even when the request region differs from the trail home region.

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

- Trail and lookup APIs honor IAM enforcement and SigV4 when Compose hardening is on.
- Forensic Compose sets `FLOCI_STORAGE_MODE=hybrid` and `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`. See [README forensic lab](../../README.md#forensic-lab) and [AGENTS.md](../../AGENTS.md#forensic-services-map).
