# Amazon GuardDuty

**Protocol:** JSON 1.1 (`X-Amz-Target: GuardDuty_2017-11-28.*`)
**Endpoint:** `POST http://localhost:4566/`

GuardDuty provides detector lifecycle, sample findings, and optional CloudTrail-driven suspicious-event rules for forensic labs. For canonical service counts, see [Services Overview](index.md). GuardDuty is not yet listed in that matrix.

## Supported Actions

| Action | Description |
|---|---|
| `CreateDetector` | Create one detector per region |
| `ListDetectors` | List detector IDs |
| `GetDetector` | Describe detector status and data sources |
| `UpdateDetector` | Enable/disable or change publishing frequency |
| `ListFindings` | List finding IDs (optional criteria) |
| `GetFindings` | Return finding details |
| `ArchiveFindings` | Archive findings by ID |
| `CreateSampleFindings` | Seed representative finding types |

## CloudTrail integration

When CloudTrail audit is enabled and a detector is active, `GuardDutyCloudTrailHook` evaluates selected management events (`CreateAccessKey`, `DeleteBucket`, `ConsoleLogin`, `StopLogging`, `DeleteTrail`, and others) and may raise findings. CloudTrail tampering rules use `DefenseEvasion:CloudTrail/StopLogging` and `DefenseEvasion:CloudTrail/DeleteTrail`. Findings can forward to [Security Hub](securityhub.md) via `GuardDutyFindingSubscriber` when Security Hub is enabled in the same region.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_GUARDDUTY_ENABLED` | `true` | Enable or disable GuardDuty |

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

DETECTOR_ID=$(aws guardduty create-detector --enable \
  --query DetectorId --output text)

aws guardduty create-sample-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-types Recon:EC2/PortProbeUnprotectedPort

aws guardduty list-findings --detector-id "$DETECTOR_ID"

aws guardduty get-findings \
  --detector-id "$DETECTOR_ID" \
  --finding-ids $(aws guardduty list-findings --detector-id "$DETECTOR_ID" --query FindingIds[0] --output text)
```

## Forensic lab notes

Pair GuardDuty with [CloudTrail](cloudtrail.md) audit (`FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true`) and [Security Hub](securityhub.md) for a three-layer lab: API audit, threat findings, and centralized ASFF import.

Not modeled: multi-account invitations, malware protection, EKS runtime monitoring, or publishing destinations to S3/Firehose.
