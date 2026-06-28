# AWS Security Hub

**Protocol:** JSON 1.1 (`X-Amz-Target: AWSSecurityHub.*`)
**Endpoint:** `POST http://localhost:4566/`

Security Hub supports hub enablement, ASFF finding import, lookup, and batch updates for forensic aggregation labs. For canonical service counts, see [Services Overview](index.md). Security Hub is not yet listed in that matrix.

## Supported Actions

| Action | Description |
|---|---|
| `EnableSecurityHub` | Enable the hub for the region |
| `DescribeHub` | Return hub ARN and subscription metadata |
| `BatchImportFindings` | Import AWS Security Finding Format (ASFF) records |
| `GetFindings` | List stored findings (optional filters) |
| `BatchUpdateFindings` | Update severity or workflow on imported findings |
| `ListEnabledProductsForImport` | Return stub product subscription ARNs |

## GuardDuty integration

When both services are enabled, `GuardDutyFindingSubscriber` can import GuardDuty-generated findings into Security Hub as ASFF records after detector rules fire.

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_SECURITYHUB_ENABLED` | `true` | Enable or disable Security Hub |

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

aws securityhub enable-security-hub

aws securityhub batch-import-findings --findings '[
  {
    "SchemaVersion": "2018-10-08",
    "Id": "forensic/sample/1",
    "ProductArn": "arn:aws:securityhub:us-east-1:000000000000:product/000000000000/default",
    "GeneratorId": "audit-exercise",
    "AwsAccountId": "000000000000",
    "Types": ["Software and Configuration Checks"],
    "CreatedAt": "2024-06-01T12:00:00Z",
    "UpdatedAt": "2024-06-01T12:00:00Z",
    "Severity": {"Label": "HIGH", "Normalized": 70},
    "Title": "Sample forensic finding",
    "Description": "Imported for lab analysis",
    "Resources": [{"Type": "AwsS3Bucket", "Id": "arn:aws:s3:::workload"}]
  }
]'

aws securityhub get-findings --filters '{"ProductArn":[{"Value":"arn:aws:securityhub:us-east-1:000000000000:product/000000000000/default","Comparison":"EQUALS"}]}'
```

## Audit exercise notes

Use Security Hub as the aggregation point for custom ASFF JSON, [GuardDuty](guardduty.md) findings, and participant-submitted imports. Compliance standards and security control automation are not evaluated; stored findings round-trip through import and get APIs only.
