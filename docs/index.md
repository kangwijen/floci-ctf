# Floci

<p align="center">
  <img src="assets/floci.svg" alt="Floci" width="500" />
</p>

<p align="center"><em>Light, fluffy, and always free</em></p>

---

!!! warning "CTF fork (this repository)"
    This tree is **floci-ctf**, a security-hardened fork for CTF and security exercises. Compose enables IAM enforcement, strict mode, and SigV4 validation by default. Operator credentials use `FLOCI_AUTH_ROOT_*`; participants need IAM access keys and SigV4 on every call. `test`/`test` and legacy HMAC presign are not supported.

    Fork operator and agent docs: [README.md](https://github.com/kangwijen/floci-ctf/blob/main/README.md) and [AGENTS.md](https://github.com/kangwijen/floci-ctf/blob/main/AGENTS.md). IAM detail: [CTF hardening](services/iam.md#ctf-hardening).

Floci is a fast, free, and open-source local AWS service emulator built for developers who need reliable AWS services in development and CI without cost, complexity, or vendor lock-in.

## Supported Services

Floci emulates 53 AWS services. See the [Services Overview](services/index.md) for per-service operation counts, endpoints, and full protocol details.

| Service | Protocol |
|---|---|
| SSM Parameter Store | JSON 1.1 |
| SQS | Query / JSON |
| SNS | Query / JSON |
| SES | Query |
| SES v2 | REST JSON |
| S3 | REST XML |
| DynamoDB + Streams | JSON 1.1 |
| Lambda | REST JSON |
| API Gateway v1 & v2 | REST JSON |
| AppSync | REST JSON |
| Cognito | JSON 1.1 |
| KMS | JSON 1.1 |
| Kinesis | JSON 1.1 |
| Secrets Manager | JSON 1.1 |
| CloudFormation | Query |
| Step Functions | JSON 1.1 |
| IAM | Query |
| STS | Query |
| ElastiCache (Redis / Valkey) | Query + RESP proxy |
| RDS (PostgreSQL / MySQL) | Query + wire proxy |
| Neptune (graph DB / Gremlin) | Query + WebSocket proxy |
| MSK (Kafka / Redpanda) | REST JSON + Kafka |
| Athena | JSON 1.1 |
| Glue Data Catalog + Schema Registry | JSON 1.1 |
| Data Firehose | JSON 1.1 |
| ECS | JSON 1.1 |
| EC2 | EC2 Query |
| ACM | JSON 1.1 |
| ECR | JSON 1.1 + OCI Distribution |
| Resource Groups Tagging API | JSON 1.1 |
| OpenSearch | REST JSON |
| EventBridge | JSON 1.1 |
| EventBridge Pipes | REST JSON |
| EventBridge Scheduler | REST JSON |
| CloudWatch Logs & Metrics | JSON 1.1 / Query |
| AppConfig + AppConfigData | REST JSON |
| Bedrock Runtime | REST JSON |
| EKS | REST JSON |
| ELB v2 | Query |
| Auto Scaling | Query |
| CodeBuild | JSON 1.1 |
| CodeDeploy | JSON 1.1 |
| AWS Backup | REST JSON |
| CloudFront | REST XML |
| Route53 | REST XML |
| Cloud Map | JSON 1.1 |
| AWS Config | JSON 1.1 |
| Textract | JSON 1.1 |
| Transcribe | JSON 1.1 |
| Pricing | JSON 1.1 |
| Cost Explorer | JSON 1.1 |
| Cost and Usage Reports | JSON 1.1 |
| BCM Data Exports | JSON 1.1 |
| Transfer Family | JSON 1.1 |

## Why Floci?

**No account required.** No auth tokens, no sign-ups, no telemetry. Pull the image and start building.

**No feature gates.** Every feature is available to everyone — no community-edition restrictions.

**No CI restrictions.** Run in your CI pipeline with zero limitations. No credits, no quotas, no paid tiers.

**Truly open source.** MIT licensed. Fork it, extend it, embed it. No "community edition" sunset coming.

## Quick Start

=== "CTF fork (operators)"

    Build or use the hardened image from this repo. Export operator root credentials before `docker compose up`:

    ```bash
    export FLOCI_AUTH_ROOT_ACCESS_KEY_ID="AKIA..."
    export FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY="..."
    export AWS_ACCESS_KEY_ID="$FLOCI_AUTH_ROOT_ACCESS_KEY_ID"
    export AWS_SECRET_ACCESS_KEY="$FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY"
    docker compose up -d
    ```

    Provision participant IAM users with the root pair, then issue scoped policies and `CreateAccessKey`. See [CTF hardening](services/iam.md#ctf-hardening).

=== "Upstream-style (permissive)"

    ```yaml title="docker-compose.yml"
    services:
      floci:
        image: floci/floci:latest
        ports:
          - "4566:4566"
        volumes:
          - ./data:/app/data
    ```

    ```bash
    docker compose up -d
    export AWS_ENDPOINT_URL=http://localhost:4566
    export AWS_ACCESS_KEY_ID=test
    export AWS_SECRET_ACCESS_KEY=test
    aws s3 mb s3://my-bucket
    ```

All 51 AWS services are immediately available at `http://localhost:4566`.

[Get started →](getting-started/quick-start.md){ .md-button .md-button--primary }
[View services →](services/index.md){ .md-button }
