# application.yml Reference

!!! note "Source builds only"
    This page is for users who build Floci from source or mount a custom `application.yml` into the container. **If you run the published Docker image, you don't need this file** — all settings are configured through `FLOCI_*` environment variables. See the [Environment Variables Reference](../environment-variables.md) for the complete list.

All settings can be provided as YAML (in `src/main/resources/application.yml` or mounted as a config file) or overridden via environment variables using the `FLOCI_` prefix with dots and dashes replaced by underscores.

## URL configuration

Floci generates absolute URLs for certain response fields (SQS queue URLs, SNS
subscription endpoints, pre-signed S3 URLs). Two settings control the hostname
embedded in those URLs:

| Setting | Env variable | Default | Description |
|---|---|---|---|
| `floci.base-url` | `FLOCI_BASE_URL` | `http://localhost:4566` | Full base URL used to build response URLs. Change the scheme, host, and port together. |
| `floci.hostname` | `FLOCI_HOSTNAME` | _(none)_ | Override only the hostname in `base-url`. Useful in Docker Compose where `localhost` is unreachable from other containers. |

When `floci.hostname` is set it replaces just the host portion of `base-url`,
leaving the scheme and port unchanged. Setting `FLOCI_HOSTNAME: floci` is
equivalent to changing `base-url` from `http://localhost:4566` to
`http://floci:4566`.

**Example — Docker Compose multi-container setup:**

```yaml
environment:
  FLOCI_HOSTNAME: floci   # matches the compose service name
```

See [Docker Compose — Multi-container networking](../docker-compose.md#multi-container-networking) for a full example.

## CTF fork settings

**floci-ctf** ships IAM enforcement, strict mode, and SigV4 off in `application.yml` for local dev; [docker-compose.yml](../../../docker-compose.yml) turns them on. See [README.md](../../../README.md) and [AGENTS.md](../../../AGENTS.md).

### `floci.ctf`

Maps to `FLOCI_CTF_*` environment variables.

| Setting | Env variable | Default | Description |
|---|---|---|---|
| `floci.ctf.hide-internal-endpoints` | `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | `true` | `false`: expose introspection routes. `true`: HTTP 404 for `/_floci/*`, `/_localstack/*`, and `/_aws/*`. `all`: also hide `/health` |
| `floci.ctf.container-credentials-bind-localhost` | `FLOCI_CTF_CONTAINER_CREDENTIALS_BIND_LOCALHOST` | `true` | Bind credential servers to `127.0.0.1` when link-local URI mode is off |
| `floci.ctf.container-credentials-use-link-local-uri` | `FLOCI_CTF_CONTAINER_CREDENTIALS_USE_LINK_LOCAL_URI` | `true` | AWS link-local credential URIs; servers bind `0.0.0.0` |
| `floci.ctf.container-credentials-link-local-host` | `FLOCI_CTF_CONTAINER_CREDENTIALS_LINK_LOCAL_HOST` | `169.254.170.2` | Host in link-local credential URIs |
| `floci.ctf.validate-federated-tokens` | `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS` | `false` | Structural JWT/SAML checks, JWT `exp`, reject `alg=none`, SAML Signature required with claims bound to the verified Assertion; crypto when keys configured. Compose sets `true`. Strict mode also requires federated crypto via `AuthPosture` without flipping this YAML default (B.4 owns CTF profile flip) |
| `floci.ctf.federated-jwt-hmac-secret` | `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRET` | _(none)_ | Shared HS256 HMAC secret for web identity JWT verification |
| `floci.ctf.federated-jwt-hmac-secrets` | `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRETS__*` | _(none)_ | Per OIDC provider host HS256 secrets |
| `floci.ctf.federated-jwt-rs256-public-key-pem` | `FLOCI_CTF_FEDERATED_JWT_RS256_PUBLIC_KEY_PEM` | _(none)_ | PEM RSA public key for RS256 web identity JWT verification |
| `floci.ctf.ecs-allow-host-volumes` | `FLOCI_CTF_ECS_ALLOW_HOST_VOLUMES` | `false` | Permit ECS host source paths only with an allowlist |
| `floci.ctf.ecs-allowed-host-source-paths` | `FLOCI_CTF_ECS_ALLOWED_HOST_SOURCE_PATHS` | _(none)_ | Allowed host-path roots for ECS volumes |
| `floci.ctf.block-private-outbound-urls` | `FLOCI_CTF_BLOCK_PRIVATE_OUTBOUND_URLS` | `false` | `AuthPosture.egressBlock`. Reject non-public outbound HTTP destinations and enable pin-connect egress (Compose sets `true`). Main YAML stays permissive until B.4 CTF profile |
| `floci.ctf.outbound-url-host-allowlist` | `FLOCI_CTF_OUTBOUND_URL_HOST_ALLOWLIST` | _(none)_ | Optional outbound hostname allowlist |
| `floci.ctf.outbound-allow-private-addresses` | `FLOCI_CTF_OUTBOUND_ALLOW_PRIVATE_ADDRESSES` | `false` | Operator override for private outbound addresses |
| `floci.ctf.require-jwt-signature-verification` | `FLOCI_CTF_REQUIRE_JWT_SIGNATURE_VERIFICATION` | `true` | Require HTTP API JWT authorizer signature verification |
| `floci.ctf.api-gateway-jwt-hmac-secret` | `FLOCI_CTF_API_GATEWAY_JWT_HMAC_SECRET` | _(none)_ | HS256 secret for HTTP API JWT authorizers |
| `floci.ctf.require-eks-token-sigv4` | `FLOCI_CTF_REQUIRE_EKS_TOKEN_SIGV4` | `true` | Require SigV4 or SigV4a on EKS bearer tokens |
| `floci.ctf.cloud-trail-allow-source-ip-header` | `FLOCI_CTF_CLOUDTRAIL_ALLOW_SOURCE_IP_HEADER` | `false` | Operator-only: stamp `sourceIPAddress` on audit events |
| `floci.ctf.cloud-trail-injection-enabled` | `FLOCI_CTF_CLOUDTRAIL_INJECTION_ENABLED` | `false` | Operator-only `POST /_floci/cloudtrail/events*` (root AKID + SigV4 when validate-signatures is on) |

```yaml
floci:
  ctf:
    hide-internal-endpoints: true
    container-credentials-bind-localhost: true
    container-credentials-use-link-local-uri: true
    container-credentials-link-local-host: 169.254.170.2
    validate-federated-tokens: false
    ecs-allow-host-volumes: false
    block-private-outbound-urls: false
    require-jwt-signature-verification: true
    require-eks-token-sigv4: true
    # federated-jwt-hmac-secret: lab-secret
    # api-gateway-jwt-hmac-secret: lab-jwt-secret
    # federated-jwt-hmac-secrets:
    #   accounts.google.com: provider-secret
    # federated-jwt-rs256-public-key-pem: |
    #   -----BEGIN PUBLIC KEY-----
    #   ...
    #   -----END PUBLIC KEY-----
```

| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | `/health` | `/_floci/*`, `/_localstack/*`, `/_aws/*` |
|---|---|---|
| `false` | 200 | reachable |
| `true` (default) | 200 | 404 |
| `all` | 404 | 404 |

### `floci.auth.trust-forwarded-headers`

| Setting | Env variable | Default | Description |
|---|---|---|---|
| `floci.auth.trust-forwarded-headers` | `FLOCI_AUTH_TRUST_FORWARDED_HEADERS` | `false` | When `true`, `X-Forwarded-For` may set `aws:sourceip` in IAM conditions. Default ignores forwarded headers (CTF-safe) |

### IAM enforcement (Compose profile)

| Setting | Env variable | Default in repo Compose |
|---|---|---|
| `floci.services.iam.enforcement-enabled` | `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `true` |
| `floci.services.iam.strict-enforcement-enabled` | `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `true` |
| `floci.auth.validate-signatures` | `FLOCI_AUTH_VALIDATE_SIGNATURES` | `true` |

## Full Reference

The block below mirrors `src/main/resources/application.yml`, it's the effective set of keys Floci ships with. Some supported keys are omitted here (for example `floci.init-hooks.*`) but can still be provided via YAML or environment variables.

```yaml
floci:
  max-request-size: 2048             # Max HTTP request body size in MB
  base-url: "http://localhost:4566"  # Used to build response URLs (SQS QueueUrl, SNS endpoints, etc.)
  # hostname: ""                     # When set, overrides the host in base-url for multi-container Docker
  default-region: us-east-1
  default-account-id: "000000000000"

  storage:
    mode: memory                      # memory | persistent | hybrid | wal
    persistent-path: ./data
    # EFS access-point emulation for the shared local Docker volumes that back ECS
    # efsVolumeConfiguration mounts. All opt-in; with no overrides a shared volume is a plain
    # named volume (root:root 0755), so existing behaviour is unchanged. See docs/services/ecs.md.
    efs:
      # owner-uid: 1001            # CreationInfo.OwnerUid (set together with owner-gid)
      # owner-gid: 1001            # CreationInfo.OwnerGid (set together with owner-uid)
      # root-permissions: "2775"   # CreationInfo.Permissions; 3-4 octal digits (4-digit carries setgid/sticky)
      init-image: busybox:stable   # image for the one-off chown/chmod of the volume root
      # mount-user: "1001:1001"    # PosixUser: run mounting containers as uid[:gid]
      # mount-group-add: 2000      # supplementary gid added to mounting containers
    wal:
      compaction-interval-ms: 30000
    services:
      ssm:
        flush-interval-ms: 5000
      dynamodb:
        flush-interval-ms: 5000
      sns:
        flush-interval-ms: 5000
      lambda:
        flush-interval-ms: 5000
      cloudwatchlogs:
        flush-interval-ms: 5000
      cloudwatchmetrics:
        flush-interval-ms: 5000
      secretsmanager:
        flush-interval-ms: 5000
      acm:
        flush-interval-ms: 5000
      opensearch:
        flush-interval-ms: 5000

  dns:
    # Extra hostname suffixes resolved to Floci's container IP by the embedded DNS server.
    # The primary suffix (floci.hostname or derived from base-url) is always included.
    # Useful when migrating from LocalStack — Lambda functions that hardcode
    # localhost.localstack.cloud as their endpoint work without code changes.
    # Via env var (comma-separated): FLOCI_DNS_EXTRA_SUFFIXES=localhost.localstack.cloud,other.internal
    # extra-suffixes:
    #   - localhost.localstack.cloud
    container-fallback-enabled: true         # FLOCI_DNS_CONTAINER_FALLBACK_ENABLED
    container-fallback-servers:            # FLOCI_DNS_CONTAINER_FALLBACK_SERVERS=1.1.1.1,1.0.0.1
      - 8.8.8.8
      - 8.8.4.4

  ctf:
    hide-internal-endpoints: true          # FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS — false | true | all

  # Audit profile (see docker-compose.yml)
  # services:
  #   cloudtrail:
  #     audit-enabled: true                # FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED
  #     exclude-internal-paths:            # FLOCI_SERVICES_CLOUDTRAIL_EXCLUDE_INTERNAL_PATHS
  #       - /_floci
  #       - /_localstack
  #       - /_aws
  #       - /health
    container-credentials-bind-localhost: true   # FLOCI_CTF_CONTAINER_CREDENTIALS_BIND_LOCALHOST
    container-credentials-use-link-local-uri: true   # FLOCI_CTF_CONTAINER_CREDENTIALS_USE_LINK_LOCAL_URI
    container-credentials-link-local-host: 169.254.170.2   # FLOCI_CTF_CONTAINER_CREDENTIALS_LINK_LOCAL_HOST
    validate-federated-tokens: false       # FLOCI_CTF_VALIDATE_FEDERATED_TOKENS
    # federated-jwt-hmac-secret:           # FLOCI_CTF_FEDERATED_JWT_HMAC_SECRET
    # federated-jwt-hmac-secrets:          # FLOCI_CTF_FEDERATED_JWT_HMAC_SECRETS__<provider_host>
    # federated-jwt-rs256-public-key-pem:  # FLOCI_CTF_FEDERATED_JWT_RS256_PUBLIC_KEY_PEM

  auth:
    validate-signatures: false               # FLOCI_AUTH_VALIDATE_SIGNATURES
    # trust-forwarded-headers: false       # FLOCI_AUTH_TRUST_FORWARDED_HEADERS
    # root-access-key-id / root-secret-access-key — operator bypass and built-in S3 presign signing

  tls:
    enabled: false                           # FLOCI_TLS_ENABLED — enable HTTPS on all endpoints
    # cert-path: ""                          # FLOCI_TLS_CERT_PATH — PEM certificate file path
    # key-path: ""                           # FLOCI_TLS_KEY_PATH — PEM private key file path
    self-signed: true                        # FLOCI_TLS_SELF_SIGNED — auto-generate cert when no paths provided

  docker:
    log-max-size: "10m"                      # Max size per container log file before rotation
    log-max-file: "3"                        # Number of rotated log files to retain
    docker-host: unix:///var/run/docker.sock # Docker daemon socket (shared by Lambda, RDS, ElastiCache)
    docker-config-path: ""                   # Path to dir containing Docker's config.json (e.g. /root/.docker)
    registry-credentials: []                 # Per-registry explicit credentials for private registries

  services:
    ssm:
      enabled: true
      max-parameter-history: 5               # Max versions kept per parameter

    sqs:
      enabled: true
      default-visibility-timeout: 30         # Seconds
      max-message-size: 1048576              # Bytes (1 MB)
      clear-fifo-deduplication-cache-on-purge: false  # When true, PurgeQueue clears SQS FIFO dedup and SNS FIFO topic dedup for topics subscribed to that queue

    s3:
      enabled: true
      default-presign-expiry-seconds: 3600

    dynamodb:
      enabled: true

    sns:
      enabled: true

    lambda:
      enabled: true
      ephemeral: false                        # true = remove container after each invocation
      default-memory-mb: 128
      default-timeout-seconds: 3
      runtime-api-base-port: 9200             # Port range for Lambda Runtime API
      runtime-api-max-port: 9299
      code-path: ./data/lambda-code           # Where ZIP archives are stored
      poll-interval-ms: 1000
      container-idle-timeout-seconds: 300     # Remove idle containers after this
      region-concurrency-limit: 1000          # Concurrent executions ceiling per region
      unreserved-concurrency-min: 100         # Minimum unreserved capacity PutFunctionConcurrency must leave
      hot-reload:
        enabled: false                        # true = enable bind-mount hot-reload via S3Bucket=hot-reload
        # allowed-paths:                      # Optional allowlist of host paths that may be bind-mounted
        #   - /home/user/projects
        #   - /tmp

    apigateway:
      enabled: true

    apigatewayv2:
      enabled: true

    iam:
      enabled: true
      enforcement-enabled: false        # FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED
      # strict-enforcement-enabled: false  # FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED
      seed-deployer-principal: false    # FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL

    elasticache:
      enabled: true
      proxy-base-port: 6379
      proxy-max-port: 6399
      default-image: "valkey/valkey:8"

    rds:
      enabled: true
      mock: false                             # true = clusters/instances created without Docker (useful for CI)
      proxy-base-port: 7001
      proxy-max-port: 7099
      default-postgres-image: "postgres:16-alpine"
      default-mysql-image: "mysql:8.0"
      default-mariadb-image: "mariadb:11"

    rds-data:
      enabled: true
      transaction-ttl-seconds: 180

    eventbridge:
      enabled: true

    scheduler:
      enabled: true

    cloudwatchlogs:
      enabled: true
      max-events-per-query: 10000

    cloudwatchmetrics:
      enabled: true

    secretsmanager:
      enabled: true
      default-recovery-window-days: 30

    kinesis:
      enabled: true

    kms:
      enabled: true

    cognito:
      enabled: true

    stepfunctions:
      enabled: true

    cloudformation:
      enabled: true
      # deleted-stack-retention-seconds: 30   # How long DescribeStacks-by-ARN can still see DELETE_COMPLETE

    acm:
      enabled: true
      validation-wait-seconds: 0              # Seconds before transitioning PENDING_VALIDATION → ISSUED

    ses:
      enabled: true
      # smtp-host: mailpit                       # SMTP server for email relay (empty = store only)
      # smtp-port: 1025
      # smtp-user: ""
      # smtp-pass: ""
      # smtp-starttls: DISABLED                  # DISABLED, OPTIONAL, or REQUIRED

    opensearch:
      enabled: true
      mock: false                             # true = metadata only, no Docker (useful for CI)
      default-image: "opensearchproject/opensearch:2"
      proxy-base-port: 9400
      proxy-max-port: 9499
      keep-running-on-shutdown: false         # leave containers running after Floci stops
      # docker network is inherited from floci.services.docker-network

    ec2:
      enabled: true

    ecs:
      enabled: true
      mock: false                             # true = tasks go to RUNNING without Docker (useful for CI)

    appsync:
      enabled: true

    appconfig:
      enabled: true

    appconfigdata:
      enabled: true

    ecr:
      enabled: true
      registry-image: "registry:2"
      registry-container-name: floci-ecr-registry
      registry-base-port: 5100
      registry-max-port: 5199
      data-path: ./data/ecr
      tls-enabled: false
      keep-running-on-shutdown: true
      uri-style: hostname                     # hostname | path
```

### Initialization hooks

`floci.init-hooks.*` is accepted as an override but is not declared in the shipped `application.yml`. See [Initialization Hooks](../initialization-hooks.md) for the full list of keys (`shell-executable`, `timeout-seconds`, `shutdown-grace-period-seconds`) and their defaults.

## Service Limits

All keys in this table are declared on `EmulatorConfig` and accept environment variable overrides via the `FLOCI_` prefix.

| Variable                                           | Default          | Description                                                   |
|----------------------------------------------------|------------------|---------------------------------------------------------------|
| `FLOCI_MAX_REQUEST_SIZE`                           | `512`            | Max HTTP request body size in MB                              |
| `FLOCI_DEFAULT_REGION`                             | `us-east-1`      | Default AWS region used in ARNs and response URLs             |
| `FLOCI_DEFAULT_AVAILABILITY_ZONE`                  | `us-east-1a`     | Default AZ reported by EC2, RDS, and other AZ-aware services  |
| `FLOCI_DEFAULT_ACCOUNT_ID`                         | `000000000000`   | Default AWS account ID used in ARNs                           |
| `FLOCI_ECR_BASE_URI`                               | `public.ecr.aws` | Base URI used when pulling container images (e.g. Lambda)     |
| `FLOCI_DNS_EXTRA_SUFFIXES`                         | *(unset)*        | Comma-separated extra hostname suffixes the embedded DNS server resolves to Floci's container IP. E.g. `localhost.localstack.cloud,localhost.example.internal` |
| `FLOCI_DNS_CONTAINER_FALLBACK_ENABLED`             | `true`           | Append public resolvers to spawned container DNS; upstream fallback for embedded forwarder |
| `FLOCI_DNS_CONTAINER_FALLBACK_SERVERS`             | `8.8.8.8,8.8.4.4` | Comma-separated fallback DNS servers when container fallback is enabled |
| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS`                | `true`           | `false` / `true` / `all` — hide `/_floci/*`, `/_localstack/*`, `/_aws/*`; `all` also hides `/health` |
| `FLOCI_CTF_CONTAINER_CREDENTIALS_BIND_LOCALHOST`   | `true`           | Bind container credential HTTP servers to loopback only |
| `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS`              | `false`          | Structural federated token checks; crypto when HMAC/RS256 keys configured |
| `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRET`               | _(none)_         | Shared HS256 secret for web identity JWT verification |
| `FLOCI_CTF_FEDERATED_JWT_HMAC_SECRETS__*`           | _(none)_         | Per-provider HS256 secrets |
| `FLOCI_CTF_FEDERATED_JWT_RS256_PUBLIC_KEY_PEM`      | _(none)_         | PEM RSA public key for RS256 web identity JWT verification |
| `FLOCI_AUTH_TRUST_FORWARDED_HEADERS`               | `false`          | Trust `X-Forwarded-For` for `aws:sourceip` in IAM conditions |
| `FLOCI_AUTH_VALIDATE_SIGNATURES`                   | `false`          | Enforce SigV4 on inbound API requests and S3 presigned query URLs |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID`                    | *(unset)*        | Operator access key; bypasses IAM enforcement when paired with root secret |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY`                | *(unset)*        | Operator secret for SigV4 validation |
| `FLOCI_SERVICES_SSM_MAX_PARAMETER_HISTORY`         | `5`              | Max parameter versions kept                                   |
| `FLOCI_SERVICES_SQS_DEFAULT_VISIBILITY_TIMEOUT`    | `30`             | Default visibility timeout (seconds)                          |
| `FLOCI_SERVICES_SQS_MAX_MESSAGE_SIZE`              | `1048576`        | Max message size (bytes)                                      |
| `FLOCI_SERVICES_SQS_CLEAR_FIFO_DEDUPLICATION_CACHE_ON_PURGE` | `false` | When `true`, `PurgeQueue` clears the FIFO 5-minute deduplication cache for the target queue and matching SNS FIFO topic dedup entries |
| `FLOCI_SERVICES_S3_DEFAULT_PRESIGN_EXPIRY_SECONDS` | `3600`           | Pre-signed URL expiry                                         |
| `FLOCI_SERVICES_DOCKER_NETWORK`                    | *(unset)*        | Shared Docker network for Lambda, RDS, ElastiCache containers |
| `FLOCI_SERVICES_RDS_DATA_ENABLED`                  | `true`           | Enable the RDS Data API service                               |
| `FLOCI_SERVICES_RDS_DATA_TRANSACTION_TTL_SECONDS`  | `180`            | Idle timeout, in seconds, before leaked RDS Data API transactions expire |
| `FLOCI_SERVICES_ECS_MOCK`                          | `false`          | Skip Docker; tasks go straight to RUNNING (useful for CI)     |
| `FLOCI_SERVICES_ECS_DOCKER_NETWORK`                | *(unset)*        | Docker network for ECS task containers                        |
| `FLOCI_SERVICES_ECS_DEFAULT_MEMORY_MB`             | `512`            | Default memory (MB) when task definition omits it             |
| `FLOCI_SERVICES_ECS_DEFAULT_CPU_UNITS`             | `256`            | Default CPU units when task definition omits it               |
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED`           | `false`          | Enforce IAM identity-based policies on every request when `true` |
| `FLOCI_SERVICES_OPENSEARCH_MOCK`                   | `false`          | Skip Docker; domains appear active immediately (useful for CI)   |
| `FLOCI_SERVICES_OPENSEARCH_KEEP_RUNNING_ON_SHUTDOWN` | `false`        | Leave OpenSearch containers running after Floci stops            |
| `FLOCI_SERVICES_SES_SMTP_HOST`                     | *(unset)*        | SMTP server host for SES email relay (empty = store only)     |
| `FLOCI_SERVICES_SES_SMTP_PORT`                     | `25`             | SMTP server port                                              |
| `FLOCI_SERVICES_SES_SMTP_USER`                     | *(unset)*        | SMTP authentication username                                  |
| `FLOCI_SERVICES_SES_SMTP_PASS`                     | *(unset)*        | SMTP authentication password                                  |
| `FLOCI_SERVICES_SES_SMTP_STARTTLS`                 | `DISABLED`       | STARTTLS mode: `DISABLED`, `OPTIONAL`, or `REQUIRED`          |
| `FLOCI_SERVICES_LAMBDA_HOT_RELOAD_ENABLED`         | `false`          | Enable bind-mount hot-reload mode (`S3Bucket=hot-reload`)     |
| `FLOCI_SERVICES_LAMBDA_HOT_RELOAD_ALLOWED_PATHS`   | *(unset)*        | Comma-separated list of host paths allowed as bind-mount roots; unset = any absolute path |

Per-queue SQS redrive policy (`maxReceiveCount`) is configured at queue creation time via `SetQueueAttributes` / `CreateQueue`, not as a global default.

`FLOCI_DEFAULT_AVAILABILITY_ZONE` and `FLOCI_ECR_BASE_URI` are declared in `EmulatorConfig` but not in the shipped `application.yml`, so they fall through to the `@WithDefault` values above when unset.

## Disabling Services

Set `enabled: false` for any service you don't need. Disabled services return a `ServiceUnavailableException` rather than silently ignoring calls.

```yaml
floci:
  services:
    cloudformation:
      enabled: false
    stepfunctions:
      enabled: false
```

Via environment variable — set to `false` for any `FLOCI_SERVICES_<SERVICE>_ENABLED` key. See [Environment Variables Reference](../environment-variables.md#services-core) for the full list.

## Logging

Floci uses standard [Quarkus logging](https://quarkus.io/guides/logging). The default effective level is `INFO`. Each service logs operation-level events at `DEBUG` (IDs and target resources) and full request/response payloads at `TRACE` — useful when diagnosing TestContainers-based test failures.

Floci ships with `quarkus.log.min-level: TRACE`, so raising a single category to `TRACE` is enough; you don't need to change the min-level yourself.

**Enable TRACE for a service via environment variables:**

```bash
# SQS: log SendMessage/ReceiveMessage/DeleteMessage bodies and attributes
QUARKUS_LOG_CATEGORY__IO_GITHUB_HECTORVENT_FLOCI_SERVICES_SQS__LEVEL=TRACE

# DynamoDB: log PutItem/GetItem/UpdateItem/DeleteItem items, Query/Scan counts
QUARKUS_LOG_CATEGORY__IO_GITHUB_HECTORVENT_FLOCI_SERVICES_DYNAMODB__LEVEL=TRACE
```

**Or in `application.yml`:**

```yaml
quarkus:
  log:
    category:
      "io.github.hectorvent.floci.services.sqs":
        level: TRACE
      "io.github.hectorvent.floci.services.dynamodb":
        level: TRACE
```

**TestContainers example:**

```java
new GenericContainer<>("floci/floci:latest")
    .withExposedPorts(4566)
    .withEnv("QUARKUS_LOG_CATEGORY__IO_GITHUB_HECTORVENT_FLOCI_SERVICES_SQS__LEVEL", "TRACE");
```

TRACE output includes the payload alongside the existing DEBUG line:

```
DEBUG [SqsService] Sent message aa7b93e7-... to queue .../events
TRACE [SqsService] Sent message aa7b93e7-... to queue .../events body={"eventType":"..."} attributes={source=okta}
```
