# Running with Docker

Floci is distributed as a Docker image. All configuration is done through environment variables — no config files or volume-mounted YAML is required.

## Quick Start

```bash
docker run --rm -p 4566:4566 floci/floci:latest
```

That's it. The default configuration works out of the box for most services: SQS, SNS, S3, DynamoDB, SSM, Lambda, API Gateway, Cognito, KMS, Kinesis, Secrets Manager, CloudFormation, Step Functions, IAM, STS, EventBridge, Scheduler, and CloudWatch.

## Docker Compose

### Minimal (stateless)

```yaml title="docker-compose.yml"
services:
  floci:
    image: floci/floci:latest
    ports:
      - "4566:4566"
    environment:
      FLOCI_HOSTNAME: floci
```

### With persistence

Add two env vars and a volume — no config file needed:

```yaml title="docker-compose.yml"
services:
  floci:
    image: floci/floci:latest
    ports:
      - "4566:4566"
    volumes:
      - floci-data:/app/data
    environment:
      FLOCI_HOSTNAME: floci
      FLOCI_STORAGE_MODE: persistent
      FLOCI_STORAGE_PERSISTENT_PATH: /app/data

volumes:
  floci-data:
```

### With ElastiCache and RDS (challenge override)

ElastiCache and RDS proxy TCP connections to real Docker containers. When a challenge needs those wire protocols from the host, publish the proxy ranges in **challenge** Compose. Root CTF Compose maps only `4566`. The Floci image declares no `EXPOSE`. The Docker socket is required for Floci to manage those containers:

```yaml title="docker-compose.yml"
services:
  floci:
    image: floci:local
    ports:
      - "4566:4566"
      - "6379-6399:6379-6399"  # challenge override: ElastiCache proxy
      - "7001-7099:7001-7099"  # challenge override: RDS proxy
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - floci-data:/app/data
    environment:
      FLOCI_HOSTNAME: floci
      FLOCI_SERVICES_DOCKER_NETWORK: myproject_default
      FLOCI_STORAGE_MODE: persistent
      FLOCI_STORAGE_PERSISTENT_PATH: /app/data

volumes:
  floci-data:
```

!!! warning "Docker socket"
    Lambda, ElastiCache, RDS, OpenSearch, and MSK require access to the Docker socket (`/var/run/docker.sock`) to spawn and manage containers. If you don't use these services, you can omit that volume. A RW socket mount still means Floci can drive the host Docker Engine. Non-operator container specs cannot request privileged mode or bind-mount the socket (`ContainerSpecHardening`). An optional socket proxy (Phase D.2) further limits Engine API surface. LAN or internet exposure of port `4566` with a RW sock remains host-root equivalent until both gates are in place.

!!! danger "Host boundary: RW socket equals host root on LAN exposure"
    Default root Compose mounts the host Docker socket read-write into the Floci container. Anyone who can reach the Floci API (or escape into that container) can drive the Docker daemon: privileged containers, host path binds, and full host takeover. Treat LAN or internet exposure of that path as **host root**. The optional socket-proxy override below reduces Docker **API surface** only. It does not replace container-spec hardening for privileged or host-path binds in create bodies.

### Optional Docker socket proxy (API allowlist)

To keep the host socket out of the Floci container and allowlist create / start / stop / inspect (plus image pull and network attach that Floci needs), stack the override file:

```bash
docker compose -f docker-compose.yml -f docker-compose.socket-proxy.yml up
```

| Piece | Behavior |
|-------|----------|
| `docker-socket-proxy` | Mounts `/var/run/docker.sock`; `CONTAINERS` + `POST` + `ALLOW_START` + `ALLOW_STOP` (+ `IMAGES` / `NETWORKS` for Floci pull/attach). No host port publish. |
| `floci` override | Sets `FLOCI_DOCKER_DOCKER_HOST=tcp://docker-socket-proxy:2375` and drops the direct sock volume. |
| Still denied by default | `BUILD`, `AUTH`, `SECRETS`, `SWARM`, `VOLUMES`, `EXEC`, `SYSTEM`, and other proxy sections left at `0`. |

Regression: `DockerSocketProxyComposeTest` (`@Tag("security-regression")`).

!!! note "ECR port"
    With CTF IAM registry auth, publish `5100` from challenge Compose when host `docker push`/`pull` is required. Without the auth proxy, the `registry:2` sidecar binds its own host port — do not add `5100-5199` to the Floci service. See [Ports Reference](./ports.md#ctf-fork-this-repository).

## Multi-container Networking

By default Floci embeds `localhost` in response URLs — for example, SQS queue URLs look like `http://localhost:4566/000000000000/my-queue`. This works when your application runs on the same machine, but breaks inside Docker Compose because other containers cannot reach `localhost` of the Floci container.

Set `FLOCI_HOSTNAME` to the Compose service name so Floci uses that name in every URL it generates:

```yaml title="docker-compose.yml"
services:
  floci:
    image: floci/floci:latest
    ports:
      - "4566:4566"
    environment:
      FLOCI_HOSTNAME: floci   # (1)

  app:
    build: .
    environment:
      AWS_ENDPOINT_URL: http://floci:4566
    depends_on:
      - floci
```

1. Must match the Compose service name so other containers can resolve it by DNS.

With this setting Floci returns URLs like `http://floci:4566/000000000000/my-queue` that other containers can reach.

Floci automatically attaches Lambda containers it spawns to the same Compose network when no explicit Docker network is configured. Setting `FLOCI_HOSTNAME` ensures those containers receive a reachable endpoint, and that response fields such as SQS `QueueUrl` use the Docker service name instead of `localhost`.

Fields affected:

- SQS — `QueueUrl`
- SNS — topic ARN callback URLs and subscription endpoints
- Any pre-signed URL or callback generated from `FLOCI_BASE_URL`

!!! tip "CI pipelines"
    In GitHub Actions or GitLab CI where both your app and Floci run as `services`, set `FLOCI_HOSTNAME` to the service name (e.g. `floci`) and point your SDK at `http://floci:4566`.

## Initialization Hooks

Mount shell scripts into hook directories to run setup or teardown logic at each lifecycle phase. No configuration variable is needed — Floci detects scripts by directory:

```yaml title="docker-compose.yml"
services:
  floci:
    image: floci/floci:latest-compat
    ports:
      - "4566:4566"
    volumes:
      - ./init/boot.d:/etc/floci/init/boot.d:ro    # before storage loads — no AWS APIs yet
      - ./init/start.d:/etc/floci/init/start.d:ro  # after HTTP server is ready
      - ./init/ready.d:/etc/floci/init/ready.d:ro  # after all start hooks complete
      - ./init/stop.d:/etc/floci/init/stop.d:ro    # during shutdown, while HTTP is still up
```

Use the `latest-compat` image when your scripts call `aws` or `boto3` — it includes the AWS CLI and boto3 pre-configured for the local endpoint, so no `--endpoint-url` flag is needed.

If you have existing LocalStack init scripts, mount them under the LocalStack-compat paths and they run unchanged:

```yaml
volumes:
  - ./localstack-init/ready.d:/etc/localstack/init/ready.d:ro
```

See [Initialization Hooks](./initialization-hooks.md) for execution order, script types, and exit-code behavior.

## CI Pipeline Example

```yaml title=".github/workflows/test.yml"
services:
  floci:
    image: floci/floci:latest
    ports:
      - "4566:4566"

steps:
  - name: Run tests
    env:
      AWS_ENDPOINT_URL: http://localhost:4566
      AWS_DEFAULT_REGION: us-east-1
      AWS_ACCESS_KEY_ID: test
      AWS_SECRET_ACCESS_KEY: test
    run: mvn test
```

## CTF security profile

The repository root `docker-compose.yml` enables Quarkus profile **`ctf`** (`application-ctf.yml`) and mirrors the same AuthPosture knobs as `FLOCI_*` env vars.

**Ports:** Challenge Compose publishes host ports. The Floci image from `docker/Dockerfile` declares **no `EXPOSE`**. Root Compose maps only `4566:4566` (AWS API). Do not map Lambda Runtime API (`9200-9299`). Add `5100`, `6379-6399`, or `7001-7099` only in challenge Compose when host ECR push/pull or Redis/RDS wire access is required. See [Ports Reference](./ports.md).

| Variable | Compose value | Purpose |
|---|---|---|
| `QUARKUS_PROFILE` | `ctf` | Load `application-ctf.yml` (IAM, strict, SigV4, federated, egress) |
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `"true"` | Enforce IAM policies on API calls (mirrors profile) |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `"true"` | Deny unregistered keys and unknown action mappings |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `"true"` | Verify SigV4 request signatures |
| `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS` | `"true"` | Federated JWT/SAML crypto required |
| `FLOCI_CTF_BLOCK_PRIVATE_OUTBOUND_URLS` | `"true"` | Reject non-public outbound HTTP destinations |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | `${FLOCI_AUTH_ROOT_ACCESS_KEY_ID}` | Operator access key ID (host passthrough) |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | `${FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY}` | Operator secret key paired with the root access key ID |
| `FLOCI_CTF_HIDE_INTERNAL_ENDPOINTS` | `"true"` | Hide unauthenticated `/_floci/*`, `/_localstack/*`, and `/_aws/*`; use `all` to hide `/health` too |
| `FLOCI_CTF_CONTAINER_CREDENTIALS_BIND_LOCALHOST` | `"true"` | Bind Lambda/CodeBuild/ECS credential servers to `127.0.0.1` only |
| `FLOCI_STORAGE_MODE` | `hybrid` | Audit profile: async flush service state to `/app/data` |
| `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED` | `"true"` | Audit profile: record HTTP and in-process API calls to active trails (SFN, EventBridge, Firehose, etc.) |

Export the root credential pair on the host before `docker compose up`. The same values are typically mirrored into `AWS_ACCESS_KEY_ID` and `AWS_SECRET_ACCESS_KEY` for operator CLI use and S3 presign signing. See [IAM CTF hardening](../services/iam.md#ctf-hardening) for the full operator workflow.

!!! warning "Unsupported for CTF: plain docker run without profile"
    `docker run` of the image without `QUARKUS_PROFILE=ctf` (and without the CTF `FLOCI_*` knobs) keeps main `application.yml` lab defaults (permissive). That path is unsupported for CTF challenges. Use Compose or pass the profile/env explicitly.

**Compat / lab escape hatch:** omit `QUARKUS_PROFILE` and leave CTF `FLOCI_*` unset (CI `compat-test` does this). Unit tests use main YAML. Do not flip main `application.yml` to enforce-all.

## Common Environment Variables

The most frequently set variables when running Floci as a Docker image:

| Variable | Default | Purpose |
|---|---|---|
| `FLOCI_HOSTNAME` | _(none)_ | Hostname embedded in response URLs. Set to the Compose service name in multi-container setups |
| `FLOCI_DEFAULT_REGION` | `us-east-1` | AWS region reported in ARNs and responses |
| `FLOCI_DEFAULT_ACCOUNT_ID` | `000000000000` | AWS account ID used in ARNs |
| `FLOCI_STORAGE_MODE` | `memory` | `memory`, `persistent`, `hybrid`, or `wal` |
| `FLOCI_STORAGE_PERSISTENT_PATH` | `./data` | Directory for persistent storage |
| `FLOCI_SERVICES_DOCKER_NETWORK` | _(none)_ | Docker network for spawned containers (Lambda, ElastiCache, RDS, OpenSearch, MSK) |
| `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED` | `false` | Enforce IAM policies (enabled in repo `docker-compose.yml`) |
| `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED` | `false` | Strict IAM enforcement; no permissive fall-through (enabled in repo `docker-compose.yml`) |
| `FLOCI_AUTH_VALIDATE_SIGNATURES` | `false` | Verify SigV4 request signatures (enabled in repo `docker-compose.yml`) |
| `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` | _(none)_ | Operator root access key ID for IAM bypass |
| `FLOCI_AUTH_ROOT_SECRET_ACCESS_KEY` | _(none)_ | Operator root secret paired with the root access key ID |
| `FLOCI_SERVICES_LAMBDA_EPHEMERAL` | `false` | Remove Lambda containers after each invocation |

For the complete list of every `FLOCI_*` variable, see [Environment Variables Reference](./environment-variables.md).

## Docker Configuration

For Docker daemon socket, private registry authentication, log rotation, and network settings see [Docker Configuration](./docker.md).
