# Ports Reference

## CTF fork (this repository)

The Floci image built from [`docker/Dockerfile`](../../docker/Dockerfile) declares **no `EXPOSE`**. Host publishing belongs on the **challenge** Compose (or challenge wrapper image), not in the Floci image metadata.

The repository root [`docker-compose.yml`](../../docker-compose.yml) publishes only `4566:4566` (AWS API). Do not map Lambda Runtime API (`9200–9299`). Add `5100`, `6379–6399`, `7001–7099`, or other proxy ranges only when a challenge needs host ECR push/pull or Redis/RDS (or similar) wire access from the player host.

`docker run -P` against a rebuilt `floci:local` image publishes nothing, because the image exposes no ports. Use explicit `-p 4566:4566` or challenge Compose `ports:`.

## Port Overview

| Port / Range | Protocol | Purpose | Challenge Compose mapping when host access needed? |
|---|---|---|---|
| `4566` | HTTP | All AWS API calls (every service) | Yes (CTF default) |
| `5100–5199` | HTTP | ECR registry / auth proxy (see ECR note) | Only for host `docker push`/`pull` challenges |
| `6379–6399` | TCP | ElastiCache Redis proxy (inside Floci) | Only for host Redis wire access |
| `6500–6599` | HTTPS | EKS k3s API server — bound directly by each k3s container | **No** (Docker binds on host) |
| `7001–7099` | TCP | RDS proxy (inside Floci) | Only for host Postgres/MySQL wire access |
| `9200–9299` | HTTP | Lambda Runtime API (internal, Docker-network only) | **Never** |
| `9400–9499` | HTTP | OpenSearch data-plane — bound directly by each OpenSearch container | **No** (Docker binds on host) |

## Why some ports don't need docker-compose mapping

There are two distinct patterns Floci uses to expose container ports:

### Proxy-in-Floci (ElastiCache, RDS)

Floci runs a **TCP proxy process inside its own container**. The proxy listens on the container port and forwards traffic to the backend container.

```
host:6379  →  [challenge Compose ports mapping]  →  Floci container:6379  →  Redis container:6379
```

Because the listener is inside the Floci container, challenge Compose `ports:` is required to make that range reachable from the host. The CTF default Compose omits these ranges.

### Direct container binding (ECR without auth proxy, EKS, OpenSearch)

Floci tells the Docker daemon to start a sidecar/service container and bind its port **directly on the host**. Floci itself communicates with the container via the shared Docker network (container name + internal port). The host port is bound by Docker, not by Floci.

```
host:9400  ←──  opensearch container:9200  (Docker binds 9400 directly on the host)
                        ↑
       Floci reaches it via Docker network: floci-opensearch-{name}:9200
```

No Compose `ports:` mapping on the Floci service is needed — the port is already on the host.

## Port 4566 — AWS API

Every AWS SDK and CLI call goes to port `4566`. This includes all management-plane operations: creating queues, putting items, invoking Lambdas, etc.

```bash
aws s3 ls --endpoint-url http://localhost:4566
aws sqs list-queues --endpoint-url http://localhost:4566
aws lambda list-functions --endpoint-url http://localhost:4566
```

## Ports 6379–6399 — ElastiCache

When you create an ElastiCache replication group, Floci starts a Valkey/Redis Docker container and creates a TCP proxy on the next available port in the `6379–6399` range. The proxy runs inside the Floci container, so this range must be mapped in **challenge** Compose when players need host Redis wire access. CTF default Compose does not publish it.

Proxy ports are probed on the host before assignment. If a port in the configured range is already bound (for example by a local Redis instance), Floci skips it or falls back to an ephemeral port.

```bash
# Create a replication group
aws elasticache create-replication-group \
  --replication-group-id my-redis \
  --replication-group-description "dev cache" \
  --endpoint-url http://localhost:4566

# Connect directly on the proxied port (returned in DescribeReplicationGroups Endpoint.Port)
redis-cli -h localhost -p 6379
```

!!! note
    Configure the range with `FLOCI_SERVICES_ELASTICACHE_PROXY_BASE_PORT` and `FLOCI_SERVICES_ELASTICACHE_PROXY_MAX_PORT`.

## Ports 6500–6599 — EKS (real mode)

When you create an EKS cluster in real mode, Floci asks the Docker daemon to start a k3s container and bind its API server port (6443) to the next available host port in `6500–6599`. The port is bound directly on the host by Docker — no Floci service `ports:` mapping is needed.

The `endpoint` field returned by `DescribeCluster` points to `https://localhost:<hostPort>` when running outside a container, or `https://floci-eks-<name>:6443` when Floci is running inside Docker.

```bash
aws eks create-cluster \
  --name my-cluster \
  --role-arn arn:aws:iam::000000000000:role/eks-role \
  --resources-vpc-config subnetIds=[],securityGroupIds=[] \
  --endpoint-url http://localhost:4566

# DescribeCluster returns the API server address, e.g. https://localhost:6500
```

!!! note
    Configure the range with `FLOCI_SERVICES_EKS_API_SERVER_BASE_PORT` and `FLOCI_SERVICES_EKS_API_SERVER_MAX_PORT`.

## Ports 7001–7099 — RDS

When you create an RDS DB instance, Floci starts a PostgreSQL or MySQL Docker container and creates a TCP proxy on the next available port in the `7001–7099` range. The proxy runs inside the Floci container, so this range must be mapped in **challenge** Compose when players need host DB wire access. CTF default Compose does not publish it.

```bash
aws rds create-db-instance \
  --db-instance-identifier mydb \
  --db-instance-class db.t3.micro \
  --engine postgres \
  --master-username admin \
  --master-user-password secret \
  --endpoint-url http://localhost:4566

# Connect using the proxied port (returned in DescribeDBInstances Endpoint.Port)
psql -h localhost -p 7001 -U admin
```

!!! note
    Configure the range with `FLOCI_SERVICES_RDS_PROXY_BASE_PORT` and `FLOCI_SERVICES_RDS_PROXY_MAX_PORT`.

## Ports 9200–9299 — Lambda Runtime API (internal)

Floci binds a Runtime API port in `9200–9299` for each warm Lambda container to poll. These ports are consumed by containers on the shared Docker network only — they are never accessed from the host and must **not** be mapped in Compose or declared with `EXPOSE` on the Floci image.

The allocator probes each candidate port on the host before assignment. When the configured range is exhausted or ports are already bound (for example by a prior test run or another service), Floci falls back to an OS ephemeral port so Lambda containers can still start.

Configure the range with `FLOCI_SERVICES_LAMBDA_RUNTIME_API_BASE_PORT` and `FLOCI_SERVICES_LAMBDA_RUNTIME_API_MAX_PORT`.

## Ports 9400–9499 — OpenSearch (real mode)

When you create an OpenSearch domain in real mode, Floci asks the Docker daemon to start an `opensearchproject/opensearch` container and bind its REST port (9200) to the next available host port in `9400–9499`. The port is bound directly on the host by Docker — no Floci service `ports:` mapping is needed.

The `endpoint` field returned by `DescribeDomain` points to `http://localhost:<hostPort>` when running outside a container, or `http://floci-opensearch-<name>:9200` when Floci is running inside Docker.

```bash
aws opensearch create-domain \
  --domain-name my-search \
  --engine-version OpenSearch_2.11 \
  --endpoint-url http://localhost:4566

# DescribeDomain returns the data-plane address, e.g. http://localhost:9400
curl http://localhost:9400/_cluster/health
```

!!! note
    Configure the range with `FLOCI_SERVICES_OPENSEARCH_PROXY_BASE_PORT` and `FLOCI_SERVICES_OPENSEARCH_PROXY_MAX_PORT`.

## Ports 5100–5199 — ECR Registry

Behavior depends on whether the IAM registry auth proxy is active (`FLOCI_SERVICES_ECR_REGISTRY_AUTH_ENABLED=true` with IAM enforcement, the CTF Compose default). See [ECR](../services/ecr.md#docker-compose-port-mapping).

**Auth proxy on (CTF):** Floci listens on the public registry port (default **5100**) inside the Floci container. Challenge Compose must publish `5100:5100` when host `docker push`/`pull` is in scope. CTF default Compose does not publish it.

**Auth proxy off:** The `registry:2` sidecar binds its host port directly. Do **not** add `5100-5199` to the Floci service `ports` list (that pre-allocates ports on the Floci container and prevents the sidecar from binding).

!!! warning "Do not declare ECR ports on the Floci image"
    The CTF `docker/Dockerfile` has no `EXPOSE`. Do not add `EXPOSE 5100` (or Redis/RDS ranges) to the Floci image. Publish from challenge Compose only when needed.

## Exposing Ports in Docker Compose

### CTF default (this repository)

```yaml
services:
  floci:
    build:
      context: .
      dockerfile: docker/Dockerfile
    ports:
      - "4566:4566"   # AWS API only — challenge Compose owns publishing
```

The Floci image declares no `EXPOSE`. Challenge wrappers add further `ports:` only when the challenge needs them.

### Optional wire-access overrides (challenge-specific)

Proxy-based services (ElastiCache and RDS) need extra mappings when players must reach Redis or SQL from the host:

```yaml
services:
  floci:
    image: floci:local
    ports:
      - "4566:4566"
      - "6379-6399:6379-6399" # ElastiCache / Redis proxy (only if challenge needs it)
      - "7001-7099:7001-7099" # RDS proxy (only if challenge needs it)
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
```

EKS (`6500–6599`) and OpenSearch (`9400–9499`) ports are bound directly on the host by Docker and are accessible without a Floci service `ports:` entry. ECR with auth proxy needs `5100` on the Floci service when host registry access is required. Without the auth proxy, do not add `5100–5199` to the Floci service.

If your application runs inside the same Docker Compose network, it can reach Floci directly on container port `4566` — the host port mapping is only needed for tools running on the host (CLI, IDE plugins, etc.).
