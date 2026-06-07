# Testcontainers

Floci has first-class Testcontainers modules for every major SDK language. Each module starts a real Floci container before your tests run and tears it down after — no running daemon, no shared state, no port conflicts.

!!! info "CTF fork"
    Published `FlociContainer` modules default to the upstream `floci/floci:latest` image and return `test`/`test` credentials. For **floci-ctf**, build a local image (`docker build -t floci:local .`), pass enforcement env vars via `.withEnv(...)`, and wire IAM access keys you create at test setup (or operator root credentials for provisioning). See language guides for examples.

## Available modules

| Language | Package | Version | Registry | Source |
|---|---|---|---|---|
| Java | `io.floci:testcontainers-floci` | `1.4.0` | [Maven Central](https://mvnrepository.com/artifact/io.floci/testcontainers-floci) | [GitHub](https://github.com/floci-io/testcontainers-floci) |
| Node.js | `@floci/testcontainers` | `0.1.0` | [npm](https://www.npmjs.com/package/@floci/testcontainers) | [GitHub](https://github.com/floci-io/testcontainers-floci-node) |
| Python | `testcontainers-floci` | `0.1.1` | [PyPI](https://pypi.org/project/testcontainers-floci/) | [GitHub](https://github.com/floci-io/testcontainers-floci-python) |
| Go | — | 🚧 In progress | — | [GitHub](https://github.com/floci-io/testcontainers-floci-go) |

## How it works

Every module exposes a `FlociContainer` class that wraps the official `floci/floci:latest` Docker image. When the container starts it waits for port 4566 to be ready, then exposes:

| Method | Returns |
|---|---|
| `getEndpoint()` | `http://localhost:<mapped-port>` |
| `getRegion()` | `us-east-1` (default) |
| `getAccessKey()` | `test` (upstream image only) |
| `getSecretKey()` | `test` (upstream image only) |

You pass these values directly into any AWS SDK client — no manual configuration, no environment variables. On the CTF image, create IAM users in `@BeforeAll` and use those keys instead of `getAccessKey()` / `getSecretKey()`.

## Language guides

- [Java](java.md) — JUnit 5, Spring Boot `@ServiceConnection`
- [Node.js / TypeScript](nodejs.md) — Jest, Vitest
- [Python](python.md) — pytest
- [Go](go.md) — in progress
