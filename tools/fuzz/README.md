# floci-fuzz

CTF fuzz harness for [floci-ctf](../../README.md). Lives under `tools/fuzz/` so normal CI
and `./mvnw test` stay unchanged.

## Goals

1. **Security first:** auth bypass, policy under-scope, credential escalation, sandbox escape
2. **Crash/hang second:** uncaught `Error`, OOM, watchdog timeouts
3. **Two layers:** in-repo unit fuzz + operator campaigns against live `floci:local`

## Layout

```text
tools/fuzz/
  coverage.yaml                Service matrix (protocol, unit, operator, corpora, gaps)
  src/main/java/.../oracle     Shared SecurityOracle, CrashWatchdog, FindingSerializer
  src/main/java/.../support    CorpusLoader, fixtures, request mocks
  src/main/java/.../operator   DifferentialHttpOracle helper
  unit/                        jqwik + Jazzer unit targets (default Surefire)
  operator/                    Live HTTP / TCP / delivery campaigns (-Pfuzz-operator)
  corpora/                     Seed inputs (loaded by CorpusLoader)
  findings/                    Minimized repros (gitignored except fixtures/)
  scripts/                     Windows and bash runners
```

## Prerequisites

```bash
# From repo root: install floci so fuzz can depend on it
./mvnw install -DskipTests
```

## Unit fuzz

```bash
# PowerShell
./tools/fuzz/scripts/run-unit.ps1

# Bash
./tools/fuzz/scripts/run-unit.sh

# Or directly
./mvnw -f tools/fuzz/pom.xml test
```

Coverage-guided Jazzer mutation (longer runs):

```bash
./mvnw -f tools/fuzz/pom.xml test -Pfuzz-jazzer
```

## Operator campaigns

Requires a running CTF Compose instance (`IAM` + strict + SigV4) and endpoint env:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
# Never put operator root secrets in corpora/

./tools/fuzz/scripts/run-operator.sh
# or
./mvnw -f tools/fuzz/pom.xml test -Pfuzz-operator
```

Operator tests skip cleanly when `fuzz.operator.skip=true` (default) or when
`AWS_ENDPOINT_URL` is unset.

## Not in CI

This harness is **not** wired into GitHub Actions. Run it locally or on an operator machine
with CTF Compose. Default `./mvnw test` and the CI `test` / `ctf-regression` jobs do not
execute `tools/fuzz/`. Do not commit operator root credentials into corpora or findings.

## Oracle model

Oracles live under `src/main/java/.../oracle/`.

| Priority | Component | What it catches |
|----------|-----------|-----------------|
| 1 | `SecurityOracle` | Auth bypass, unexpected Allow, credential keys in env, ARN namespace drift, policy under-scope |
| 2 | `CrashWatchdog` | Uncaught `Error`, hangs beyond per-property timeout |
| 3 | `FindingSerializer` | Persists minimized seeds to `findings/` for graduation |

Security failures call `SecurityOracle.failSecurity(...)`, which records a `Finding` and
rethrows as `AssertionError` so jqwik/JUnit mark the property failed. HTTP operator
campaigns use `DifferentialHttpOracle` to compare unsigned vs expected deny shapes on live
`:4566`.

## How corpora wire in

`CorpusLoader` reads seeds from `tools/fuzz/corpora/` (override with `-Dfuzz.corpora.dir=`).

| Method | Use |
|--------|-----|
| `lines(relativePath)` | One seed per non-empty, non-`#` line (actions, paths, scopes) |
| `filesUnder(relativeDir)` | All files in a directory (ARN JSON fixtures, policy JSON) |
| `orFallback(path, builtIn)` | Corpus line if present, else generator fallback in `FuzzBodyGenerators` |

Unit tests and operator `@Provide` methods pull corpora for jqwik shrinking. Shared buckets:

| Directory | Examples |
|-----------|----------|
| `corpora/arn/` | DynamoDB table, KMS key, SQS queue URL, Secrets path, STS assume role |
| `corpora/json11/` | DDB PartiQL, KMS decrypt, Athena start, CloudTrail stop, high-value targets |
| `corpora/query/` | IAM, STS, SQS, SNS query actions |
| `corpora/rest/paths.txt` | Lambda, APIGW, ECR `/v2/`, IoT shadow, Scheduler, Pipes, internal paths |
| `corpora/policy/` | Allow/Deny/session/resource-policy fixtures for unit policy oracles |
| `corpora/delivery/` | Service principals and target ARNs for in-process delivery matrix |
| `corpora/paths/internal.txt` | `/_floci/*`, `/_localstack/*`, `/_aws/*` classification seeds |
| `corpora/paths/internal-mutating.txt` | Reset, CloudTrail injection, `/_localstack/init` operator campaign seeds |
| `corpora/scopes/all-scopes.txt` | SigV4 credential scope list |

See `coverage.yaml` `corpora_index` for the full map.

## Staged coverage summary

Five stages group work by surface. Counts are service rows in `coverage.yaml` (70 total:
69 AWS packages under `services/` plus `floci` internal).

| Stage | Unit / operator classes | Primary surfaces |
|-------|-------------------------|------------------|
| `unit-parsers` | 31 unit classes (+ 4 Jazzer) | ResourceArnBuilder, intentional `*` scopes, thin REST, policy/SigV4/SigV4a, ECR auth, TCP tokens, open data-plane, MQTT CONNECT, extreme-value crash, ZIP/VTL |
| `unit-bypass` | 6 unit classes | Bypass paths, blank-role env, in-process IAM/SFN/delivery |
| `operator-http` | HttpDifferential, ServiceProtocol, PresignAndAnonymous, SignedDifferential, InternalEndpoint | Unsigned deny, participant SigV4 differential, internal hide |
| `operator-nonhttp` | NonHttp, ContainerCredentials | Cred ports, TCP proxies, MQTT CONNECT deny, Neptune upgrade probes, ECR `/v2` |
| `operator-delivery` | Delivery, DeliveryProvisionSmoke | EventBridge, Pipes, SNS, Lambda ESM, Scheduler, Logs, CloudTrail, Config, Firehose |

### By protocol family (summary, not per-service)

| Protocol family | Services (approx) | Unit depth | Operator depth | Notes |
|-----------------|-----------------|------------|----------------|-------|
| Query | 14 | arn-matrix + IamActionRegistry on most | HttpDifferential + ServiceProtocol + SignedDifferential | IAM/STS/SQS/SNS/EC2/RDS share query corpora |
| JSON 1.1 | 40+ | arn-matrix on scoped services + Json11Split + intentional `*` | ServiceProtocol targets from `json11/targets.txt` | `ce` / `pricing` locked to `*` |
| REST | 25+ | RestRules + ThinRest + ECR auth | ServiceProtocol + PresignAndAnonymous + InternalEndpoint | batch/mq/s3vectors must not map as `s3` |
| TCP | 5 | TcpAuthTokenFuzzTest + OpenDataPlaneSurfaceFuzzTest | NonHttp port + Redis AUTH + Neptune soft probes | DocDB uses dynamic Docker ports |
| MQTT | 1 (IoT) | MqttConnectAuthFuzzTest + arn-matrix | NonHttp CONNECT deny + hang-safe | Password/SigV4 not validated on CONNECT yet |
| In-process | 15+ delivery + SFN | InProcessAuthorizer + DeliveryMatrix + SfnSdkMatrix | Delivery + DeliveryProvisionSmoke | Blank role denies under enforcement |

**Full service matrix:** [coverage.yaml](./coverage.yaml) lists every package with `protocol`,
`unit`, `operator`, `corpora`, and `gaps`.

### Verified unit tests (31)

| Class | Stage |
|-------|-------|
| ResourceArnBuilderFuzzTest | unit-parsers |
| ResourceArnBuilderScopedFuzzTest | unit-parsers |
| ResourceArnBuilderPartiqlFuzzTest | unit-parsers |
| ResourceArnBuilderJazzerTest | unit-parsers (Jazzer) |
| IntentionalWildcardScopeFuzzTest | unit-parsers |
| CatalogOnlyScopeFuzzTest | unit-parsers |
| ThinRestServicePathFuzzTest | unit-parsers |
| IamActionRegistryFuzzTest | unit-parsers |
| IamActionRegistryJazzerTest | unit-parsers (Jazzer) |
| IamActionRegistryJson11SplitFuzzTest | unit-parsers |
| IamActionRegistryRestRulesFuzzTest | unit-parsers |
| IamPolicyAndPrincipalFuzzTest | unit-parsers |
| IamPolicyEvaluatorJazzerTest | unit-parsers (Jazzer) |
| IamSessionAndResourcePolicyFuzzTest | unit-parsers |
| SigV4RequestValidatorFuzzTest | unit-parsers |
| SigV4RequestValidatorJazzerTest | unit-parsers (Jazzer) |
| SigV4CredentialSmugglingFuzzTest | unit-parsers |
| SigV4aAndPresignPathFuzzTest | unit-parsers |
| PresignedPostConditionFuzzTest | unit-parsers |
| EcrRegistryPathFuzzTest | unit-parsers |
| EcrRegistryAuthFuzzTest | unit-parsers |
| EcrRegistrySignedDifferentialFuzzTest | unit-parsers |
| TcpAuthTokenFuzzTest | unit-parsers |
| OpenDataPlaneSurfaceFuzzTest | unit-parsers |
| MqttConnectAuthFuzzTest | unit-parsers |
| ExtremeValueCrashFuzzTest | unit-parsers |
| FederatedTokenParserFuzzTest | unit-parsers |
| ZipAndVtlFuzzTest | unit-parsers |
| AccountAndIpFuzzTest | unit-parsers |
| SecurityBypassAndEnvFuzzTest | unit-bypass |
| PathClassificationMatrixFuzzTest | unit-bypass |
| InProcessAuthorizerFuzzTest | unit-bypass |
| InProcessDeliveryMatrixFuzzTest | unit-bypass |
| InProcessSfnSdkMatrixFuzzTest | unit-bypass |
| BlankRoleOperatorEnvFuzzTest | unit-bypass |

### Verified operator campaigns (9)

| Class | Stage |
|-------|-------|
| HttpDifferentialCampaignTest | operator-http |
| ServiceProtocolCampaignTest | operator-http |
| PresignAndAnonymousCampaignTest | operator-http |
| SignedDifferentialCampaignTest | operator-http |
| InternalEndpointCampaignTest | operator-http |
| NonHttpCampaignTest | operator-nonhttp |
| ContainerCredentialsCampaignTest | operator-nonhttp |
| DeliveryCampaignTest | operator-delivery |
| DeliveryProvisionSmokeCampaignTest | operator-delivery |

## Findings workflow

1. Failing oracle writes `tools/fuzz/findings/*.txt` via `FindingSerializer`
2. Minimize the seed (jqwik replay or manual trim)
3. Copy a fixture snippet to `findings/fixtures/` if useful for docs
4. Graduate to a `src/test` `*PocTest` or `*BypassIntegrationTest`
5. Fix production code and keep the regression in the main Maven module

Finding file format:

```text
kind=SECURITY
target=ResourceArnBuilder.scoped
summary=...
seed=
<repro input>
details=
  arn=...
```

Override output dir with `-Dfuzz.findings.dir=`.

## Closed gaps (this campaign)

| Gap area | Closure |
|----------|---------|
| No arn-matrix / intentional `*` | `IntentionalWildcardScopeFuzzTest` locks `ce`/`pricing`/`api.pricing`/`ec2messages`/`cloudcontrolapi` to `*`. `CatalogOnlyScopeFuzzTest` asserts zero remaining catalog-only gaps. |
| Former catalog-only ARN arms | Production `ResourceArnBuilder` arms for `mq`, `batch`, `lightsail`, `memorydb`, `codepipeline`, `elasticbeanstalk`, `s3vectors`, `docdb` (RDS alias). REST rules for batch/mq/s3vectors. |
| Thin REST corpus | Expanded `corpora/rest/paths.txt` + `ThinRestServicePathFuzzTest` + ServiceProtocol probes. S3 Vectors paths no longer mis-map as S3. |
| TCP wire auth | `TcpAuthTokenFuzzTest` + NonHttp Redis AUTH / port soft probes |
| MQTT CONNECT | IAM enforcement on rejects blank username (`IotMqttBrokerService.allowMqttConnect`). `MqttConnectAuthFuzzTest` + NonHttp deny oracle. |
| Neptune / DocDB open TCP | Intentional transparent relays (no wire SigV4). Locked by `OpenDataPlaneSurfaceFuzzTest` + NonHttp probes. |
| Presigned POST conditions | `PresignedPostConditionFuzzTest` + PresignAndAnonymous fake-policy deny |
| Signed differential HTTP | `SignedDifferentialCampaignTest` + `FUZZ_PARTICIPANT_*` hooks |
| SFN aws-sdk task matrix | `InProcessSfnSdkMatrixFuzzTest` |
| ECR data-plane auth | `EcrRegistryAuthFuzzTest`, `EcrRegistrySignedDifferentialFuzzTest`, invalid Basic operator probe |
| Blank execution role | `BlankRoleOperatorEnvFuzzTest` mirrors launcher merge under enforcement |
| Internal operator APIs | `InternalEndpointCampaignTest` + `corpora/paths/internal-mutating.txt` |
| Extreme-value crash fuzz | `ExtremeValueGenerators` + `ExtremeValueCrashFuzzTest` + Jazzer entries for ARN/policy/SigV4/action registry |

## Open fuzz gaps

**None.** `CatalogOnlyScopeFuzzTest` fails the build if a new catalog service lands without either a `ResourceArnBuilder` arm or an intentional-wildcard listing.

Intentional non-scoped surfaces (not gaps):

| Surface | Lock |
|---------|------|
| `ce`, `pricing`, `api.pricing`, `ec2messages`, `cloudcontrolapi` | AWS-intentional `*` (AGENTS.md) |
| Neptune / DocDB TCP | Transparent relay by design |
| MQTT password / IoT policy language | Username required under IAM enforcement. Full custom authorizer not modeled |

Operator signed differential env:

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
export FUZZ_PARTICIPANT_ACCESS_KEY_ID=AKIA...
export FUZZ_PARTICIPANT_SECRET_ACCESS_KEY=...
# optional: FUZZ_PRESIGN_ACCESS_KEY_ID / FUZZ_PRESIGN_SECRET_ACCESS_KEY
./mvnw -f tools/fuzz/pom.xml test -Pfuzz-operator
```

## Roadmap phases (historical)

| Phase | Surface | Location |
|-------|---------|----------|
| 1 | Parsers (ARN, action registry, policy, SigV4, federated, ZIP/VTL) | `unit/` |
| 2 | Bypass paths, container env hardening | `unit/` |
| 3 | HTTP differential + protocol smoke | `HttpDifferentialCampaignTest`, `ServiceProtocolCampaignTest` |
| 4 | Non-HTTP / creds / Athena / MQTT | `NonHttpCampaignTest`, `ContainerCredentialsCampaignTest` |
| 5 | Delivery control-plane + provision smoke | `DeliveryCampaignTest`, `DeliveryProvisionSmokeCampaignTest`, in-process unit |
| 6 | Presign / anonymous S3 and Lambda URL | `PresignAndAnonymousCampaignTest` |
| 7 | Gap closure + extreme values + ARN arms + MQTT gate | see Closed gaps above |

Phase status and per-service detail live in [coverage.yaml](./coverage.yaml).
