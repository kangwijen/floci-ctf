# SNS

**Protocol:** Query (XML) and JSON 1.0 (both supported)
**Endpoint:** `POST http://localhost:4566/`

## Supported Actions

| Action | Description |
|---|---|
| `CreateTopic` | Create a topic |
| `DeleteTopic` | Delete a topic |
| `ListTopics` | List all topics |
| `GetTopicAttributes` | Get topic configuration |
| `SetTopicAttributes` | Update topic configuration |
| `Subscribe` | Subscribe an endpoint (SQS, HTTP, Lambda, email) |
| `Unsubscribe` | Remove a subscription |
| `ListSubscriptions` | List all subscriptions |
| `ListSubscriptionsByTopic` | List subscriptions for a specific topic |
| `GetSubscriptionAttributes` | Get subscription settings |
| `SetSubscriptionAttributes` | Update subscription settings |
| `ConfirmSubscription` | Confirm a pending subscription |
| `Publish` | Publish a message to a topic |
| `PublishBatch` | Publish up to 10 messages in one call |
| `TagResource` | Tag a topic |
| `UntagResource` | Remove tags from a topic |
| `ListTagsForResource` | List tags on a topic |
| `CreatePlatformApplication` | Create a mobile push platform app (iOS or Android) |
| `DeletePlatformApplication` | Delete a platform app and its endpoints |
| `GetPlatformApplicationAttributes` | Read platform app attributes |
| `SetPlatformApplicationAttributes` | Update platform app attributes (e.g. `Enabled`) |
| `ListPlatformApplications` | List platform applications in the region |
| `CreatePlatformEndpoint` | Register a device token under a platform app |
| `DeleteEndpoint` | Delete a platform endpoint |
| `GetEndpointAttributes` | Read endpoint attributes |
| `SetEndpointAttributes` | Update endpoint attributes (e.g. `Enabled=false` to simulate token expiry) |
| `ListEndpointsByPlatformApplication` | List endpoints under a platform app |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_SNS_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_STORAGE_SERVICES_SNS_MODE` | *(global default)* | Storage mode override for SNS (`memory`, `persistent`, `hybrid`, `wal`) |
| `FLOCI_STORAGE_SERVICES_SNS_FLUSH_INTERVAL_MS` | `5000` | Flush interval for `hybrid`/`wal` storage modes (milliseconds) |

## CTF fork {#ctf-fork}

When IAM enforcement is on:

### No default open topic policy

Upstream Floci attaches a permissive default topic policy when none is set. The CTF fork **omits** that policy when `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`. `GetTopicAttributes` returns no `Policy` attribute until the operator sets one. `sns:Publish` (and other data-plane actions) require an explicit identity policy **or** topic resource policy Allow.

Regression: `SnsTopicNoDefaultPolicyIntegrationTest` (`getTopicAttributesOmitsDefaultPolicy`, `publishDeniedWithoutIdentityOrResourcePolicy`).

### Account `:root` in topic resource policies

A topic policy principal `arn:aws:iam::ACCOUNT:root` does **not** authorize every IAM user in the account. Participants still need an identity policy Allow on `sns:Publish` (or another principal explicitly named in the topic policy). This matches AWS: `:root` in a resource policy is not a wildcard for all IAM users.

Regression: `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest`.

### CloudTrail audit (HTTP)

When `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true` and a trail is logging, `sns:Publish` records a **management** event (not a data event) per [AWS SNS CloudTrail](https://docs.aws.amazon.com/sns/latest/dg/sns-logging-using-cloudtrail.html):

| Field | Behavior |
|-------|----------|
| `requestParameters.topicArn` | Topic ARN from Query `TopicArn` or JSON `TopicArn` (`SNS_20100331.Publish`) |
| `resources[]` | `AWS::SNS::Topic` with topic ARN |
| `eventCategory` | `Management`; `readOnly` is `false` |
| Message body | Not recorded in `requestParameters` |

Regression: `CloudTrailSnsPublishAuditIntegrationTest`, `SnsPublishScopedIamIntegrationTest`. Cross-reference: [CloudTrail data-plane audit](./cloudtrail.md#data-plane-requestparameters-http-audit).

### SNS to SQS fan-out (closed)

**Status:** Closed on current `floci:local`. End-to-end subscribe, operator publish with explicit resource policies, and SQS delivery under IAM enforcement is covered by `SnsSubscribeReceiveIamIntegrationTest.fanOutWithExplicitTopicAndQueueResourcePolicies`.

Operator provisioning must set explicit resource policies:

1. **Topic policy** allowing operator `sns:Publish` (name the operator role or user ARN; do not rely on `:root` to grant participants publish).
2. **Queue policy** allowing `sns.amazonaws.com` to `sqs:SendMessage` with `aws:SourceArn` matching the topic ARN.
3. Participant identity policy with `sns:Subscribe` on the topic ARN and `sqs:ReceiveMessage` on the queue ARN (not `sns:Publish`).

```bash
export AWS_ENDPOINT_URL=http://localhost:4566
TOPIC_ARN=arn:aws:sns:us-east-1:000000000000:dispatch-topic
QUEUE_ARN=arn:aws:sqs:us-east-1:000000000000:dispatch-notify-queue
QUEUE_URL=http://localhost:4566/000000000000/dispatch-notify-queue

# Operator: queue policy for SNS delivery
aws sqs set-queue-attributes --queue-url "$QUEUE_URL" --attributes Policy="{\"Version\":\"2012-10-17\",\"Statement\":[{\"Effect\":\"Allow\",\"Principal\":{\"Service\":\"sns.amazonaws.com\"},\"Action\":\"sqs:SendMessage\",\"Resource\":\"$QUEUE_ARN\",\"Condition\":{\"ArnEquals\":{\"aws:SourceArn\":\"$TOPIC_ARN\"}}}]}"

# Operator: topic policy for publish
aws sns set-topic-attributes --topic-arn "$TOPIC_ARN" --attribute-name Policy --attribute-value \
  '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:root"},"Action":"sns:Publish","Resource":"'"$TOPIC_ARN"'"}]}'

# Participant: subscribe SQS endpoint, then operator publishes; participant receives without sns:Publish
aws sns subscribe --topic-arn "$TOPIC_ARN" --protocol sqs --notification-endpoint "$QUEUE_URL"
```

**Regression tests:** `SnsTopicNoDefaultPolicyIntegrationTest`, `SnsTopicRootPrincipalDoesNotAllowIamUserIntegrationTest`, `SnsSubscribeReceiveIamIntegrationTest` (including `fanOutWithExplicitTopicAndQueueResourcePolicies` for operator topic + queue policies, participant `sns:Subscribe`, publish, and queue receive).

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create a topic
TOPIC_ARN=$(aws sns create-topic --name notifications \
  --query TopicArn --output text \
  --endpoint-url $AWS_ENDPOINT_URL)

# Subscribe an SQS queue
QUEUE_ARN=$(aws sqs get-queue-attributes \
  --queue-url $AWS_ENDPOINT_URL/000000000000/orders \
  --attribute-names QueueArn \
  --query Attributes.QueueArn --output text \
  --endpoint-url $AWS_ENDPOINT_URL)

aws sns subscribe \
  --topic-arn $TOPIC_ARN \
  --protocol sqs \
  --notification-endpoint $QUEUE_ARN \
  --endpoint-url $AWS_ENDPOINT_URL

# Publish a message
aws sns publish \
  --topic-arn $TOPIC_ARN \
  --message '{"event":"user.registered"}' \
  --endpoint-url $AWS_ENDPOINT_URL

# Fan-out: publish and verify the SQS queue received the message
aws sqs receive-message \
  --queue-url $AWS_ENDPOINT_URL/000000000000/orders \
  --endpoint-url $AWS_ENDPOINT_URL
```

## SNS → SQS Fan-Out

Floci supports real SNS → SQS fan-out. When you publish to a topic, all SQS-subscribed queues receive the message immediately.

Supported subscription protocols:
- `sqs` — delivers to a Floci SQS queue
- `lambda` — invokes a Floci Lambda function
- `http` / `https` — posts to an HTTP endpoint

## Mobile push (mock)

Floci mocks SNS mobile push for iOS and Android. No real APNS or FCM connection is
made — every push is captured in memory so tests can assert what would have been sent.

**Supported platforms:** `APNS`, `APNS_SANDBOX`, `GCM`, `FCM`. Any other platform
value returns `InvalidParameter`.

### End-to-end flow

```bash
APP_ARN=$(aws sns create-platform-application \
  --name ios-app --platform APNS \
  --attributes PlatformCredential=fake-cert \
  --endpoint-url http://localhost:4566 --query PlatformApplicationArn --output text)

ENDPOINT_ARN=$(aws sns create-platform-endpoint \
  --platform-application-arn $APP_ARN \
  --token ios-device-token-abc \
  --endpoint-url http://localhost:4566 --query EndpointArn --output text)

# Plain string payload
aws sns publish --target-arn $ENDPOINT_ARN --message '{"aps":{"alert":"hi"}}' \
  --endpoint-url http://localhost:4566

# Platform-specific payloads with MessageStructure=json
aws sns publish --target-arn $ENDPOINT_ARN --message-structure json \
  --message '{"default":"fallback","APNS":"{\"aps\":{\"alert\":\"ios\"}}","GCM":"{\"notification\":{\"body\":\"android\"}}"}' \
  --endpoint-url http://localhost:4566
```

When `MessageStructure="json"`, Floci picks the key matching the endpoint's platform
(`APNS`, `APNS_SANDBOX`, `GCM`, or `FCM`), falling back to `default`. The envelope
must be a JSON object and must include `default` — otherwise `InvalidParameter`.

### Inspecting captured pushes

```bash
# All captured pushes (newest first), or filtered by endpoint
curl http://localhost:4566/_aws/sns/push-notifications
curl "http://localhost:4566/_aws/sns/push-notifications?EndpointArn=$ENDPOINT_ARN"

# Reset between tests
curl -X DELETE http://localhost:4566/_aws/sns/push-notifications
```

### Simulating expired tokens

Two ways to make `Publish` fail with `EndpointDisabledException`:

1. **Explicit** — call `SetEndpointAttributes` with `Enabled=false`. Matches the
   real AWS flow after an async APNS/FCM failure.
2. **Sentinel** — create an endpoint whose token contains `EXPIRED`
   (case-insensitive). Floci marks it `Enabled=false` on creation, so the first
   publish fails. Lets you exercise the unhappy path with a single API call.

### Error codes

| Action | Condition | Error code | HTTP |
|---|---|---|---|
| `CreatePlatformApplication` | Missing `Name` | `InvalidParameter` | 400 |
| `CreatePlatformApplication` | Unsupported `Platform` (e.g. `WNS`, `ADM`) | `InvalidParameter` | 400 |
| `CreatePlatformEndpoint` | Missing `Token` | `InvalidParameter` | 400 |
| `CreatePlatformEndpoint` | Unknown `PlatformApplicationArn` | `NotFound` | 404 |
| `CreatePlatformEndpoint` | Same `Token`, different `CustomUserData` or attrs | `InvalidParameter` | 400 |
| `CreatePlatformEndpoint` | Platform app disabled | `PlatformApplicationDisabledException` | 400 |
| `Publish` | Unknown endpoint ARN | `NotFound` | 404 |
| `Publish` | `TargetArn` is a platform application ARN | `InvalidParameter` | 400 |
| `Publish` | Endpoint `Enabled=false` | `EndpointDisabledException` | 400 |
| `Publish` | Platform application `Enabled=false` | `PlatformApplicationDisabledException` | 400 |
| `Publish` | `MessageStructure=json` missing `default` key | `InvalidParameter` | 400 |
| `Publish` | `MessageStructure=json` message is not valid JSON | `InvalidParameter` | 400 |
| `GetPlatformApplicationAttributes` | Unknown ARN | `NotFound` | 404 |
| `GetEndpointAttributes` | Unknown ARN | `NotFound` | 404 |
| `SetEndpointAttributes` | Unknown ARN | `NotFound` | 404 |

`DeletePlatformApplication` and `DeleteEndpoint` are idempotent — they succeed
silently if the resource does not exist, matching real SNS behavior.

## CTF fork {#ctf-fork}

When `FLOCI_CTF_BLOCK_PRIVATE_OUTBOUND_URLS=true` (Compose CTF default; YAML default is `false`), HTTP(S) subscription deliveries reject destinations that resolve to non-public addresses unless the hostname is on `FLOCI_CTF_OUTBOUND_URL_HOST_ALLOWLIST` or `FLOCI_CTF_OUTBOUND_ALLOW_PRIVATE_ADDRESSES=true`.