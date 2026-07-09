# Secrets Manager

**Protocol:** JSON 1.1 (`X-Amz-Target: secretsmanager.*`)
**Endpoint:** `POST http://localhost:4566/`

## Supported Actions

<!-- floci:actions:start -->
| Action | Description |
| --- | --- |
| `CreateSecret` | Create a new secret |
| `GetSecretValue` | Retrieve the current secret value |
| `PutSecretValue` | Update the secret value (new version) |
| `UpdateSecret` | Update secret metadata or value |
| `DescribeSecret` | Get secret metadata and version info |
| `ListSecrets` | List all secrets |
| `DeleteSecret` | Delete a secret (with recovery window) |
| `RestoreSecret` | - |
| `RotateSecret` | Trigger secret rotation via a Lambda |
| `TagResource` | Tag a secret |
| `UntagResource` | Remove tags |
| `ListSecretVersionIds` | List all versions of a secret |
| `GetResourcePolicy` | Get the resource policy |
| `GetRandomPassword` | Generate a random password |
| `BatchGetSecretValue` | Retrieve multiple secret values in one call |
| `DeleteResourcePolicy` | Remove the resource policy |
| `PutResourcePolicy` | Attach a resource policy |
| `UpdateSecretVersionStage` | Move a staging label between versions |
<!-- floci:actions:end -->

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_SECRETSMANAGER_ENABLED` | `true` | Enable or disable the service |
| `FLOCI_SERVICES_SECRETSMANAGER_DEFAULT_RECOVERY_WINDOW_DAYS` | `30` | Days before a deleted secret is permanently purged |

## CTF fork {#ctf-fork}

When IAM enforcement is enabled:

- Data-plane calls require SigV4 from a registered IAM user or assumed role with `secretsmanager:*` (or scoped actions) on the secret ARN.
- Resource policies merge with identity policies via `ResourcePolicyResolver` (same pattern as S3 bucket policies).
- IAM evaluation uses the **stored secret ARN** including AWS six-character suffix when the secret exists.

### IAM resource patterns (AWS)

Secrets Manager appends six random characters to every secret name in its ARN (`secret:name-AbCdEf`). See [AWS identity-based policy examples](https://docs.aws.amazon.com/secretsmanager/latest/userguide/auth-and-access_examples.html).

| Example policy pattern | Matches secret `env/prod/service-a` | AWS guidance |
|---|---|---|
| `arn:...:secret:env/prod/*` | Yes | Use for path-style prefixes (`TestEnv/*` in AWS docs) |
| `arn:...:secret:env/prod/service-a-*` | Yes | Suffix wildcard after full secret name |
| `arn:...:secret:env/prod/service-a-??????` | Yes | Recommended for one specific secret name |
| `arn:...:secret:env/prod-*` | **No** | Hyphen suffix matches `env/prod-foo`, not `env/prod/foo` |

Regression: `SecretsManagerGetSecretValueScopedArnIntegrationTest`, `SecretsManagerKmsEnvelopeIntegrationTest`, `SecretsManagerKmsSupportTest`, `SecretsManagerRotationKmsIntegrationTest`, `ResourceArnBuilderTest`.

### KMS-wrapped `SecretBinary`

**Status:** Closed on current `floci:local`. When a secret uses a customer-managed KMS key, `GetSecretValue` returns `SecretBinary` (base64) instead of `SecretString`. The value is a Floci KMS `CiphertextBlob` (`kms:v2:` wire format after base64 decode). One `kms:Decrypt` on that blob yields the application plaintext; there is no nested envelope to unwrap.

**Storage rules (CTF fork):**

- Plaintext supplied via `SecretString` or `SecretBinary` on create/update is encrypted once with the secret CMK and stored as base64 `SecretBinary`.
- Values that are already KMS `CiphertextBlob` data (raw `kms:v2:` UTF-8 or a single base64 layer from `kms:Encrypt`) are stored without re-wrapping.
- Pass **raw bytes** to SDK `SecretBinary` parameters; do not pre-base64-encode before boto3 (AWS encodes once on the wire). Floci normalizes accidental double-base64 provisioning input to a single layer on store.

Players need `secretsmanager:GetSecretValue` on the secret ARN, then `kms:Decrypt` on the CMK (from `--key-id` or the key id embedded in the blob). `kms:Decrypt` IAM enforcement scopes to `arn:aws:kms:REGION:ACCOUNT:key/KEY-ID` from `KeyId` or from the `kms:v2:` blob. Regression: `SecretsManagerKmsEnvelopeIntegrationTest`.

### Rotation and pre-wrapped KMS envelopes

Lambda rotation hooks often call `PutSecretValue` with a value that is already a KMS `CiphertextBlob` (from `kms:Encrypt`). Floci stores that blob without re-wrapping it in a second envelope. `GetSecretValue` returns the same base64 `SecretBinary`; one `kms:Decrypt` yields the application plaintext (not nested `kms:v2:` bytes). Applies to `SecretBinary` on `PutSecretValue` and to pre-wrapped `SecretString` promoted to `AWSCURRENT` via `UpdateSecretVersionStage`.

Regression: `SecretsManagerRotationKmsIntegrationTest` (`putSecretValueWithPreWrappedEnvelopeDuringRotationDoesNotDoubleWrap`, `putSecretValueWithPreWrappedSecretStringPromotesToCurrentWithoutDoubleWrap`).

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Fetch ciphertext (requires secretsmanager:GetSecretValue on the secret ARN)
BINARY=$(aws secretsmanager get-secret-value --secret-id my-app/cmk-secret \
  --query SecretBinary --output text \
  --endpoint-url "$AWS_ENDPOINT_URL")

# Single decrypt -> application plaintext (SecretBinary is valid CiphertextBlob base64)
aws kms decrypt --key-id "$CMK_KEY_ID" \
  --ciphertext-blob "$BINARY" \
  --query Plaintext --output text \
  --endpoint-url "$AWS_ENDPOINT_URL" | base64 -d
```

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create a string secret
aws secretsmanager create-secret \
  --name /app/database-url \
  --secret-string "postgresql://admin:secret@localhost/mydb" \
  --endpoint-url $AWS_ENDPOINT_URL

# Create a JSON secret
aws secretsmanager create-secret \
  --name /app/api-keys \
  --secret-string '{"stripe":"sk_test_xxx","sendgrid":"SG.xxx"}' \
  --endpoint-url $AWS_ENDPOINT_URL

# Retrieve a secret
aws secretsmanager get-secret-value \
  --secret-id /app/database-url \
  --endpoint-url $AWS_ENDPOINT_URL

# Update a secret
aws secretsmanager put-secret-value \
  --secret-id /app/database-url \
  --secret-string "postgresql://admin:new-password@localhost/mydb" \
  --endpoint-url $AWS_ENDPOINT_URL

# List secrets
aws secretsmanager list-secrets --endpoint-url $AWS_ENDPOINT_URL

# Delete (with recovery window)
aws secretsmanager delete-secret \
  --secret-id /app/database-url \
  --recovery-window-in-days 7 \
  --endpoint-url $AWS_ENDPOINT_URL

# Delete immediately (no recovery)
aws secretsmanager delete-secret \
  --secret-id /app/database-url \
  --force-delete-without-recovery \
  --endpoint-url $AWS_ENDPOINT_URL

# Generate a random password
aws secretsmanager get-random-password \
  --password-length 24 \
  --exclude-punctuation \
  --endpoint-url $AWS_ENDPOINT_URL

# Batch-fetch multiple secrets in one call
aws secretsmanager batch-get-secret-value \
  --secret-id-list /app/database-url /app/api-keys \
  --endpoint-url $AWS_ENDPOINT_URL

# Move the AWSCURRENT label to a different version (e.g. during a rotation)
aws secretsmanager update-secret-version-stage \
  --secret-id /app/database-url \
  --version-stage AWSCURRENT \
  --move-to-version-id <new-version-id> \
  --remove-from-version-id <old-version-id> \
  --endpoint-url $AWS_ENDPOINT_URL
```
