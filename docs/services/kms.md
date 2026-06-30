# KMS

**Protocol:** JSON 1.1 (`X-Amz-Target: TrentService.*`)
**Endpoint:** `POST http://localhost:4566/`

## Supported Actions

| Action | Description |
|---|---|
| `CreateKey` | Create a new KMS key |
| `GenerateRandom` | Generate random bytes |
| `GetPublicKey` | Get public key material for asymmetric keys |
| `DescribeKey` | Get key metadata |
| `ListKeys` | List all keys |
| `Encrypt` | Encrypt plaintext with a key |
| `Decrypt` | Decrypt ciphertext |
| `ReEncrypt` | Re-encrypt under a different key |
| `GenerateDataKey` | Generate a data key (plaintext + encrypted) |
| `GenerateDataKeyWithoutPlaintext` | Generate only the encrypted data key |
| `Sign` | Sign a message with an asymmetric key |
| `Verify` | Verify a signature |
| `GenerateMac` | Generate a MAC with an HMAC key |
| `VerifyMac` | Verify a MAC with an HMAC key |
| `CreateAlias` | Create a friendly name for a key |
| `DeleteAlias` | Remove an alias |
| `ListAliases` | List all aliases |
| `ScheduleKeyDeletion` | Mark a key for deletion |
| `CancelKeyDeletion` | Cancel pending deletion |
| `EnableKey` | Enable a key |
| `DisableKey` | Disable a key |
| `TagResource` | Tag a key |
| `UntagResource` | Remove tags |
| `ListResourceTags` | List tags |
| `GetKeyPolicy` | Get a key's resource policy |
| `PutKeyPolicy` | Update a key's resource policy |
| `UpdateKeyDescription` | Update a key's description |
| `GetKeyRotationStatus` | Check if automatic key rotation is enabled |
| `EnableKeyRotation` | Enable automatic key rotation (symmetric keys only) |
| `DisableKeyRotation` | Disable automatic key rotation |
| `RotateKeyOnDemand` | Rotate key material on demand (symmetric keys only) |
| `CreateGrant` | Create a grant for a KMS key |
| `ListGrants` | List grants for a KMS key |
| `ListRetirableGrants` | List grants retirable by a principal |
| `RevokeGrant` | Revoke (administratively delete) a grant |
| `RetireGrant` | Retire a grant (token- or key+grant-based) |

## Grant Support Scope

Grant lifecycle operations (`CreateGrant`, `ListGrants`, `ListRetirableGrants`, `RevokeGrant`, `RetireGrant`) are supported.

In permissive mode, grants are stored and queryable but are **not** evaluated during cryptographic operations (`Encrypt`, `Decrypt`, `Sign`, `Verify`, `GenerateDataKey`, etc.).

## CTF fork {#ctf-fork}

When `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`, HTTP data-plane calls evaluate grants after identity and key policy checks. A valid grant for the caller principal and operation can allow `Decrypt` (and related crypto actions) when IAM alone would deny. In-process calls from Step Functions `aws-sdk` tasks do not evaluate grants yet; use the state machine execution role's IAM policy for those paths.

### CloudTrail audit (HTTP)

When `FLOCI_SERVICES_CLOUDTRAIL_AUDIT_ENABLED=true` and a trail is logging, KMS API calls emit management events indexed for `lookup-events`. `Decrypt` matches [AWS KMS CloudTrail events](https://docs.aws.amazon.com/kms/latest/developerguide/logging-using-cloudtrail.html):

| Field | Behavior |
|-------|----------|
| `readOnly` | `true` for `Decrypt` |
| `requestParameters.keyId` | Full key ARN; resolved from explicit `KeyId`, response `KeyId`, or Floci `kms:v2:` envelope in `CiphertextBlob` |
| `requestParameters.encryptionContext` | Present when supplied in the request body |
| `requestParameters.encryptionAlgorithm` | Defaults to `SYMMETRIC_DEFAULT` when omitted |
| Sensitive fields | `CiphertextBlob` and `Plaintext` are omitted from audit |
| `resources[]` | `AWS::KMS::Key` with key ARN and account id |
| `eventCategory` | `Management` |

Regression: `CloudTrailKmsDecryptAuditIntegrationTest`, `KmsDecryptScopedKeyIntegrationTest`. Cross-reference: [CloudTrail data-plane audit](./cloudtrail.md#data-plane-requestparameters-http-audit).

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_KMS_ENABLED` | `true` | Enable or disable the service |

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Create a symmetric key
KEY_ID=$(aws kms create-key \
  --description "My encryption key" \
  --query KeyMetadata.KeyId --output text \
  --endpoint-url $AWS_ENDPOINT_URL)

# Create an alias
aws kms create-alias \
  --alias-name alias/my-key \
  --target-key-id $KEY_ID \
  --endpoint-url $AWS_ENDPOINT_URL

# Encrypt
CIPHER=$(aws kms encrypt \
  --key-id alias/my-key \
  --plaintext "Hello, World!" \
  --query CiphertextBlob --output text \
  --endpoint-url $AWS_ENDPOINT_URL)

# Decrypt
aws kms decrypt \
  --ciphertext-blob $CIPHER \
  --query Plaintext --output text \
  --endpoint-url $AWS_ENDPOINT_URL | base64 --decode

# Generate a data key (envelope encryption)
aws kms generate-data-key \
  --key-id alias/my-key \
  --key-spec AES_256 \
  --endpoint-url $AWS_ENDPOINT_URL
```
`CreateKey` also accepts a reserved creation-time tag key, `floci:override-id`, when tests need a deterministic `KeyId`. Floci uses the tag value as the created key id, strips the reserved tag from stored resource tags, and rejects attempts to add `floci:*` tags later via `TagResource`.
