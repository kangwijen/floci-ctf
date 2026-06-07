# STS

**Protocol:** Query (XML) — `POST http://localhost:4566/` with `Action=` parameter

## Supported Actions

| Action | Description |
|---|---|
| `GetCallerIdentity` | Returns the account ID, user ID, and ARN |
| `AssumeRole` | Assume an IAM role, returns temporary credentials |
| `AssumeRoleWithWebIdentity` | Assume a role using a web identity token (OIDC) |
| `AssumeRoleWithSAML` | Assume a role using a SAML assertion |
| `GetSessionToken` | Get temporary credentials for an IAM user |
| `GetFederationToken` | Get temporary credentials for a federated user |
| `DecodeAuthorizationMessage` | Decode an encoded authorization failure message |

## Configuration

| Variable | Default | Description |
|---|---|---|
| `FLOCI_SERVICES_STS_ENABLED` | `true` | Enable or disable the service |

## Examples

```bash
export AWS_ENDPOINT_URL=http://localhost:4566

# Get caller identity (always works, useful for smoke testing)
aws sts get-caller-identity --endpoint-url $AWS_ENDPOINT_URL

# Assume a role
aws sts assume-role \
  --role-arn arn:aws:iam::000000000000:role/my-role \
  --role-session-name dev-session \
  --endpoint-url $AWS_ENDPOINT_URL

# Get a session token
aws sts get-session-token --endpoint-url $AWS_ENDPOINT_URL
```

`GetCallerIdentity` is commonly used in CI pipelines and integration tests as a quick connectivity check before running more complex tests.

## CTF fork {#ctf-fork}

When IAM enforcement is enabled:

| Action | CTF behavior |
|---|---|
| `GetSessionToken` | Returned session credentials are limited to the intersection of the caller's IAM policies and any optional inline session policy |
| `AssumeRole` / `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML` | Role trust policies are evaluated (`Principal`, `:root`, federated conditions); WebIdentity and SAML assertions are parsed for claim-based trust (no external IdP crypto validation) |
| `GetFederationToken` | Federated principal name is extracted from the assertion for trust matching |

STS control-plane calls still require SigV4 from a registered principal or the operator root pair.
