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

## Trust Policy Enforcement

By default `AssumeRole` succeeds for any caller. When `FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`,
`AssumeRole` evaluates the target role's trust policy (`AssumeRolePolicyDocument`) against the caller
and returns `AccessDenied` if it is not permitted. AWS principal forms are matched — `"*"`, an
account id, an account-root ARN (`arn:aws:iam::<acct>:root`), and exact principal ARNs — and an
explicit `Deny` always wins. Both `Action` and `NotAction` elements are honored when matching
`sts:AssumeRole`. Roles that Floci has no record of stay permissive, so this only affects roles
created through IAM with a real trust policy.

### Known limitations (upstream default)

- **`Condition` blocks are not evaluated** by upstream `AssumeRolePolicyEvaluator`. A trust policy
  that requires `sts:ExternalId` is matched on its principal alone; the `ExternalId` request
  parameter is ignored. This matches moto/LocalStack.

Under CTF hardening (`FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`), `StsQueryHandler` uses
`AssumeRoleTrustPolicyEvaluator` instead: `sts:ExternalId` conditions are enforced, federated
WebIdentity/SAML trust is evaluated, and unknown roles (not in IAM storage) stay permissive.
Same-account `AssumeRole` succeeds on trust policy alone unless the caller has an explicit
identity Deny on `sts:AssumeRole` for the role ARN. Cross-account calls require both trust
Allow and caller identity Allow. Regression: `StsAssumeRoleCallerIdentityPolicyIntegrationTest`.
Strict mode still requires registered access keys; integration tests must use operator root or IAM
users with `create-access-key`, not fake account-id AKIDs.

**OIDC/federated condition matching (CTF Stage 4):**

- **Multi-value `aud`:** When an OIDC token `aud` claim is a JSON array, the provider-prefixed
  condition key (e.g. `accounts.google.com:aud`) stores all values comma-joined. Trust policy
  `StringEquals` / `StringLike` conditions on that key match any individual audience, matching
  AWS `ForAnyValue` semantics. The bare `aud` key and `:oaud` key retain the first audience value.
  If `azp` is present it overrides the multi-value list for both keys, as AWS specifies.
- **`nbf` (not-before) enforcement:** When `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=true`, tokens
  whose `nbf` claim is in the future are rejected.
- **SAML `SignatureValue` trivial-sig rejection:** When validation is enabled, SAML assertions
  whose `SignatureValue` element decodes to fewer than 64 bytes are rejected as structurally
  inadequate.

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

`GetCallerIdentity` is commonly used in CI pipelines and integration tests as a quick connectivity check before running more complex tests. Under CTF hardening, participant IAM user keys return the user ARN from `sts:GetCallerIdentity`, not `arn:aws:iam::ACCOUNT:root` (see [CTF fork](#ctf-fork)).

## CTF fork {#ctf-fork}

When IAM enforcement is enabled:

| Action | CTF behavior |
|---|---|
| `GetCallerIdentity` | Returns the **calling principal ARN**, not account `:root` for IAM user access keys (`arn:aws:iam::ACCOUNT:user/name`) or temporary assumed-role sessions (`arn:aws:sts::ACCOUNT:assumed-role/role/session`). Operator requests signed with `FLOCI_AUTH_ROOT_ACCESS_KEY_ID` still return `arn:aws:iam::ACCOUNT:root`. Policy-exempt like AWS (no Allow required; explicit Deny does not block). Regression: `StsGetCallerIdentityIntegrationTest` |
| `GetSessionToken` | Returned session credentials are limited to the intersection of the caller's IAM policies and any optional inline session policy; session policy alone cannot expand permissions. Parent user permission boundaries apply. Regression: `StsGetSessionTokenIntersectionIntegrationTest` |
| `AssumeRole` | Same-account: trust policy Allow is sufficient unless caller identity explicitly Denies `sts:AssumeRole` on the role. Cross-account: caller identity must Allow the role ARN in addition to trust Allow. WebIdentity/SAML trust evaluated; federated token validation optional via `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS`. Regression: `StsAssumeRoleCallerIdentityPolicyIntegrationTest`, `AssumeRoleTrustPolicyIntegrationTest` |
| `GetFederationToken` | Federated principal name is extracted from the assertion for trust matching |

STS control-plane calls still require SigV4 from a registered principal or the operator root pair.

When `FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL=true` and IAM enforcement is off, requests signed with the seeded `floci` access key return `arn:aws:iam::000000000000:user/floci-deployer`. With IAM enforcement enabled (Compose default), the deployer principal is not seeded.
