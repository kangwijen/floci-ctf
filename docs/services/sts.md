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
`sts:AssumeRole`. Roles that Floci has no record of stay permissive unless IAM strict enforcement
is also on (Compose CTF), in which case missing roles return `AccessDenied` and no ASIA session
is minted.

### Known limitations (upstream default)

- **`Condition` blocks are not evaluated** by upstream `AssumeRolePolicyEvaluator`. A trust policy
  that requires `sts:ExternalId` is matched on its principal alone; the `ExternalId` request
  parameter is ignored. This matches moto/LocalStack.

Under CTF hardening (`FLOCI_SERVICES_IAM_ENFORCEMENT_ENABLED=true`), `StsQueryHandler` uses
`AssumeRoleTrustPolicyEvaluator` instead: `sts:ExternalId` conditions are enforced and federated
WebIdentity/SAML trust is evaluated. Unknown roles stay permissive only when strict enforcement
is off; with `FLOCI_SERVICES_IAM_STRICT_ENFORCEMENT_ENABLED=true` (Compose CTF) they are denied
(`StsAssumeRoleMissingRoleStrictIntegrationTest`). Same-account `AssumeRole` succeeds on trust
policy alone unless the caller has an explicit identity Deny on `sts:AssumeRole` for the role ARN.
Cross-account calls require both trust Allow and caller identity Allow. Regression:
`StsAssumeRoleCallerIdentityPolicyIntegrationTest`. Strict mode still requires registered access
keys; integration tests must use operator root or IAM users with `create-access-key`, not fake
account-id AKIDs.

**OIDC/federated condition matching (CTF Stage 4):**

- **Multi-value `aud`:** When an OIDC token `aud` claim is a JSON array, the provider-prefixed
  condition key (e.g. `accounts.google.com:aud`) stores all values comma-joined. Trust policy
  `StringEquals` / `StringLike` conditions on that key match any individual audience, matching
  AWS `ForAnyValue` semantics. The bare `aud` key and `:oaud` key retain the first audience value.
  If `azp` is present it overrides the multi-value list for both keys, as AWS specifies.
- **`nbf` (not-before) enforcement:** When `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS=true`, tokens whose `nbf` claim is in the future are rejected.
- **`iss` alignment:** When validation is enabled and the JWT carries an `iss` claim, it must match the OIDC provider host from `ProviderId`.
- **SAML time conditions:** When validation is enabled, `NotBefore` / `NotOnOrAfter` on the assertion (including `SubjectConfirmationData`) are enforced.
- **SAML XML signature verification:** When validation is enabled and `FLOCI_CTF_FEDERATED_SAML_SIGNING_CERT_PEM` or per-provider `FLOCI_CTF_FEDERATED_SAML_SIGNING_CERTS__*` is set, SAML assertions must carry a valid enveloped XML signature from a pinned trust anchor (Apache Santuario). Claims are taken only from the Assertion node covered by the verified Signature. Documents that also contain an unsigned Assertion outside that signed subtree (XML Signature Wrapping) are rejected (`SamlWrappedAssertionRejectedTest`). The SAML XML parser rejects DOCTYPE declarations and external entities. Structural checks still require a non-trivial `SignatureValue` when no cert is configured.
- **Federated crypto under strict IAM:** When IAM enforcement and strict mode are both on (Compose CTF), federated token crypto is required even if `application.yml` leaves `validate-federated-tokens` at the lab default `false`. Unsigned / `alg=none` web identity tokens return `InvalidIdentityToken` (`StsWebIdentityStrictUnsignedIntegrationTest`). YAML defaults are not flipped globally (Phase B AuthPosture).
- **`AssumeRoleWithSAML` response fields** use parsed assertion claims (`Issuer`, `Subject`, `Audience`) and optional `RoleSessionName` (defaulting from `NameID`).
- **Invalid federated tokens** on known roles return `InvalidIdentityToken` (400) when parsing fails; trust failures remain `AccessDenied` (403).
- **Trust policy explicit `Deny`** is evaluated before `Allow` statements.

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
| `AssumeRole` | Same-account: trust policy Allow is sufficient unless caller identity explicitly Denies `sts:AssumeRole` on the role. Cross-account: caller identity must Allow the role ARN in addition to trust Allow. WebIdentity/SAML trust evaluated; federated token validation via `FLOCI_CTF_VALIDATE_FEDERATED_TOKENS` or IAM strict posture. Missing roles denied under strict IAM. Regression: `StsAssumeRoleCallerIdentityPolicyIntegrationTest`, `AssumeRoleTrustPolicyIntegrationTest`, `StsAssumeRoleMissingRoleStrictIntegrationTest` |
| `AssumeRoleWithWebIdentity` / `AssumeRoleWithSAML` | Authenticated by JWT or SAML assertion in the form body, not SigV4. Under strict IAM, `IamEnforcementFilter` skips the missing-Authorization gate; trust and federated crypto run in `StsQueryHandler`. Unsigned tokens denied under strict. Regression: `StsWebIdentityStrictUnsignedIntegrationTest`, `StsWebIdentityTrustIntegrationTest`, `SamlWrappedAssertionRejectedTest` |
| `GetFederationToken` | Federated principal name is extracted from the assertion for trust matching |

Most STS control-plane calls require SigV4 from a registered principal or the operator root pair. **Exception:** `AssumeRoleWithWebIdentity` and `AssumeRoleWithSAML` when the corresponding token field is present in the form body.

When `FLOCI_SERVICES_IAM_SEED_DEPLOYER_PRINCIPAL=true` and IAM enforcement is off, requests signed with the seeded `floci` access key return `arn:aws:iam::000000000000:user/floci-deployer`. With IAM enforcement enabled (Compose default), the deployer principal is not seeded.
