package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;

import java.util.Optional;
import io.github.hectorvent.floci.core.common.AwsNamespaces;
import io.github.hectorvent.floci.core.common.AwsQueryController;
import io.github.hectorvent.floci.core.common.AwsQueryResponse;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.XmlBuilder;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.time.Instant;
import java.time.format.DateTimeFormatter;
import java.util.concurrent.ThreadLocalRandom;

/**
 * Query-protocol handler for STS (Security Token Service) actions.
 * Receives pre-dispatched calls from {@link AwsQueryController}.
 * All responses use the STS XML namespace {@code https://sts.amazonaws.com/doc/2011-06-15/}.
 */
@ApplicationScoped
public class StsQueryHandler {

    private static final Logger LOG = Logger.getLogger(StsQueryHandler.class);
    private static final String CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";

    private final IamService iamService;
    private final RegionResolver regionResolver;
    private final AccountResolver accountResolver;
    private final EmulatorConfig config;

    @Context
    HttpHeaders headers;

    @Inject
    public StsQueryHandler(IamService iamService, RegionResolver regionResolver,
                           AccountResolver accountResolver, EmulatorConfig config) {
        this.iamService = iamService;
        this.regionResolver = regionResolver;
        this.accountResolver = accountResolver;
        this.config = config;
    }

    public Response handle(String action, MultivaluedMap<String, String> params, String authorization) {
        action = IamUnrestrictedActions.canonicalQueryOperation("sts", action);
        LOG.debugv("STS action: {0}", action);

        return switch (action) {
            case "AssumeRole"                  -> handleAssumeRole(params, authorization);
            case "GetCallerIdentity"           -> handleGetCallerIdentity(authorization);
            case "GetSessionToken"             -> handleGetSessionToken(params, authorization);
            case "AssumeRoleWithWebIdentity"   -> handleAssumeRoleWithWebIdentity(params, authorization);
            case "AssumeRoleWithSAML"          -> handleAssumeRoleWithSAML(params, authorization);
            case "GetFederationToken"          -> handleGetFederationToken(params, authorization);
            case "DecodeAuthorizationMessage"  -> handleDecodeAuthorizationMessage(params);
            default -> AwsQueryResponse.error("UnsupportedOperation",
                    "Operation " + action + " is not supported by STS.", AwsNamespaces.STS, 400);
        };
    }

    private Response handleAssumeRole(MultivaluedMap<String, String> params, String authorization) {
        Response validation = validateRequired(params, "RoleArn", "RoleSessionName");
        if (validation != null) {
            return validation;
        }
        Response trustDeny = validateAssumeRoleTrust(params, authorization, "sts:AssumeRole");
        if (trustDeny != null) {
            return trustDeny;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = getParam(params, "RoleSessionName");
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn != null && roleArn.contains("/")
                ? roleArn.substring(roleArn.lastIndexOf('/') + 1)
                : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        String assumedRoleId = "AROA" + randomId(16) + ":" + sessionName;

        // Register session so IAM enforcement can resolve the role's policies, RDS/ElastiCache
        // IAM token validation can find the temporary secret key, and account routing can map
        // these temporary credentials to the assumed role's account.
        String sessionPolicy = getParam(params, "Policy");
        iamService.registerSession(accessKeyId, roleArn, expiration, sessionPolicy, secretKey,
                assumedRoleId, assumedRoleArn, null, sessionToken, callerAccountId);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRole", AwsNamespaces.STS, result)).build();
    }

    private Response handleGetCallerIdentity(String authorization) {
        String accessKeyId = accountResolver.extractAccessKeyId(authorization);
        String defaultAccountId = accountResolver.resolve(authorization);
        CallerIdentity identity = iamService.resolveCallerIdentity(
                        accessKeyId, defaultAccountId, config.auth().rootAccessKeyId())
                .orElseGet(() -> CallerIdentity.root(defaultAccountId));
        String result = new XmlBuilder()
                .elem("UserId", identity.userId())
                .elem("Account", identity.account())
                .elem("Arn", identity.arn())
                .build();
        return Response.ok(AwsQueryResponse.envelope("GetCallerIdentity", AwsNamespaces.STS, result)).build();
    }

    private Response handleGetSessionToken(MultivaluedMap<String, String> params, String authorization) {
        int durationSeconds = getIntParam(params, "DurationSeconds", 43200);
        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String accountId = regionResolver.getAccountId();
        String sessionArn = AwsArnUtils.Arn.of("sts", "", accountId, "federated-user/floci-session").toString();
        String federatedUserId = accountId + ":floci-session";
        String sessionPolicy = getParam(params, "Policy");
        String parentAccessKeyId = accountResolver.extractAccessKeyId(authorization);
        iamService.registerSession(accessKeyId, sessionArn, expiration, sessionPolicy, secretKey,
                federatedUserId, sessionArn, parentAccessKeyId, sessionToken, accountId);

        String result = credentialsXml(accessKeyId, secretKey, sessionToken, expiration);
        return Response.ok(AwsQueryResponse.envelope("GetSessionToken", AwsNamespaces.STS, result)).build();
    }

    private Response handleAssumeRoleWithWebIdentity(MultivaluedMap<String, String> params, String authorization) {
        Response validation = validateRequired(params, "RoleArn", "RoleSessionName", "WebIdentityToken");
        if (validation != null) {
            return validation;
        }
        Response trustDeny = validateAssumeRoleTrust(params, authorization, "sts:AssumeRoleWithWebIdentity");
        if (trustDeny != null) {
            return trustDeny;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = getParam(params, "RoleSessionName");
        String providerId = getParam(params, "ProviderId");
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);
        String roleAccountId = AwsArnUtils.accountOrDefault(roleArn, regionResolver.getAccountId());
        FederatedTrustContext federatedContext = FederatedTokenParser.parseWebIdentityToken(
                getParam(params, "WebIdentityToken"),
                providerId,
                roleAccountId,
                FederatedTokenValidationConfig.from(config.ctf()));

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        String assumedRoleId = "AROA" + randomId(16) + ":" + sessionName;
        String provider = providerId != null && !providerId.isBlank()
                ? providerId
                : FederatedTokenParser.oidcProviderHost(
                        federatedContext == null ? null : federatedContext.federatedPrincipal());
        if (provider == null || provider.isBlank()) {
            provider = "accounts.google.com";
        }
        String audience = federatedContext == null ? null
                : federatedContext.conditionClaims().get("aud");
        String subject = federatedContext == null ? null
                : federatedContext.conditionClaims().get("sub");

        String sessionPolicy = getParam(params, "Policy");
        iamService.registerSession(accessKeyId, roleArn, expiration, sessionPolicy, secretKey,
                assumedRoleId, assumedRoleArn, null, sessionToken, callerAccountId);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .elem("Provider", provider)
                .elem("Audience", audience != null ? audience : "sts.amazonaws.com")
                .elem("SubjectFromWebIdentityToken", subject != null ? subject : "web-identity-subject")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRoleWithWebIdentity", AwsNamespaces.STS, result)).build();
    }

    private Response handleAssumeRoleWithSAML(MultivaluedMap<String, String> params, String authorization) {
        Response validation = validateRequired(params, "RoleArn", "PrincipalArn", "SAMLAssertion");
        if (validation != null) {
            return validation;
        }
        Response trustDeny = validateAssumeRoleTrust(params, authorization, "sts:AssumeRoleWithSAML");
        if (trustDeny != null) {
            return trustDeny;
        }
        String roleArn = getParam(params, "RoleArn");
        String sessionName = "saml-session";
        int durationSeconds = getIntParam(params, "DurationSeconds", 3600);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);

        String roleName = roleArn.contains("/") ? roleArn.substring(roleArn.lastIndexOf('/') + 1) : "UnknownRole";
        String callerAccountId = regionResolver.getAccountId();
        String accountId = AwsArnUtils.accountOrDefault(roleArn, callerAccountId);
        String assumedRoleArn = AwsArnUtils.Arn.of("sts", "", accountId, "assumed-role/" + roleName + "/" + sessionName).toString();
        String assumedRoleId = "AROA" + randomId(16) + ":" + sessionName;

        iamService.registerSession(accessKeyId, roleArn, expiration, null, secretKey,
                assumedRoleId, assumedRoleArn, null, sessionToken, callerAccountId);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("AssumedRoleUser")
                  .elem("Arn", assumedRoleArn)
                  .elem("AssumedRoleId", assumedRoleId)
                .end("AssumedRoleUser")
                .elem("PackedPolicySize", "0")
                .elem("Issuer", "https://saml.example.com")
                .elem("Audience", "urn:amazon:webservices")
                .elem("NameQualifier", "saml-qualifier")
                .elem("SubjectType", "persistent")
                .elem("Subject", "saml-subject")
                .build();
        return Response.ok(AwsQueryResponse.envelope("AssumeRoleWithSAML", AwsNamespaces.STS, result)).build();
    }

    private Response handleGetFederationToken(MultivaluedMap<String, String> params, String authorization) {
        Response validation = validateRequired(params, "Name");
        if (validation != null) {
            return validation;
        }
        String name = getParam(params, "Name");
        int durationSeconds = getIntParam(params, "DurationSeconds", 43200);

        String accessKeyId = "ASIA" + randomId(16);
        String secretKey = randomSecret(40);
        String sessionToken = randomSecret(200);
        Instant expiration = Instant.now().plusSeconds(durationSeconds);
        String accountId = regionResolver.getAccountId();
        String federatedUserId = accountId + ":" + name;
        String federatedUserArn = AwsArnUtils.Arn.of("sts", "", accountId, "federated-user/" + name).toString();

        String sessionPolicy = getParam(params, "Policy");
        String parentAccessKeyId = accountResolver.extractAccessKeyId(authorization);
        iamService.registerSession(accessKeyId, federatedUserArn, expiration, sessionPolicy, secretKey,
                federatedUserId, federatedUserArn, parentAccessKeyId, sessionToken, accountId);

        String result = new XmlBuilder()
                .raw(credentialsXml(accessKeyId, secretKey, sessionToken, expiration))
                .start("FederatedUser")
                  .elem("FederatedUserId", federatedUserId)
                  .elem("Arn", federatedUserArn)
                .end("FederatedUser")
                .elem("PackedPolicySize", "0")
                .build();
        return Response.ok(AwsQueryResponse.envelope("GetFederationToken", AwsNamespaces.STS, result)).build();
    }

    private Response handleDecodeAuthorizationMessage(MultivaluedMap<String, String> params) {
        Response validation = validateRequired(params, "EncodedMessage");
        if (validation != null) {
            return validation;
        }
        String encodedMessage = getParam(params, "EncodedMessage");
        String result = new XmlBuilder().elem("DecodedMessage", encodedMessage).build();
        return Response.ok(AwsQueryResponse.envelope("DecodeAuthorizationMessage", AwsNamespaces.STS, result)).build();
    }

    private Response validateAssumeRoleTrust(MultivaluedMap<String, String> params, String authorization,
                                             String stsAction) {
        String roleArn = getParam(params, "RoleArn");
        if (roleArn == null || roleArn.isBlank()) {
            return null;
        }
        FederatedTrustContext federatedContext = buildFederatedTrustContext(params, stsAction, roleArn);
        if (isFederatedAssumeRoleAction(stsAction)) {
            if (federatedContext == null) {
                return AwsQueryResponse.error("AccessDenied",
                        "User is not authorized to perform: " + stsAction + " on resource: " + roleArn,
                        AwsNamespaces.STS, 403);
            }
            try {
                iamService.validateAssumeRoleTrust(
                        roleArn, federatedContext.federatedPrincipal(), getParam(params, "ExternalId"),
                        stsAction, federatedContext);
            } catch (AwsException e) {
                return AwsQueryResponse.error(e.getErrorCode(), e.getMessage(), AwsNamespaces.STS, e.getHttpStatus());
            }
            return null;
        }
        String accessKeyId = accountResolver.extractAccessKeyId(authorization);
        String defaultAccountId = accountResolver.resolve(authorization);
        Optional<CallerIdentity> caller = iamService.resolveCallerIdentity(
                accessKeyId, defaultAccountId, config.auth().rootAccessKeyId());
        if (caller.isEmpty()) {
            return AwsQueryResponse.error("AccessDenied",
                    "User is not authorized to perform: " + stsAction + " on resource: " + roleArn,
                    AwsNamespaces.STS, 403);
        }
        try {
            iamService.validateAssumeRoleTrust(
                    roleArn, caller.get().arn(), getParam(params, "ExternalId"), stsAction);
        } catch (AwsException e) {
            return AwsQueryResponse.error(e.getErrorCode(), e.getMessage(), AwsNamespaces.STS, e.getHttpStatus());
        }
        return null;
    }

    private FederatedTrustContext buildFederatedTrustContext(MultivaluedMap<String, String> params,
                                                             String stsAction,
                                                             String roleArn) {
        String roleAccountId = AwsArnUtils.accountOrDefault(roleArn, regionResolver.getAccountId());
        FederatedTokenValidationConfig validationConfig = FederatedTokenValidationConfig.from(config.ctf());
        if ("sts:AssumeRoleWithWebIdentity".equals(stsAction)) {
            return FederatedTokenParser.parseWebIdentityToken(
                    getParam(params, "WebIdentityToken"),
                    getParam(params, "ProviderId"),
                    roleAccountId,
                    validationConfig);
        }
        if ("sts:AssumeRoleWithSAML".equals(stsAction)) {
            return FederatedTokenParser.parseSamlAssertion(
                    getParam(params, "SAMLAssertion"),
                    getParam(params, "PrincipalArn"),
                    validationConfig);
        }
        return null;
    }

    private static boolean isFederatedAssumeRoleAction(String stsAction) {
        return "sts:AssumeRoleWithWebIdentity".equals(stsAction)
                || "sts:AssumeRoleWithSAML".equals(stsAction);
    }

    private Response validateRequired(MultivaluedMap<String, String> params, String... names) {
        for (String name : names) {
            String value = params.getFirst(name);
            if (value == null || value.isBlank()) {
                return AwsQueryResponse.error("ValidationError",
                        "1 validation error detected: Value null at '" + name
                        + "' failed to satisfy constraint: Member must not be null",
                        AwsNamespaces.STS, 400);
            }
        }
        return null;
    }

    private String credentialsXml(String accessKeyId, String secretKey, String sessionToken, Instant expiration) {
        return new XmlBuilder()
                .start("Credentials")
                  .elem("AccessKeyId", accessKeyId)
                  .elem("SecretAccessKey", secretKey)
                  .elem("SessionToken", sessionToken)
                  .elem("Expiration", isoDate(expiration))
                .end("Credentials")
                .build();
    }

    private String getParam(MultivaluedMap<String, String> params, String name) {
        return params.getFirst(name);
    }

    private int getIntParam(MultivaluedMap<String, String> params, String name, int defaultValue) {
        String value = params.getFirst(name);
        if (value == null) return defaultValue;
        try {
            return Integer.parseInt(value);
        } catch (NumberFormatException e) {
            return defaultValue;
        }
    }

    private String isoDate(Instant instant) {
        return DateTimeFormatter.ISO_INSTANT.format(instant);
    }

    private static String randomId(int length) {
        StringBuilder sb = new StringBuilder(length);
        String upper = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
        for (int i = 0; i < length; i++) {
            sb.append(upper.charAt(ThreadLocalRandom.current().nextInt(upper.length())));
        }
        return sb.toString();
    }

    private static String randomSecret(int length) {
        StringBuilder sb = new StringBuilder(length);
        for (int i = 0; i < length; i++) {
            sb.append(CHARS.charAt(ThreadLocalRandom.current().nextInt(CHARS.length())));
        }
        return sb.toString();
    }
}
