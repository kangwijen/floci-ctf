package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses OIDC JWT and SAML assertion payloads for trust-policy condition evaluation.
 * Cryptographic validation is intentionally omitted in the local emulator.
 */
public final class FederatedTokenParser {

    private static final Logger LOG = Logger.getLogger(FederatedTokenParser.class);
    private static final TypeReference<Map<String, Object>> CLAIM_MAP_TYPE = new TypeReference<>() {};
    private static final ObjectMapper JWT_MAPPER = new ObjectMapper();

    private static final Pattern XML_TAG = Pattern.compile(
            "<(?:[\\w]+:)?(Issuer|NameID|Audience|SubjectConfirmationData)(?:\\s[^>]*)?>([^<]*)</(?:[\\w]+:)?\\1>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern RECIPIENT_ATTR = Pattern.compile(
            "Recipient\\s*=\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);

    private FederatedTokenParser() {
    }

    public static FederatedTrustContext parseWebIdentityToken(String webIdentityToken,
                                                              String providerId,
                                                              String roleAccountId) {
        Map<String, Object> claims = parseJwtPayload(webIdentityToken);
        if (claims.isEmpty()) {
            return null;
        }
        String provider = resolveOidcProviderPrincipal(providerId, roleAccountId);
        String providerHost = oidcProviderHost(provider);
        Map<String, String> conditionClaims = buildOidcConditionClaims(claims, providerHost);
        return new FederatedTrustContext(provider, conditionClaims);
    }

    public static FederatedTrustContext parseSamlAssertion(String samlAssertionBase64,
                                                           String principalArn) {
        if (samlAssertionBase64 == null || samlAssertionBase64.isBlank()) {
            return null;
        }
        String xml;
        try {
            xml = new String(Base64.getDecoder().decode(samlAssertionBase64), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            LOG.debugv("Invalid SAML assertion encoding: {0}", e.getMessage());
            return null;
        }
        Map<String, String> samlClaims = extractSamlClaims(xml, principalArn);
        if (samlClaims.isEmpty()) {
            return null;
        }
        return new FederatedTrustContext(principalArn, samlClaims);
    }

    static Map<String, Object> parseJwtPayload(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return Map.of();
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return Map.of();
        }
        try {
            byte[] payload = decodeBase64Url(parts[1]);
            return JWT_MAPPER.readValue(payload, CLAIM_MAP_TYPE);
        } catch (Exception e) {
            LOG.debugv("Failed to decode JWT payload: {0}", e.getMessage());
            return Map.of();
        }
    }

    static String resolveOidcProviderPrincipal(String providerId, String roleAccountId) {
        if (providerId != null && providerId.contains(":oidc-provider/")) {
            return providerId;
        }
        String host = providerId == null || providerId.isBlank()
                ? "accounts.google.com"
                : providerId;
        String account = roleAccountId == null || roleAccountId.isBlank()
                ? "000000000000"
                : roleAccountId;
        return "arn:aws:iam::" + account + ":oidc-provider/" + host;
    }

    static String oidcProviderHost(String providerPrincipal) {
        if (providerPrincipal == null) {
            return "";
        }
        int idx = providerPrincipal.indexOf(":oidc-provider/");
        if (idx >= 0) {
            return providerPrincipal.substring(idx + ":oidc-provider/".length());
        }
        return providerPrincipal;
    }

    static Map<String, String> buildOidcConditionClaims(Map<String, Object> claims, String providerHost) {
        Map<String, String> ctx = new LinkedHashMap<>();
        String audClaim = claimAsString(claims.get("aud"));
        String azpClaim = claimAsString(claims.get("azp"));
        String subClaim = claimAsString(claims.get("sub"));
        String amrClaim = claimAsMultiValue(claims.get("amr"));

        String audKeyValue = azpClaim != null && !azpClaim.isBlank() ? azpClaim : audClaim;
        if (audKeyValue != null) {
            ctx.put("aud", audKeyValue);
        }
        if (subClaim != null) {
            ctx.put("sub", subClaim);
        }
        if (amrClaim != null) {
            ctx.put("amr", amrClaim);
        }
        if (providerHost != null && !providerHost.isBlank()) {
            if (audKeyValue != null) {
                ctx.put(providerHost + ":aud", audKeyValue);
            }
            if (subClaim != null) {
                ctx.put(providerHost + ":sub", subClaim);
            }
            if (amrClaim != null) {
                ctx.put(providerHost + ":amr", amrClaim);
            }
            if (azpClaim != null && !azpClaim.isBlank() && audClaim != null) {
                ctx.put(providerHost + ":oaud", audClaim);
            } else if (audClaim != null) {
                ctx.put(providerHost + ":oaud", audClaim);
            }
        }
        return ctx;
    }

    static Map<String, String> extractSamlClaims(String xml, String principalArn) {
        Map<String, String> ctx = new LinkedHashMap<>();
        String issuer = firstXmlValue(xml, "Issuer");
        String subject = firstXmlValue(xml, "NameID");
        String recipient = firstRecipient(xml);
        if (recipient == null || recipient.isBlank()) {
            recipient = firstXmlValue(xml, "Audience");
        }
        if (issuer != null) {
            ctx.put("saml:iss", issuer);
        }
        if (subject != null) {
            ctx.put("saml:sub", subject);
        }
        if (recipient != null) {
            ctx.put("saml:aud", recipient);
        }
        String doc = samlDoc(principalArn);
        if (doc != null) {
            ctx.put("saml:doc", doc);
        }
        return ctx;
    }

    static String samlDoc(String principalArn) {
        if (principalArn == null || !principalArn.contains(":saml-provider/")) {
            return null;
        }
        String account = AwsArnUtils.accountOrDefault(principalArn, "");
        int idx = principalArn.indexOf(":saml-provider/");
        if (account.isBlank() || idx < 0) {
            return null;
        }
        String providerName = principalArn.substring(idx + ":saml-provider/".length());
        return account + "/" + providerName;
    }

    private static String firstXmlValue(String xml, String tagName) {
        Matcher matcher = XML_TAG.matcher(xml);
        while (matcher.find()) {
            if (tagName.equalsIgnoreCase(matcher.group(1))) {
                return matcher.group(2).trim();
            }
        }
        return null;
    }

    private static String firstRecipient(String xml) {
        Matcher matcher = RECIPIENT_ATTR.matcher(xml);
        if (matcher.find()) {
            return matcher.group(1).trim();
        }
        return null;
    }

    private static String claimAsString(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof List<?> list) {
            for (Object item : list) {
                if (item != null) {
                    return item.toString();
                }
            }
            return null;
        }
        return claim.toString();
    }

    private static String claimAsMultiValue(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof List<?> list) {
            List<String> values = new ArrayList<>();
            for (Object item : list) {
                if (item != null) {
                    values.add(item.toString());
                }
            }
            return values.isEmpty() ? null : String.join(",", values);
        }
        return claim.toString();
    }

    private static byte[] decodeBase64Url(String value) {
        String padded = padBase64Url(value);
        return Base64.getUrlDecoder().decode(padded);
    }

    private static String padBase64Url(String value) {
        int mod = value.length() % 4;
        if (mod == 0) {
            return value;
        }
        return value + "=".repeat(4 - mod);
    }
}
