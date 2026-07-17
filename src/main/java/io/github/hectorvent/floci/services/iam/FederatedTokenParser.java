package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import org.jboss.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.X509EncodedKeySpec;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Parses OIDC JWT and SAML assertion payloads for trust-policy condition evaluation.
 * Optional CTF crypto validation is controlled by {@link FederatedTokenValidationConfig}.
 */
public final class FederatedTokenParser {

    private static final Logger LOG = Logger.getLogger(FederatedTokenParser.class);
    private static final TypeReference<Map<String, Object>> CLAIM_MAP_TYPE = new TypeReference<>() {};
    private static final ObjectMapper JWT_MAPPER = new ObjectMapper();
    private static final Set<String> PROVIDER_PREFIX_SKIP_CLAIMS = Set.of("exp", "iat", "nbf");

    private static final Pattern XML_TAG = Pattern.compile(
            "<(?:[\\w]+:)?(Issuer|NameID|Audience|SubjectConfirmationData)(?:\\s[^>]*)?>([^<]*)</(?:[\\w]+:)?\\1>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern RECIPIENT_ATTR = Pattern.compile(
            "Recipient\\s*=\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAML_DIGEST_VALUE = Pattern.compile(
            "<(?:[\\w]+:)?DigestValue[^>]*>([^<]+)</(?:[\\w]+:)?DigestValue>",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAML_NOT_BEFORE = Pattern.compile(
            "NotBefore\\s*=\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAML_NOT_ON_OR_AFTER = Pattern.compile(
            "NotOnOrAfter\\s*=\\s*\"([^\"]+)\"",
            Pattern.CASE_INSENSITIVE);
    private static final Pattern SAML_SIGNATURE_VALUE = Pattern.compile(
            "<(?:[\\w]+:)?SignatureValue[^>]*>([^<]+)</(?:[\\w]+:)?SignatureValue>",
            Pattern.CASE_INSENSITIVE);
    private static final int SAML_SIGNATURE_MIN_BYTES = 64;

    private FederatedTokenParser() {
    }

    public static FederatedTrustContext parseWebIdentityToken(String webIdentityToken,
                                                              String providerId,
                                                              String roleAccountId) {
        return parseWebIdentityToken(webIdentityToken, providerId, roleAccountId,
                FederatedTokenValidationConfig.disabled());
    }

    public static FederatedTrustContext parseWebIdentityToken(String webIdentityToken,
                                                              String providerId,
                                                              String roleAccountId,
                                                              boolean validateFederatedTokens) {
        FederatedTokenValidationConfig config = validateFederatedTokens
                ? new FederatedTokenValidationConfig(
                        true, Optional.empty(), Map.of(), Optional.empty(), Optional.empty(), Map.of())
                : FederatedTokenValidationConfig.disabled();
        return parseWebIdentityToken(webIdentityToken, providerId, roleAccountId, config);
    }

    public static FederatedTrustContext parseWebIdentityToken(String webIdentityToken,
                                                              String providerId,
                                                              String roleAccountId,
                                                              FederatedTokenValidationConfig validationConfig) {
        boolean validateFederatedTokens = validationConfig != null
                && validationConfig.validateFederatedTokens();
        if (validateFederatedTokens && !isStructurallyValidJwt(webIdentityToken)) {
            return null;
        }
        if (validateFederatedTokens && !hasJwtSignaturePart(webIdentityToken)) {
            return null;
        }
        Map<String, Object> claims = parseJwtPayload(webIdentityToken);
        if (claims.isEmpty()) {
            return null;
        }
        if (validateFederatedTokens && isJwtExpired(claims)) {
            return null;
        }
        if (validateFederatedTokens && isJwtNotYetValid(claims)) {
            return null;
        }
        String provider = resolveOidcProviderPrincipal(providerId, roleAccountId);
        String providerHost = oidcProviderHost(provider);
        if (validateFederatedTokens) {
            String iss = claimAsString(claims.get("iss"));
            if (iss != null && !issuerMatchesProvider(iss, providerHost, providerId)) {
                return null;
            }
        }
        if (validateFederatedTokens
                && !verifyJwtCrypto(webIdentityToken, providerHost, validationConfig)) {
            return null;
        }
        Map<String, String> conditionClaims = buildOidcConditionClaims(claims, providerHost);
        return new FederatedTrustContext(provider, conditionClaims);
    }

    public static FederatedTrustContext parseSamlAssertion(String samlAssertionBase64,
                                                           String principalArn) {
        return parseSamlAssertion(samlAssertionBase64, principalArn, FederatedTokenValidationConfig.disabled());
    }

    public static FederatedTrustContext parseSamlAssertion(String samlAssertionBase64,
                                                           String principalArn,
                                                           boolean validateFederatedTokens) {
        FederatedTokenValidationConfig config = validateFederatedTokens
                ? new FederatedTokenValidationConfig(
                        true, Optional.empty(), Map.of(), Optional.empty(), Optional.empty(), Map.of())
                : FederatedTokenValidationConfig.disabled();
        return parseSamlAssertion(samlAssertionBase64, principalArn, config);
    }

    public static FederatedTrustContext parseSamlAssertion(String samlAssertionBase64,
                                                           String principalArn,
                                                           FederatedTokenValidationConfig validationConfig) {
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
        boolean validateFederatedTokens = validationConfig != null
                && validationConfig.validateFederatedTokens();
        if (validateFederatedTokens && !isStructurallyValidSamlAssertion(xml)) {
            return null;
        }
        String claimsXml = xml;
        if (validateFederatedTokens) {
            if (!validateSamlSignatureStructure(xml)) {
                return null;
            }
            Optional<String> signedAssertionXml = bindVerifiedSamlAssertionXml(
                    xml, principalArn, validationConfig);
            if (signedAssertionXml.isEmpty()) {
                return null;
            }
            claimsXml = signedAssertionXml.get();
            if (!isSamlAssertionTimeValid(claimsXml)) {
                return null;
            }
        }
        Map<String, String> samlClaims = extractSamlClaims(claimsXml, principalArn);
        if (samlClaims.isEmpty()) {
            return null;
        }
        return new FederatedTrustContext(principalArn, samlClaims);
    }

    static boolean isStructurallyValidJwt(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return false;
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 2) {
            return false;
        }
        if (parts[0].isBlank() || parts[1].isBlank()) {
            return false;
        }
        try {
            decodeBase64Url(parts[0]);
            decodeBase64Url(parts[1]);
            return true;
        } catch (IllegalArgumentException e) {
            return false;
        }
    }

    static boolean hasJwtSignaturePart(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return false;
        }
        String[] parts = jwt.split("\\.");
        return parts.length == 3 && !parts[2].isBlank();
    }

    static boolean isJwtExpired(Map<String, Object> claims) {
        Object exp = claims.get("exp");
        if (exp == null) {
            return false;
        }
        long expSeconds;
        if (exp instanceof Number number) {
            expSeconds = number.longValue();
        } else {
            try {
                expSeconds = Long.parseLong(exp.toString());
            } catch (NumberFormatException e) {
                return true;
            }
        }
        return Instant.now().getEpochSecond() >= expSeconds;
    }

    static boolean isJwtNotYetValid(Map<String, Object> claims) {
        Object nbf = claims.get("nbf");
        if (nbf == null) {
            return false;
        }
        long nbfSeconds;
        if (nbf instanceof Number number) {
            nbfSeconds = number.longValue();
        } else {
            try {
                nbfSeconds = Long.parseLong(nbf.toString());
            } catch (NumberFormatException e) {
                return true;
            }
        }
        return Instant.now().getEpochSecond() < nbfSeconds;
    }

    static boolean isStructurallyValidSamlAssertion(String xml) {
        if (xml == null || xml.isBlank()) {
            return false;
        }
        String lower = xml.toLowerCase();
        return lower.contains("assertion")
                && (lower.contains("<issuer") || lower.contains(":issuer"));
    }

    static boolean validateSamlSignatureStructure(String xml) {
        if (xml == null || xml.isBlank()) {
            return false;
        }
        String lower = xml.toLowerCase();
        if (!lower.contains("signature")) {
            return false;
        }
        Matcher digestMatcher = SAML_DIGEST_VALUE.matcher(xml);
        if (digestMatcher.find()) {
            String digestValue = normalizeXmlBase64Content(digestMatcher.group(1));
            if (digestValue.isBlank()) {
                return false;
            }
            try {
                byte[] decoded = Base64.getDecoder().decode(digestValue);
                if (decoded.length == 0) {
                    return false;
                }
            } catch (IllegalArgumentException e) {
                return false;
            }
        }
        Matcher sigMatcher = SAML_SIGNATURE_VALUE.matcher(xml);
        if (!sigMatcher.find()) {
            return false;
        }
        String sigValue = normalizeXmlBase64Content(sigMatcher.group(1));
        if (sigValue.isBlank()) {
            return false;
        }
        try {
            byte[] decoded = Base64.getDecoder().decode(sigValue);
            if (decoded.length < SAML_SIGNATURE_MIN_BYTES) {
                return false;
            }
        } catch (IllegalArgumentException e) {
            return false;
        }
        return true;
    }

    static boolean verifyJwtCrypto(String jwt, String providerHost, FederatedTokenValidationConfig config) {
        if (config == null || !config.validateFederatedTokens()) {
            return true;
        }
        String[] parts = jwt.split("\\.");
        if (parts.length != 3) {
            return false;
        }
        Map<String, Object> header = parseJwtHeader(jwt);
        if (header.isEmpty()) {
            return false;
        }
        Object algClaim = header.get("alg");
        if (algClaim == null) {
            return false;
        }
        String alg = algClaim.toString();
        if ("none".equalsIgnoreCase(alg)) {
            return false;
        }
        String signingInput = parts[0] + "." + parts[1];
        byte[] signature;
        try {
            signature = decodeBase64Url(parts[2]);
        } catch (IllegalArgumentException e) {
            return false;
        }
        if ("HS256".equalsIgnoreCase(alg)) {
            return config.resolveHmacSecret(providerHost)
                    .map(secret -> verifyHmacSha256(signingInput, signature, secret))
                    .orElse(false);
        }
        if ("RS256".equalsIgnoreCase(alg)) {
            return config.federatedJwtRs256PublicKeyPem()
                    .filter(pem -> !pem.isBlank())
                    .map(pem -> verifyRs256(signingInput, signature, pem))
                    .orElse(false);
        }
        return false;
    }

    static boolean verifySamlCrypto(String xml, String principalArn, FederatedTokenValidationConfig config) {
        if (config == null || !config.validateFederatedTokens()) {
            return true;
        }
        return bindVerifiedSamlAssertionXml(xml, principalArn, config).isPresent();
    }

    /**
     * Verifies XML-DSig against pinned trust anchors and returns the Assertion XML
     * covered by the verified Signature. Rejects XSW documents with extra Assertions.
     */
    static Optional<String> bindVerifiedSamlAssertionXml(
            String xml, String principalArn, FederatedTokenValidationConfig config) {
        if (config == null || !config.validateFederatedTokens()) {
            return Optional.empty();
        }
        String providerName = samlProviderName(principalArn);
        return SamlAssertionSignatureVerifier
                .verifyAndBindSignedAssertion(xml, config.resolveSamlSigningCertPems(providerName))
                .flatMap(SamlAssertionSignatureVerifier::serializeElement);
    }

    static String samlProviderName(String principalArn) {
        if (principalArn == null || !principalArn.contains(":saml-provider/")) {
            return null;
        }
        int idx = principalArn.indexOf(":saml-provider/");
        return principalArn.substring(idx + ":saml-provider/".length());
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

    static Map<String, Object> parseJwtHeader(String jwt) {
        if (jwt == null || jwt.isBlank()) {
            return Map.of();
        }
        String[] parts = jwt.split("\\.");
        if (parts.length < 1 || parts[0].isBlank()) {
            return Map.of();
        }
        try {
            byte[] header = decodeBase64Url(parts[0]);
            return JWT_MAPPER.readValue(header, CLAIM_MAP_TYPE);
        } catch (Exception e) {
            LOG.debugv("Failed to decode JWT header: {0}", e.getMessage());
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
        String audMultiClaim = claimAsMultiValue(claims.get("aud"));
        String azpClaim = claimAsString(claims.get("azp"));
        String subClaim = claimAsString(claims.get("sub"));
        String amrClaim = claimAsMultiValue(claims.get("amr"));

        String audKeyValue = azpClaim != null && !azpClaim.isBlank() ? azpClaim : audClaim;
        String audPrefixedValue = azpClaim != null && !azpClaim.isBlank() ? azpClaim : audMultiClaim;
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
            for (Map.Entry<String, Object> entry : claims.entrySet()) {
                String claimName = entry.getKey();
                if (PROVIDER_PREFIX_SKIP_CLAIMS.contains(claimName)) {
                    continue;
                }
                String value = scalarClaimAsString(entry.getValue());
                if (value != null) {
                    ctx.put(providerHost + ":" + claimName, value);
                }
            }
            if (audPrefixedValue != null) {
                ctx.put(providerHost + ":aud", audPrefixedValue);
            }
            if (audClaim != null) {
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

    private static boolean verifyHmacSha256(String signingInput, byte[] signature, String secret) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(secret.getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
            byte[] expected = mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8));
            return constantTimeEquals(expected, signature);
        } catch (Exception e) {
            LOG.debugv("HS256 verification failed: {0}", e.getMessage());
            return false;
        }
    }

    private static boolean verifyRs256(String signingInput, byte[] signature, String pem) {
        try {
            PublicKey publicKey = parseRs256PublicKey(pem);
            Signature verifier = Signature.getInstance("SHA256withRSA");
            verifier.initVerify(publicKey);
            verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(signature);
        } catch (Exception e) {
            LOG.debugv("RS256 verification failed: {0}", e.getMessage());
            return false;
        }
    }

    private static PublicKey parseRs256PublicKey(String pem) throws Exception {
        String normalized = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = Base64.getDecoder().decode(normalized);
        return KeyFactory.getInstance("RSA").generatePublic(new X509EncodedKeySpec(decoded));
    }

    private static boolean constantTimeEquals(byte[] left, byte[] right) {
        if (left.length != right.length) {
            return false;
        }
        int result = 0;
        for (int i = 0; i < left.length; i++) {
            result |= left[i] ^ right[i];
        }
        return result == 0;
    }

    private static String normalizeXmlBase64Content(String value) {
        if (value == null) {
            return "";
        }
        return value
                .replaceAll("\\s", "")
                .replace("&#13;", "")
                .replace("&#10;", "")
                .replace("&#9;", "");
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

    private static String scalarClaimAsString(Object claim) {
        if (claim == null) {
            return null;
        }
        if (claim instanceof Map<?, ?>) {
            return null;
        }
        if (claim instanceof List<?> list) {
            return claimAsMultiValue(list);
        }
        return claim.toString();
    }

    static String sanitizeSessionName(String candidate, String fallback) {
        String raw = candidate != null && !candidate.isBlank() ? candidate : fallback;
        if (raw == null || raw.isBlank()) {
            return "federated-session";
        }
        String sanitized = raw.replaceAll("[^a-zA-Z0-9+=,.@-]", "-");
        if (sanitized.length() > 64) {
            sanitized = sanitized.substring(0, 64);
        }
        return sanitized.isBlank() ? "federated-session" : sanitized;
    }

    static boolean issuerMatchesProvider(String iss, String providerHost, String providerId) {
        if (iss == null || iss.isBlank()) {
            return false;
        }
        String host = providerHost == null ? "" : providerHost.trim();
        if (host.isBlank() && providerId != null && !providerId.isBlank()) {
            host = providerId.contains(":oidc-provider/")
                    ? providerId.substring(providerId.indexOf(":oidc-provider/") + ":oidc-provider/".length())
                    : providerId.trim();
        }
        if (host.isBlank()) {
            return true;
        }
        String normalizedIss = iss.trim();
        if (normalizedIss.equals(host) || normalizedIss.equals("https://" + host) || normalizedIss.equals("http://" + host)) {
            return true;
        }
        return normalizedIss.endsWith("/" + host) || normalizedIss.contains("://" + host);
    }

    static boolean isSamlAssertionTimeValid(String xml) {
        Instant now = Instant.now();
        Instant notBefore = firstSamlInstant(xml, SAML_NOT_BEFORE);
        if (notBefore != null && now.isBefore(notBefore)) {
            return false;
        }
        Instant notOnOrAfter = firstSamlInstant(xml, SAML_NOT_ON_OR_AFTER);
        if (notOnOrAfter != null && !now.isBefore(notOnOrAfter)) {
            return false;
        }
        return true;
    }

    private static Instant firstSamlInstant(String xml, Pattern pattern) {
        Matcher matcher = pattern.matcher(xml);
        while (matcher.find()) {
            Instant parsed = parseSamlInstant(matcher.group(1).trim());
            if (parsed != null) {
                return parsed;
            }
        }
        return null;
    }

    private static Instant parseSamlInstant(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (Exception ignored) {
            // SAML often uses offset datetime without Z
        }
        try {
            return java.time.OffsetDateTime.parse(value).toInstant();
        } catch (Exception e) {
            return null;
        }
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
