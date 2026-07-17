package io.github.hectorvent.floci.services.apigatewayv2;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.OutboundUrlGuard;
import io.github.hectorvent.floci.core.common.PinnedHttpResponse;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.math.BigInteger;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Verifies signed JWTs used by HTTP API JWT authorizers before their claims are trusted.
 */
@ApplicationScoped
public class JwtAuthorizerVerifier {

    private static final Logger LOG = Logger.getLogger(JwtAuthorizerVerifier.class);
    private static final TypeReference<Map<String, Object>> MAP_TYPE = new TypeReference<>() {};
    private static final Duration HTTP_TIMEOUT = Duration.ofSeconds(5);

    private final EmulatorConfig config;
    private final ObjectMapper objectMapper;
    private final OutboundUrlGuard outboundUrlGuard;

    @Inject
    public JwtAuthorizerVerifier(EmulatorConfig config, ObjectMapper objectMapper, OutboundUrlGuard outboundUrlGuard) {
        this.config = config;
        this.objectMapper = objectMapper;
        this.outboundUrlGuard = outboundUrlGuard;
    }

    public boolean verify(String token, String issuer) {
        String[] parts = token == null ? new String[0] : token.split("\\.", -1);
        if (parts.length != 3 || parts[0].isBlank() || parts[1].isBlank() || parts[2].isBlank()) {
            return false;
        }
        try {
            Map<String, Object> header = parseJson(parts[0]);
            String algorithm = stringValue(header.get("alg"));
            if (algorithm == null || algorithm.isBlank() || "none".equalsIgnoreCase(algorithm)) {
                return false;
            }
            byte[] signature = decodeBase64Url(parts[2]);
            String signingInput = parts[0] + "." + parts[1];
            return switch (algorithm) {
                case "HS256" -> verifyHs256(signingInput, signature);
                case "RS256", "ES256" -> verifyAsymmetric(algorithm, header, signingInput, signature, issuer);
                default -> false;
            };
        } catch (Exception e) {
            LOG.debugv("JWT signature verification failed: {0}", e.getMessage());
            return false;
        }
    }

    private boolean verifyHs256(String signingInput, byte[] signature) throws Exception {
        Optional<String> secret = config.ctf().apiGatewayJwtHmacSecret().filter(value -> !value.isBlank());
        if (secret.isEmpty()) {
            return false;
        }
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(secret.get().getBytes(StandardCharsets.UTF_8), "HmacSHA256"));
        return MessageDigest.isEqual(mac.doFinal(signingInput.getBytes(StandardCharsets.UTF_8)), signature);
    }

    private boolean verifyAsymmetric(String algorithm, Map<String, Object> header, String signingInput,
                                    byte[] signature, String issuer) throws Exception {
        if (issuer == null || issuer.isBlank()) {
            return false;
        }
        String keyId = stringValue(header.get("kid"));
        if (keyId == null || keyId.isBlank()) {
            return false;
        }
        Map<String, Object> jwk = fetchJwks(issuer).stream()
                .filter(candidate -> keyId.equals(stringValue(candidate.get("kid"))))
                .findFirst()
                .orElse(null);
        if (jwk == null || !algorithm.equals(stringValue(jwk.get("alg")))) {
            return false;
        }
        PublicKey publicKey = "RS256".equals(algorithm) ? rsaPublicKey(jwk) : ecPublicKey(jwk);
        Signature verifier = Signature.getInstance("RS256".equals(algorithm) ? "SHA256withRSA" : "SHA256withECDSA");
        verifier.initVerify(publicKey);
        verifier.update(signingInput.getBytes(StandardCharsets.UTF_8));
        return verifier.verify("ES256".equals(algorithm) ? joseToDerEcdsa(signature) : signature);
    }

    private List<Map<String, Object>> fetchJwks(String issuer) throws Exception {
        String normalizedIssuer = issuer.endsWith("/") ? issuer.substring(0, issuer.length() - 1) : issuer;
        try {
            return readJwks(URI.create(normalizedIssuer + "/.well-known/jwks.json"));
        } catch (Exception jwksFailure) {
            Map<String, Object> discovery = readJson(URI.create(normalizedIssuer + "/.well-known/openid-configuration"));
            String jwksUri = stringValue(discovery.get("jwks_uri"));
            if (jwksUri == null || jwksUri.isBlank()) {
                throw jwksFailure;
            }
            return readJwks(URI.create(jwksUri));
        }
    }

    private List<Map<String, Object>> readJwks(URI uri) throws Exception {
        Object keys = readJson(uri).get("keys");
        if (!(keys instanceof List<?> list)) {
            throw new IllegalArgumentException("JWKS response has no keys array");
        }
        return list.stream()
                .filter(Map.class::isInstance)
                .map(value -> (Map<String, Object>) value)
                .toList();
    }

    private Map<String, Object> readJson(URI uri) throws Exception {
        PinnedHttpResponse response = outboundUrlGuard.sendPinned(
                uri.toString(),
                "GET",
                null,
                Map.of(),
                HTTP_TIMEOUT,
                HTTP_TIMEOUT);
        if (response.statusCode() != 200) {
            throw new IllegalArgumentException("JWKS endpoint returned HTTP " + response.statusCode());
        }
        String body = response.body() == null
                ? ""
                : new String(response.body(), StandardCharsets.UTF_8);
        return objectMapper.readValue(body, MAP_TYPE);
    }

    private Map<String, Object> parseJson(String encoded) throws Exception {
        return objectMapper.readValue(decodeBase64Url(encoded), MAP_TYPE);
    }

    private static PublicKey rsaPublicKey(Map<String, Object> jwk) throws Exception {
        if (!"RSA".equals(stringValue(jwk.get("kty")))) {
            throw new IllegalArgumentException("JWT key type is not RSA");
        }
        BigInteger modulus = new BigInteger(1, decodeBase64Url(requiredString(jwk, "n")));
        BigInteger exponent = new BigInteger(1, decodeBase64Url(requiredString(jwk, "e")));
        return KeyFactory.getInstance("RSA").generatePublic(new RSAPublicKeySpec(modulus, exponent));
    }

    private static PublicKey ecPublicKey(Map<String, Object> jwk) throws Exception {
        if (!"EC".equals(stringValue(jwk.get("kty"))) || !"P-256".equals(stringValue(jwk.get("crv")))) {
            throw new IllegalArgumentException("JWT key is not P-256 EC");
        }
        AlgorithmParameters parameters = AlgorithmParameters.getInstance("EC");
        parameters.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = parameters.getParameterSpec(ECParameterSpec.class);
        ECPoint point = new ECPoint(
                new BigInteger(1, decodeBase64Url(requiredString(jwk, "x"))),
                new BigInteger(1, decodeBase64Url(requiredString(jwk, "y"))));
        return KeyFactory.getInstance("EC").generatePublic(new ECPublicKeySpec(point, spec));
    }

    private static byte[] joseToDerEcdsa(byte[] joseSignature) {
        if (joseSignature.length != 64) {
            throw new IllegalArgumentException("Invalid ES256 signature length");
        }
        byte[] r = derInteger(joseSignature, 0, 32);
        byte[] s = derInteger(joseSignature, 32, 32);
        byte[] result = new byte[2 + r.length + s.length];
        result[0] = 0x30;
        result[1] = (byte) (r.length + s.length);
        System.arraycopy(r, 0, result, 2, r.length);
        System.arraycopy(s, 0, result, 2 + r.length, s.length);
        return result;
    }

    private static byte[] derInteger(byte[] value, int offset, int length) {
        int first = offset;
        while (first < offset + length - 1 && value[first] == 0) {
            first++;
        }
        boolean needsLeadingZero = (value[first] & 0x80) != 0;
        int dataLength = offset + length - first;
        byte[] result = new byte[2 + dataLength + (needsLeadingZero ? 1 : 0)];
        result[0] = 0x02;
        result[1] = (byte) (dataLength + (needsLeadingZero ? 1 : 0));
        System.arraycopy(value, first, result, 2 + (needsLeadingZero ? 1 : 0), dataLength);
        return result;
    }

    private static String requiredString(Map<String, Object> values, String key) {
        String value = stringValue(values.get(key));
        if (value == null || value.isBlank()) {
            throw new IllegalArgumentException("JWT key parameter is missing: " + key);
        }
        return value;
    }

    private static String stringValue(Object value) {
        return value == null ? null : value.toString();
    }

    private static byte[] decodeBase64Url(String value) {
        int remainder = value.length() % 4;
        String padded = remainder == 0 ? value : value + "=".repeat(4 - remainder);
        return Base64.getUrlDecoder().decode(padded);
    }
}
