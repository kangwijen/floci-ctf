package io.github.hectorvent.floci.core.common;

import org.bouncycastle.asn1.ASN1EncodableVector;
import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERSequence;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Locale;
import java.util.Map;

/**
 * SigV4a (AWS4-ECDSA-P256-SHA256) presigned URL/POST signature helpers.
 * Signatures use IEEE P1363 fixed-width R||S (64 bytes for P-256), hex-encoded in {@code X-Amz-Signature}.
 */
public final class SigV4aPresignSupport {

    public static final String ALGORITHM = "AWS4-ECDSA-P256-SHA256";

    private SigV4aPresignSupport() {
    }

    public static String buildPresignedUrlStringToSign(String method,
                                                       String rawPath,
                                                       String rawQuery,
                                                       String hostHeader,
                                                       String amzDate,
                                                       String signedHeadersList,
                                                       String credentialScope,
                                                       Map<String, String> requestHeaders) throws Exception {
        String canonicalRequest = SigV4RequestValidator.buildPresignedCanonicalRequestPublic(
                method, rawPath, rawQuery, hostHeader, signedHeadersList, requestHeaders);
        return ALGORITHM + "\n"
                + amzDate + "\n"
                + credentialScope + "\n"
                + SigV4RequestValidator.sha256Hex(canonicalRequest);
    }

    public static String buildPresignedPostStringToSign(String policyBase64) throws Exception {
        return SigV4RequestValidator.sha256Hex(policyBase64);
    }

    public static String signStringToSign(String stringToSign, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA256withECDSA");
        signature.initSign(privateKey);
        signature.update(stringToSign.getBytes(StandardCharsets.UTF_8));
        return SigV4RequestValidator.hexEncode(derSignatureToConcatRs(signature.sign()));
    }

    public static boolean verifyStringToSign(String stringToSign,
                                             String providedSignatureHex,
                                             PublicKey publicKey) {
        if (stringToSign == null || providedSignatureHex == null || publicKey == null) {
            return false;
        }
        try {
            byte[] provided = SigV4RequestValidator.hexDecode(providedSignatureHex.toLowerCase(Locale.ROOT));
            if (provided == null) {
                return false;
            }
            byte[] der = concatRsToDerSignature(provided);
            Signature verifier = Signature.getInstance("SHA256withECDSA");
            verifier.initVerify(publicKey);
            verifier.update(stringToSign.getBytes(StandardCharsets.UTF_8));
            return verifier.verify(der);
        } catch (Exception e) {
            return false;
        }
    }

    public static PublicKey parseEcPublicKeyPem(String pem) throws Exception {
        if (pem == null || pem.isBlank()) {
            throw new IllegalArgumentException("Missing EC public key PEM");
        }
        String normalized = pem
                .replace("-----BEGIN PUBLIC KEY-----", "")
                .replace("-----END PUBLIC KEY-----", "")
                .replace("-----BEGIN CERTIFICATE-----", "")
                .replace("-----END CERTIFICATE-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = java.util.Base64.getDecoder().decode(normalized);
        if (pem.contains("CERTIFICATE")) {
            java.security.cert.CertificateFactory factory =
                    java.security.cert.CertificateFactory.getInstance("X.509");
            java.security.cert.X509Certificate cert =
                    (java.security.cert.X509Certificate) factory.generateCertificate(
                            new java.io.ByteArrayInputStream(decoded));
            return cert.getPublicKey();
        }
        return KeyFactory.getInstance("EC").generatePublic(new X509EncodedKeySpec(decoded));
    }

    public static PrivateKey parseEcPrivateKeyPem(String pem) throws Exception {
        String normalized = pem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] decoded = java.util.Base64.getDecoder().decode(normalized);
        return KeyFactory.getInstance("EC").generatePrivate(new PKCS8EncodedKeySpec(decoded));
    }

    static byte[] derSignatureToConcatRs(byte[] derSignature) throws Exception {
        ASN1Sequence sequence = ASN1Sequence.getInstance(derSignature);
        BigInteger r = ASN1Integer.getInstance(sequence.getObjectAt(0)).getPositiveValue();
        BigInteger s = ASN1Integer.getInstance(sequence.getObjectAt(1)).getPositiveValue();
        byte[] rBytes = toFixed32(r);
        byte[] sBytes = toFixed32(s);
        byte[] out = new byte[64];
        System.arraycopy(rBytes, 0, out, 0, 32);
        System.arraycopy(sBytes, 0, out, 32, 32);
        return out;
    }

    static byte[] concatRsToDerSignature(byte[] concatRs) throws Exception {
        if (concatRs.length != 64) {
            throw new IllegalArgumentException("Expected 64-byte P-256 signature");
        }
        BigInteger r = new BigInteger(1, java.util.Arrays.copyOfRange(concatRs, 0, 32));
        BigInteger s = new BigInteger(1, java.util.Arrays.copyOfRange(concatRs, 32, 64));
        ASN1EncodableVector vector = new ASN1EncodableVector();
        vector.add(new ASN1Integer(r));
        vector.add(new ASN1Integer(s));
        return new DERSequence(vector).getEncoded();
    }

    private static byte[] toFixed32(BigInteger value) {
        byte[] raw = value.toByteArray();
        if (raw.length == 32) {
            return raw;
        }
        if (raw.length == 33 && raw[0] == 0) {
            return java.util.Arrays.copyOfRange(raw, 1, 33);
        }
        byte[] out = new byte[32];
        int copyLen = Math.min(32, raw.length);
        System.arraycopy(raw, raw.length - copyLen, out, 32 - copyLen, copyLen);
        return out;
    }
}
