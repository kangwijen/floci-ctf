package io.github.hectorvent.floci.services.iam;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.XMLSignature;
import org.jboss.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;

/**
 * Validates SAML assertion XML signatures using Apache Santuario and pinned trust anchors.
 */
public final class SamlAssertionSignatureVerifier {

    private static final Logger LOG = Logger.getLogger(SamlAssertionSignatureVerifier.class);
    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static volatile boolean initialized;

    private SamlAssertionSignatureVerifier() {
    }

    public static boolean verify(String xml, List<String> trustedCertPems) {
        if (xml == null || xml.isBlank()) {
            return false;
        }
        if (trustedCertPems == null || trustedCertPems.isEmpty()) {
            return false;
        }
        List<X509Certificate> trustedCerts = parseTrustedCertificates(trustedCertPems);
        if (trustedCerts.isEmpty()) {
            return false;
        }
        List<PublicKey> trustedKeys = trustedCerts.stream().map(X509Certificate::getPublicKey).toList();
        ensureInit();
        try {
            Document document = parseDocument(xml);
            Element signatureElement = findSignatureElement(document);
            if (signatureElement == null) {
                return false;
            }
            XMLSignature signature = new XMLSignature(signatureElement, "");
            X509Certificate signingCert = extractSigningCertificate(signature);
            PublicKey signingKey = signingCert != null
                    ? signingCert.getPublicKey()
                    : extractSigningPublicKey(signature);
            if (signingKey == null) {
                return false;
            }
            if (!matchesTrustedCertificate(signingCert, signingKey, trustedCerts, trustedKeys)) {
                return false;
            }
            return signature.checkSignatureValue(signingKey);
        } catch (Exception e) {
            LOG.debugv("SAML XML signature verification failed: {0}", e.getMessage());
            return false;
        }
    }

    private static void ensureInit() {
        if (!initialized) {
            synchronized (SamlAssertionSignatureVerifier.class) {
                if (!initialized) {
                    Init.init();
                    initialized = true;
                }
            }
        }
    }

    private static Document parseDocument(String xml) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        factory.setExpandEntityReferences(false);
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
        factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        Document document = factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
        registerIdAttributes(document);
        return document;
    }

    private static void registerIdAttributes(Document document) {
        registerIdAttributes(document.getDocumentElement());
    }

    private static void registerIdAttributes(Element element) {
        if (element.hasAttribute("ID")) {
            element.setIdAttribute("ID", true);
        }
        if (element.hasAttribute("Id")) {
            element.setIdAttribute("Id", true);
        }
        var children = element.getChildNodes();
        for (int i = 0; i < children.getLength(); i++) {
            if (children.item(i) instanceof Element child) {
                registerIdAttributes(child);
            }
        }
    }

    private static Element findSignatureElement(Document document) {
        NodeList signatures = document.getElementsByTagNameNS(XMLDSIG_NS, "Signature");
        if (signatures.getLength() == 0) {
            signatures = document.getElementsByTagName("Signature");
        }
        if (signatures.getLength() == 0) {
            return null;
        }
        return (Element) signatures.item(0);
    }

    private static X509Certificate extractSigningCertificate(XMLSignature signature) {
        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            return null;
        }
        try {
            return keyInfo.getX509Certificate();
        } catch (Exception e) {
            LOG.debugv("Failed to read X509Certificate from SAML KeyInfo: {0}", e.getMessage());
            return null;
        }
    }

    private static PublicKey extractSigningPublicKey(XMLSignature signature) {
        KeyInfo keyInfo = signature.getKeyInfo();
        if (keyInfo == null) {
            return null;
        }
        try {
            X509Certificate certificate = keyInfo.getX509Certificate();
            if (certificate != null) {
                return certificate.getPublicKey();
            }
        } catch (Exception e) {
            LOG.debugv("Failed to read X509Certificate from SAML KeyInfo: {0}", e.getMessage());
        }
        try {
            return keyInfo.getPublicKey();
        } catch (Exception e) {
            LOG.debugv("Failed to read public key from SAML KeyInfo: {0}", e.getMessage());
            return null;
        }
    }

    private static List<X509Certificate> parseTrustedCertificates(List<String> trustedCertPems) {
        List<X509Certificate> certificates = new ArrayList<>();
        for (String pem : trustedCertPems) {
            if (pem == null || pem.isBlank()) {
                continue;
            }
            try {
                certificates.add(parseCertificateFromPem(pem));
            } catch (Exception e) {
                LOG.debugv("Skipping invalid SAML trust anchor PEM: {0}", e.getMessage());
            }
        }
        return certificates;
    }

    private static X509Certificate parseCertificateFromPem(String pem) throws Exception {
        String normalized = pem.trim();
        if (normalized.contains("BEGIN CERTIFICATE")) {
            String encoded = normalized
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");
            byte[] decoded = Base64.getDecoder().decode(encoded);
            CertificateFactory factory = CertificateFactory.getInstance("X.509");
            return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
        }
        throw new IllegalArgumentException("SAML trust anchor must be an X.509 certificate PEM");
    }

    private static boolean matchesTrustedCertificate(
            X509Certificate signingCert,
            PublicKey signingKey,
            List<X509Certificate> trustedCerts,
            List<PublicKey> trustedKeys) {
        if (signingCert != null) {
            byte[] signingDer;
            try {
                signingDer = signingCert.getEncoded();
            } catch (Exception e) {
                LOG.debugv("Failed to encode SAML signing certificate: {0}", e.getMessage());
                signingDer = null;
            }
            if (signingDer != null) {
                for (X509Certificate trusted : trustedCerts) {
                    try {
                        if (Arrays.equals(signingDer, trusted.getEncoded())) {
                            return true;
                        }
                    } catch (Exception e) {
                        LOG.debugv("Failed to encode trusted SAML certificate: {0}", e.getMessage());
                    }
                }
            }
        }
        for (PublicKey trusted : trustedKeys) {
            if (publicKeysEquivalent(signingKey, trusted)) {
                return true;
            }
        }
        return false;
    }

    private static boolean publicKeysEquivalent(PublicKey left, PublicKey right) {
        if (left == null || right == null) {
            return false;
        }
        if (left.equals(right)) {
            return true;
        }
        if (!left.getAlgorithm().equalsIgnoreCase(right.getAlgorithm())) {
            return false;
        }
        if (left instanceof RSAPublicKey leftRsa && right instanceof RSAPublicKey rightRsa) {
            return leftRsa.getModulus().equals(rightRsa.getModulus())
                    && leftRsa.getPublicExponent().equals(rightRsa.getPublicExponent());
        }
        return Arrays.equals(left.getEncoded(), right.getEncoded());
    }
}
