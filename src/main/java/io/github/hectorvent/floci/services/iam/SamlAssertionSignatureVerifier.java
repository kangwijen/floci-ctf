package io.github.hectorvent.floci.services.iam;

import org.apache.xml.security.Init;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.signature.Reference;
import org.apache.xml.security.signature.XMLSignature;
import org.jboss.logging.Logger;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.ByteArrayInputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.List;
import java.util.Optional;

/**
 * Validates SAML assertion XML signatures using Apache Santuario and pinned trust anchors.
 * Claims must be taken only from the DOM node covered by a verified Signature.
 */
public final class SamlAssertionSignatureVerifier {

    private static final Logger LOG = Logger.getLogger(SamlAssertionSignatureVerifier.class);
    private static final String XMLDSIG_NS = "http://www.w3.org/2000/09/xmldsig#";
    private static final String SAML_ASSERTION_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static volatile boolean initialized;

    private SamlAssertionSignatureVerifier() {
    }

    public static boolean verify(String xml, List<String> trustedCertPems) {
        return verifyAndBindSignedAssertion(xml, trustedCertPems).isPresent();
    }

    /**
     * Verifies an enveloped (or ID-referenced) XML signature against pinned trust anchors
     * and returns the Assertion element covered by that signature.
     * Rejects documents that also contain an Assertion outside the signed subtree (XSW).
     */
    public static Optional<Element> verifyAndBindSignedAssertion(String xml, List<String> trustedCertPems) {
        if (xml == null || xml.isBlank()) {
            return Optional.empty();
        }
        if (trustedCertPems == null || trustedCertPems.isEmpty()) {
            return Optional.empty();
        }
        List<X509Certificate> trustedCerts = parseTrustedCertificates(trustedCertPems);
        if (trustedCerts.isEmpty()) {
            return Optional.empty();
        }
        List<PublicKey> trustedKeys = trustedCerts.stream().map(X509Certificate::getPublicKey).toList();
        ensureInit();
        try {
            Document document = parseDocument(xml);
            NodeList signatures = document.getElementsByTagNameNS(XMLDSIG_NS, "Signature");
            if (signatures.getLength() == 0) {
                signatures = document.getElementsByTagName("Signature");
            }
            for (int i = 0; i < signatures.getLength(); i++) {
                Element signatureElement = (Element) signatures.item(i);
                Optional<Element> bound = verifySignatureAndBind(document, signatureElement, trustedCerts, trustedKeys);
                if (bound.isPresent()) {
                    return bound;
                }
            }
            return Optional.empty();
        } catch (Exception e) {
            LOG.debugv("SAML XML signature verification failed: {0}", e.getMessage());
            return Optional.empty();
        }
    }

    public static Optional<String> serializeElement(Element element) {
        if (element == null) {
            return Optional.empty();
        }
        try {
            TransformerFactory transformerFactory = TransformerFactory.newInstance();
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
            transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
            Transformer transformer = transformerFactory.newTransformer();
            transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
            StringWriter writer = new StringWriter();
            transformer.transform(new DOMSource(element), new StreamResult(writer));
            return Optional.of(writer.toString().replace("\r\n", "\n"));
        } catch (Exception e) {
            LOG.debugv("Failed to serialize signed SAML element: {0}", e.getMessage());
            return Optional.empty();
        }
    }

    private static Optional<Element> verifySignatureAndBind(
            Document document,
            Element signatureElement,
            List<X509Certificate> trustedCerts,
            List<PublicKey> trustedKeys) {
        try {
            XMLSignature signature = new XMLSignature(signatureElement, "");
            X509Certificate signingCert = extractSigningCertificate(signature);
            PublicKey signingKey = signingCert != null
                    ? signingCert.getPublicKey()
                    : extractSigningPublicKey(signature);
            if (signingKey == null) {
                return Optional.empty();
            }
            if (!matchesTrustedCertificate(signingCert, signingKey, trustedCerts, trustedKeys)) {
                return Optional.empty();
            }
            if (!signature.checkSignatureValue(signingKey)) {
                return Optional.empty();
            }
            Element signedElement = resolveSignedElement(document, signature);
            if (signedElement == null) {
                return Optional.empty();
            }
            Element signedAssertion = resolveAssertionElement(signedElement);
            if (signedAssertion == null) {
                return Optional.empty();
            }
            if (hasUnsignedSiblingAssertion(document, signedAssertion)) {
                LOG.debug("Rejecting SAML document with Assertion outside verified Signature coverage");
                return Optional.empty();
            }
            return Optional.of(signedAssertion);
        } catch (Exception e) {
            LOG.debugv("SAML signature candidate rejected: {0}", e.getMessage());
            return Optional.empty();
        }
    }

    private static Element resolveSignedElement(Document document, XMLSignature signature) throws Exception {
        if (signature.getSignedInfo() == null || signature.getSignedInfo().getLength() == 0) {
            return null;
        }
        Reference reference = signature.getSignedInfo().item(0);
        String uri = reference.getURI();
        if (uri == null || uri.isBlank()) {
            Element signatureElement = signature.getElement();
            Node parent = signatureElement.getParentNode();
            return parent instanceof Element element ? element : null;
        }
        if (uri.startsWith("#")) {
            String id = uri.substring(1);
            if (id.startsWith("xpointer(id('") && id.endsWith("'))")) {
                id = id.substring("xpointer(id('".length(), id.length() - "'))".length());
            }
            Element byId = document.getElementById(id);
            if (byId != null) {
                return byId;
            }
        }
        Element signatureElement = signature.getElement();
        Node parent = signatureElement.getParentNode();
        return parent instanceof Element element ? element : null;
    }

    private static Element resolveAssertionElement(Element signedElement) {
        if (isAssertionElement(signedElement)) {
            return signedElement;
        }
        NodeList nested = signedElement.getElementsByTagNameNS(SAML_ASSERTION_NS, "Assertion");
        if (nested.getLength() == 0) {
            nested = signedElement.getElementsByTagName("Assertion");
        }
        if (nested.getLength() != 1) {
            return null;
        }
        return (Element) nested.item(0);
    }

    private static boolean hasUnsignedSiblingAssertion(Document document, Element signedAssertion) {
        List<Element> assertions = collectAssertionElements(document);
        for (Element assertion : assertions) {
            if (assertion == signedAssertion) {
                continue;
            }
            if (!isDescendantOrSelf(signedAssertion, assertion)) {
                return true;
            }
        }
        return false;
    }

    private static List<Element> collectAssertionElements(Document document) {
        List<Element> assertions = new ArrayList<>();
        NodeList nested = document.getElementsByTagNameNS(SAML_ASSERTION_NS, "Assertion");
        for (int i = 0; i < nested.getLength(); i++) {
            assertions.add((Element) nested.item(i));
        }
        if (assertions.isEmpty()) {
            NodeList unprefixed = document.getElementsByTagName("Assertion");
            for (int i = 0; i < unprefixed.getLength(); i++) {
                assertions.add((Element) unprefixed.item(i));
            }
        }
        return assertions;
    }

    private static boolean isAssertionElement(Element element) {
        if (element == null) {
            return false;
        }
        String localName = element.getLocalName() != null ? element.getLocalName() : element.getTagName();
        if (!"Assertion".equals(localName) && !localName.endsWith(":Assertion")) {
            return false;
        }
        String ns = element.getNamespaceURI();
        return ns == null || ns.isBlank() || SAML_ASSERTION_NS.equals(ns);
    }

    private static boolean isDescendantOrSelf(Element ancestor, Element node) {
        Node current = node;
        while (current != null) {
            if (current == ancestor) {
                return true;
            }
            current = current.getParentNode();
        }
        return false;
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
