package io.github.hectorvent.floci.services.iam;

import org.apache.xml.security.Init;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.transforms.Transforms;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.InputSource;

import javax.xml.XMLConstants;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.InputStream;
import java.io.StringReader;
import java.io.StringWriter;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Base64;
import java.util.Date;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

/**
 * Builds signed SAML assertion XML for federated token validation tests.
 */
final class SamlAssertionTestSupport {

    private static volatile boolean initialized;

    private SamlAssertionTestSupport() {
    }

    record SigningMaterial(KeyPair keyPair, X509Certificate certificate, String certificatePem) {

        String privateKeyPem() throws Exception {
            String encoded = Base64.getMimeEncoder(64, "\n".getBytes())
                    .encodeToString(keyPair.getPrivate().getEncoded());
            return "-----BEGIN PRIVATE KEY-----\n" + encoded + "\n-----END PRIVATE KEY-----";
        }

        String singleLineTrustAnchorPem() {
            return "-----BEGIN PUBLIC KEY-----"
                    + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())
                    + "-----END PUBLIC KEY-----";
        }
    }

    static SigningMaterial generateSigningMaterial() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair keyPair = keyGen.generateKeyPair();
        Instant now = Instant.now();
        X500Name issuer = new X500Name("CN=SAML Test IdP");
        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                issuer,
                BigInteger.valueOf(now.toEpochMilli()),
                Date.from(now.minus(1, ChronoUnit.DAYS)),
                Date.from(now.plus(365, ChronoUnit.DAYS)),
                issuer,
                keyPair.getPublic());
        X509Certificate certificate = new JcaX509CertificateConverter()
                .getCertificate(builder.build(new JcaContentSignerBuilder("SHA256withRSA")
                        .build(keyPair.getPrivate())));
        String pem = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes()).encodeToString(certificate.getEncoded())
                + "\n-----END CERTIFICATE-----";
        return new SigningMaterial(keyPair, certificate, pem);
    }

    static SigningMaterial loadClasspathSigningMaterial() throws Exception {
        String certPem = readClasspathResource("/saml/idp-signing-cert.pem");
        String keyPem = readClasspathResource("/saml/idp-signing-key.pem");
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(
                new java.io.ByteArrayInputStream(certPem.getBytes(StandardCharsets.UTF_8)));
        String encodedKey = keyPem
                .replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replace("-----BEGIN RSA PRIVATE KEY-----", "")
                .replace("-----END RSA PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        PrivateKey privateKey = KeyFactory.getInstance("RSA")
                .generatePrivate(new PKCS8EncodedKeySpec(Base64.getDecoder().decode(encodedKey)));
        KeyPair keyPair = new KeyPair(certificate.getPublicKey(), privateKey);
        return new SigningMaterial(keyPair, certificate, certPem);
    }

    private static String readClasspathResource(String path) throws Exception {
        try (InputStream input = SamlAssertionTestSupport.class.getResourceAsStream(path)) {
            if (input == null) {
                throw new IllegalStateException("Missing classpath resource: " + path);
            }
            return new String(input.readAllBytes(), StandardCharsets.UTF_8);
        }
    }

    static String baseAssertionXml(String subject) {
        Instant notBefore = Instant.now().minusSeconds(60);
        Instant notOnOrAfter = Instant.now().plusSeconds(3600);
        return """
                <saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" \
                ID="_assertion-id" IssueInstant="%s" Version="2.0">
                  <saml:Issuer>https://idp.example.com</saml:Issuer>
                  <saml:Subject>
                    <saml:NameID>%s</saml:NameID>
                    <saml:SubjectConfirmation>
                      <saml:SubjectConfirmationData Recipient="https://sts.amazonaws.com"/>
                    </saml:SubjectConfirmation>
                  </saml:Subject>
                  <saml:Conditions NotBefore="%s" NotOnOrAfter="%s"/>
                </saml:Assertion>""".formatted(
                Instant.now().toString(), subject, notBefore.toString(), notOnOrAfter.toString());
    }

    static String signAssertion(String xml, X509Certificate certificate, PrivateKey privateKey) throws Exception {
        ensureInit();
        Document document = parseDocument(xml);
        Element root = document.getDocumentElement();
        if (root.hasAttribute("ID")) {
            root.setIdAttribute("ID", true);
        } else {
            throw new IllegalArgumentException("SAML assertion must have an ID attribute for enveloped signing");
        }
        XMLSignature signature = new XMLSignature(
                document,
                "",
                XMLSignature.ALGO_ID_SIGNATURE_RSA_SHA256,
                Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        root.appendChild(signature.getElement());
        Transforms transforms = new Transforms(document);
        transforms.addTransform(Transforms.TRANSFORM_ENVELOPED_SIGNATURE);
        transforms.addTransform(Transforms.TRANSFORM_C14N_EXCL_OMIT_COMMENTS);
        signature.addDocument("#" + root.getAttribute("ID"), transforms, "http://www.w3.org/2001/04/xmlenc#sha256");
        signature.addKeyInfo(certificate);
        signature.sign(privateKey);
        return documentToString(document);
    }

    static String encodeAssertion(String xml) {
        return Base64.getEncoder().encodeToString(xml.getBytes(java.nio.charset.StandardCharsets.UTF_8));
    }

    private static void ensureInit() {
        if (!initialized) {
            synchronized (SamlAssertionTestSupport.class) {
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
        factory.setFeature(XMLConstants.FEATURE_SECURE_PROCESSING, true);
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        factory.setAttribute(XMLConstants.ACCESS_EXTERNAL_SCHEMA, "");
        return factory.newDocumentBuilder().parse(new InputSource(new StringReader(xml)));
    }

    private static String documentToString(Document document) throws Exception {
        TransformerFactory transformerFactory = TransformerFactory.newInstance();
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, "");
        transformerFactory.setAttribute(XMLConstants.ACCESS_EXTERNAL_STYLESHEET, "");
        Transformer transformer = transformerFactory.newTransformer();
        transformer.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        StringWriter writer = new StringWriter();
        transformer.transform(new DOMSource(document), new StreamResult(writer));
        return writer.toString().replace("\r\n", "\n");
    }
}
