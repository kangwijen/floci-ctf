package io.github.hectorvent.floci.core.common;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

class SigV4aPresignSupportTest {

    @Test
    void signAndVerifyPresignedUrlStringToSign() throws Exception {
        String stringToSign = SigV4aPresignSupport.ALGORITHM + "\n"
                + "20260205T120000Z\n"
                + "20260205/us-east-1/s3/aws4_request\n"
                + "abc123";
        String signature = SigV4aPresignSupport.signStringToSign(stringToSign, SigV4aTestSupport.privateKey());
        assertTrue(SigV4aPresignSupport.verifyStringToSign(stringToSign, signature, SigV4aTestSupport.publicKey()));
    }

    @Test
    void signAndVerifyPresignedPostStringToSign() throws Exception {
        String policyBase64 = "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMVQwMDowMDowMC4wMDBaIn0=";
        String stringToSign = SigV4aPresignSupport.buildPresignedPostStringToSign(policyBase64);
        String signature = SigV4aPresignSupport.signStringToSign(stringToSign, SigV4aTestSupport.privateKey());
        assertTrue(SigV4aPresignSupport.verifyStringToSign(stringToSign, signature, SigV4aTestSupport.publicKey()));
    }

    @Test
    void verifyRejectsTamperedSignature() throws Exception {
        String stringToSign = SigV4aPresignSupport.buildPresignedPostStringToSign("policy");
        assertTrue(!SigV4aPresignSupport.verifyStringToSign(stringToSign, "deadbeef", SigV4aTestSupport.publicKey()));
    }
}
