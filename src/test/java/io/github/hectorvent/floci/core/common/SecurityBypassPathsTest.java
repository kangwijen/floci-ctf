package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicReference;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class SecurityBypassPathsTest {

    @Test
    void isPrefixedInternalPathMatchesFlociAndLocalstack() {
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_floci"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_floci/"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_floci/health"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_localstack"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_localstack/"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("/_localstack/init"));
    }

    @Test
    void isPrefixedInternalPathRejectsNonInternalRoutes() {
        assertFalse(SecurityBypassPaths.isPrefixedInternalPath("/_aws"));
        assertFalse(SecurityBypassPaths.isPrefixedInternalPath("/health"));
        assertFalse(SecurityBypassPaths.isPrefixedInternalPath(null));
        assertFalse(SecurityBypassPaths.isPrefixedInternalPath(""));
    }

    @Test
    void isPrefixedInternalPathNormalizesMissingLeadingSlash() {
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("_floci/status"));
        assertTrue(SecurityBypassPaths.isPrefixedInternalPath("_localstack/ready"));
    }

    @Test
    void isAwsInspectionPathMatchesAwsPrefix() {
        assertTrue(SecurityBypassPaths.isAwsInspectionPath("/_aws"));
        assertTrue(SecurityBypassPaths.isAwsInspectionPath("/_aws/"));
        assertTrue(SecurityBypassPaths.isAwsInspectionPath("/_aws/sqs/messages"));
        assertTrue(SecurityBypassPaths.isAwsInspectionPath("_aws/info"));
    }

    @Test
    void isAwsInspectionPathRejectsOtherRoutes() {
        assertFalse(SecurityBypassPaths.isAwsInspectionPath("/_floci"));
        assertFalse(SecurityBypassPaths.isAwsInspectionPath("/health"));
        assertFalse(SecurityBypassPaths.isAwsInspectionPath(null));
    }

    @Test
    void normalizePathStripsLeadingSlash() {
        assertEquals("health", SecurityBypassPaths.normalizePath("/health"));
        assertEquals("_floci/info", SecurityBypassPaths.normalizePath("/_floci/info"));
        assertEquals("health", SecurityBypassPaths.normalizePath("health"));
        assertEquals("", SecurityBypassPaths.normalizePath(null));
        assertEquals("", SecurityBypassPaths.normalizePath(""));
    }

    @Test
    void isCognitoOAuthPathMatchesTokenAndUserInfo() {
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("/cognito-idp/oauth2/token"));
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("cognito-idp/oauth2/token"));
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("/cognito-idp/oauth2/userInfo"));
        assertTrue(SecurityBypassPaths.isCognitoOAuthPath("cognito-idp/oauth2/userInfo"));
    }

    @Test
    void isCognitoOAuthPathRejectsOtherRoutes() {
        assertFalse(SecurityBypassPaths.isCognitoOAuthPath("/cognito-idp/oauth2/authorize"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthPath("/oauth2/token"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthPath(null));
        assertFalse(SecurityBypassPaths.isCognitoOAuthPath(""));
    }

    @Test
    void isCognitoOAuthTokenPathEdgeCases() {
        assertTrue(SecurityBypassPaths.isCognitoOAuthTokenPath("/cognito-idp/oauth2/token"));
        assertTrue(SecurityBypassPaths.isCognitoOAuthTokenPath("cognito-idp/oauth2/token"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthTokenPath("/cognito-idp/oauth2/token/"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthTokenPath("/cognito-idp/oauth2/userInfo"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthTokenPath("/oauth2/token"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthTokenPath(null));
        assertFalse(SecurityBypassPaths.isCognitoOAuthTokenPath(""));
    }

    @Test
    void isCognitoOAuthUserInfoPathEdgeCases() {
        assertTrue(SecurityBypassPaths.isCognitoOAuthUserInfoPath("/cognito-idp/oauth2/userInfo"));
        assertFalse(SecurityBypassPaths.isCognitoOAuthUserInfoPath("/cognito-idp/oauth2/token"));
    }

    @Test
    void isInternalHealthOrInfoPathWithHideModeOff() {
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/health", CtfHideInternalEndpointsMode.OFF));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/_floci/info", CtfHideInternalEndpointsMode.OFF));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/_localstack/ready", CtfHideInternalEndpointsMode.OFF));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_aws/sqs", CtfHideInternalEndpointsMode.OFF));
    }

    @Test
    void isInternalHealthOrInfoPathWithHideModePrefixed() {
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/health", CtfHideInternalEndpointsMode.PREFIXED));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_floci/info", CtfHideInternalEndpointsMode.PREFIXED));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_localstack/ready", CtfHideInternalEndpointsMode.PREFIXED));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_aws/sqs", CtfHideInternalEndpointsMode.PREFIXED));
    }

    @Test
    void isInternalHealthOrInfoPathWithHideModeAll() {
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/health", CtfHideInternalEndpointsMode.ALL));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_floci/info", CtfHideInternalEndpointsMode.ALL));
        assertFalse(SecurityBypassPaths.isInternalHealthOrInfoPath("/_localstack/ready", CtfHideInternalEndpointsMode.ALL));
    }

    @Test
    void isInternalHealthOrInfoPathDefaultUsesOffMode() {
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/health"));
        assertTrue(SecurityBypassPaths.isInternalHealthOrInfoPath("/_floci/status"));
    }

    @Test
    void isMultipartBucketPostRequestDetectsBucketPost() {
        ContainerRequestContext ctx = mockMultipartPost("my-bucket", new MultivaluedHashMap<>(), "");
        assertTrue(SecurityBypassPaths.isMultipartBucketPostRequest(ctx));
    }

    @Test
    void isMultipartBucketPostRequestRejectsDeleteQuery() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("delete", "");
        ContainerRequestContext ctx = mockMultipartPost("my-bucket", query, "");
        assertFalse(SecurityBypassPaths.isMultipartBucketPostRequest(ctx));
    }

    @Test
    void isMultipartBucketPostRequestRejectsNestedObjectPath() {
        ContainerRequestContext ctx = mockMultipartPost("my-bucket/object.txt", new MultivaluedHashMap<>(), "");
        assertFalse(SecurityBypassPaths.isMultipartBucketPostRequest(ctx));
    }

    @Test
    void isPresignedPostRequestDetectsPolicyField() {
        String body = multipartBody("policy", "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifQ==");
        ContainerRequestContext ctx = mockMultipartPost("upload-bucket", new MultivaluedHashMap<>(), body);
        assertTrue(SecurityBypassPaths.isPresignedPostRequest(ctx));
    }

    @Test
    void isPresignedPostRequestDetectsXAmzAlgorithmField() {
        String body = multipartBody("x-amz-algorithm", "AWS4-HMAC-SHA256");
        ContainerRequestContext ctx = mockMultipartPost("upload-bucket", new MultivaluedHashMap<>(), body);
        assertTrue(SecurityBypassPaths.isPresignedPostRequest(ctx));
    }

    @Test
    void isPresignedPostRequestRejectsMultipartWithoutPolicyMarkers() {
        String body = multipartBody("key", "file.txt");
        ContainerRequestContext ctx = mockMultipartPost("upload-bucket", new MultivaluedHashMap<>(), body);
        assertTrue(SecurityBypassPaths.isMultipartBucketPostRequest(ctx));
        assertFalse(SecurityBypassPaths.isPresignedPostRequest(ctx));
    }

    @Test
    void isPresignedPostRequestRejectsDeleteQueryEvenWithPolicy() {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        query.add("delete", "");
        String body = multipartBody("policy", "eyJleHBpcmF0aW9uIjoiMjAyNi0wMS0wMVQwMDowMDowMFoifQ==");
        ContainerRequestContext ctx = mockMultipartPost("upload-bucket", query, body);
        assertFalse(SecurityBypassPaths.isPresignedPostRequest(ctx));
    }

    @Test
    void isFederatedStsAssumeRequestDetectsWebIdentityToken() {
        ContainerRequestContext ctx = mockFormPost(
                "Action=AssumeRoleWithWebIdentity&RoleArn=arn:aws:iam::000000000000:role/x"
                        + "&WebIdentityToken=eyJ.test.token");
        assertTrue(SecurityBypassPaths.isFederatedStsAssumeRequest(ctx));
    }

    @Test
    void isFederatedStsAssumeRequestDetectsSamlAssertion() {
        ContainerRequestContext ctx = mockFormPost(
                "Action=AssumeRoleWithSAML&RoleArn=arn:aws:iam::000000000000:role/x&SAMLAssertion=abc123");
        assertTrue(SecurityBypassPaths.isFederatedStsAssumeRequest(ctx));
    }

    @Test
    void isFederatedStsAssumeRequestRejectsPlainAssumeRole() {
        ContainerRequestContext ctx = mockFormPost(
                "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/x&RoleSessionName=s");
        assertFalse(SecurityBypassPaths.isFederatedStsAssumeRequest(ctx));
    }

    private static ContainerRequestContext mockFormPost(String body) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.UTF_8)));
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
        when(uriInfo.getPath()).thenReturn("/");
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn("POST");
        when(ctx.getMediaType()).thenReturn(jakarta.ws.rs.core.MediaType.APPLICATION_FORM_URLENCODED_TYPE);
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
        return ctx;
    }

    private static ContainerRequestContext mockMultipartPost(String path,
                                                             MultivaluedMap<String, String> queryParams,
                                                             String body) {
        AtomicReference<InputStream> streamRef = new AtomicReference<>(
                new ByteArrayInputStream(body.getBytes(StandardCharsets.ISO_8859_1)));
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(uriInfo.getPath()).thenReturn(path);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(ctx.getMethod()).thenReturn("POST");
        when(ctx.getHeaderString("Content-Type"))
                .thenReturn("multipart/form-data; boundary=----floci-test-boundary");
        when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
        doAnswer(inv -> {
            streamRef.set(inv.getArgument(0));
            return null;
        }).when(ctx).setEntityStream(any(InputStream.class));
        return ctx;
    }

    private static String multipartBody(String fieldName, String fieldValue) {
        return "------floci-test-boundary\r\n"
                + "Content-Disposition: form-data; name=\"" + fieldName + "\"\r\n"
                + "\r\n"
                + fieldValue + "\r\n"
                + "------floci-test-boundary--\r\n";
    }
}
