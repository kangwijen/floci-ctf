package io.github.hectorvent.floci.core.common.auth;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountContextFilter;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.core.common.RequestContext;
import io.github.hectorvent.floci.core.common.SessionAccountLookup;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O23: when SigV4 validation is active, AccountContextFilter must not publish
 * {@link RequestContext#getAccessKeyId()} from an unverified Authorization header.
 */
@Tag("security-regression")
class RequestContextAkidGatingTest {

    private static final String AUTH =
            "AWS4-HMAC-SHA256 Credential=AKIAEXAMPLEKEY01/20260617/us-west-2/s3/aws4_request, "
                    + "SignedHeaders=host, Signature=abc";

    @Test
    void doesNotSetAccessKeyIdWhenSignatureValidationActive() {
        RequestContext requestContext = new RequestContext();
        AccountContextFilter filter = newFilter(requestContext, true);

        filter.filter(mockContext(AUTH, null));

        assertEquals("000000000000", requestContext.getAccountId());
        assertEquals("us-west-2", requestContext.getRegion());
        assertNull(requestContext.getAccessKeyId());
    }

    @Test
    void setsAccessKeyIdWhenSignatureValidationInactive() {
        RequestContext requestContext = new RequestContext();
        AccountContextFilter filter = newFilter(requestContext, false);

        filter.filter(mockContext(AUTH, null));

        assertEquals("AKIAEXAMPLEKEY01", requestContext.getAccessKeyId());
    }

    @Test
    void doesNotSetPresignedAccessKeyIdWhenSignatureValidationActive() {
        RequestContext requestContext = new RequestContext();
        AccountContextFilter filter = newFilter(requestContext, true);

        filter.filter(mockContext(null, "AKIAEXAMPLEKEY02/20260617/eu-west-1/s3/aws4_request"));

        assertEquals("eu-west-1", requestContext.getRegion());
        assertNull(requestContext.getAccessKeyId());
    }

    private static AccountContextFilter newFilter(RequestContext requestContext, boolean validateSignatures) {
        AccountResolver accountResolver = new AccountResolver("000000000000");
        RegionResolver regionResolver = new RegionResolver("us-east-1", "000000000000");
        SessionAccountLookup sessionLookup = akid -> Optional.empty();
        AuthPosture posture = AuthPosture.from(config(validateSignatures));
        return new AccountContextFilter(
                accountResolver, regionResolver, requestContext, sessionLookup, posture);
    }

    private static EmulatorConfig config(boolean validateSignatures) {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        EmulatorConfig.CtfConfig ctf = mock(EmulatorConfig.CtfConfig.class);
        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
        when(iam.enforcementEnabled()).thenReturn(false);
        when(iam.strictEnforcementEnabled()).thenReturn(false);
        when(config.auth()).thenReturn(auth);
        when(auth.validateSignatures()).thenReturn(validateSignatures);
        when(config.ctf()).thenReturn(ctf);
        when(ctf.validateFederatedTokens()).thenReturn(false);
        when(ctf.blockPrivateOutboundUrls()).thenReturn(false);
        return config;
    }

    private static ContainerRequestContext mockContext(String authHeader, String xAmzCredential) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        when(ctx.getHeaderString("Authorization")).thenReturn(authHeader);
        UriInfo uriInfo = mock(UriInfo.class);
        MultivaluedMap<String, String> queryParams = new MultivaluedHashMap<>();
        if (xAmzCredential != null) {
            queryParams.add("X-Amz-Credential", xAmzCredential);
        }
        when(uriInfo.getQueryParameters()).thenReturn(queryParams);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        return ctx;
    }
}
