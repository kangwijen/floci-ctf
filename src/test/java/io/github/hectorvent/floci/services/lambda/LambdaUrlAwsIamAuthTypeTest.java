package io.github.hectorvent.floci.services.lambda;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.model.LambdaUrlConfig;
import jakarta.ws.rs.core.HttpHeaders;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.net.URI;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * AuthType=AWS_IAM requires SigV4 even when IAM strict enforcement is off.
 */
@Tag("security-regression")
class LambdaUrlAwsIamAuthTypeTest {

    private static final String URL_ID = "abcdef0123456789abcdef0123456789";
    private static final String FUNCTION_ARN =
            "arn:aws:lambda:us-east-1:000000000000:function:iam-url-fn";

    private LambdaService lambdaService;
    private LambdaUrlInvocationController controller;
    private HttpHeaders headers;
    private UriInfo uriInfo;

    @BeforeEach
    void setUp() {
        lambdaService = mock(LambdaService.class);
        RegionResolver regionResolver = mock(RegionResolver.class);
        when(regionResolver.getAccountId()).thenReturn("000000000000");
        controller = new LambdaUrlInvocationController(lambdaService, regionResolver, new ObjectMapper());

        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("iam-url-fn");
        fn.setFunctionArn(FUNCTION_ARN);
        LambdaUrlConfig urlConfig = new LambdaUrlConfig();
        urlConfig.setAuthType("AWS_IAM");
        urlConfig.setFunctionArn(FUNCTION_ARN);
        fn.setUrlConfig(urlConfig);
        when(lambdaService.getTargetByUrlId(URL_ID)).thenReturn(fn);

        headers = mock(HttpHeaders.class);
        when(headers.getRequestHeaders()).thenReturn(new MultivaluedHashMap<>());
        uriInfo = mock(UriInfo.class);
        when(uriInfo.getRequestUri()).thenReturn(URI.create("http://localhost:4566/lambda-url/" + URL_ID + "/"));
        when(uriInfo.getQueryParameters()).thenReturn(new MultivaluedHashMap<>());
    }

    @Test
    void unsignedInvokeDeniedWhenAuthTypeAwsIam() {
        when(headers.getHeaderString("Authorization")).thenReturn(null);

        Response response = controller.handleGet(URL_ID, "", headers, uriInfo);

        assertEquals(403, response.getStatus());
        assertTrue(String.valueOf(response.getEntity()).contains("MissingAuthentication")
                || String.valueOf(response.getEntity()).contains("AccessDenied"));
        verify(lambdaService, never()).invoke(org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.anyString(),
                org.mockito.ArgumentMatchers.any(),
                org.mockito.ArgumentMatchers.any());
    }
}
