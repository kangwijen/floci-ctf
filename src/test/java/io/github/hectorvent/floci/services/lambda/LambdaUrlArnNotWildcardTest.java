package io.github.hectorvent.floci.services.lambda;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.model.LambdaUrlConfig;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.UriInfo;
import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * O10: {@code /lambda-url/{urlId}} must resolve to the concrete function ARN, not {@code function:*}.
 */
@Tag("security-regression")
class LambdaUrlArnNotWildcardTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final String URL_ID = "abcdef0123456789abcdef0123456789";
    private static final String FUNCTION_ARN =
            "arn:aws:lambda:us-east-1:222222222222:function:secret-fn";

    @Test
    void lambdaUrlPathResolvesConcreteFunctionArnFromStore() {
        LambdaFunctionStore store = mock(LambdaFunctionStore.class);
        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("secret-fn");
        fn.setFunctionArn(FUNCTION_ARN);
        LambdaUrlConfig urlConfig = new LambdaUrlConfig();
        urlConfig.setFunctionUrl("http://" + URL_ID + ".lambda-url.us-east-1.localhost:4566/");
        urlConfig.setFunctionArn(FUNCTION_ARN);
        urlConfig.setAuthType("AWS_IAM");
        fn.setUrlConfig(urlConfig);
        when(store.getByUrlId(URL_ID)).thenReturn(Optional.of(fn));

        ResourceArnBuilder builder = new ResourceArnBuilder(new ObjectMapper(), null, store, null);
        ContainerRequestContext ctx = pathCtx("lambda-url/" + URL_ID + "/");

        String arn = builder.build("lambda", ctx, REGION, ACCOUNT);

        assertEquals(FUNCTION_ARN, arn);
    }

    @Test
    void lambdaUrlPathDoesNotUseFunctionWildcardWhenStoreHasFunction() {
        LambdaFunctionStore store = mock(LambdaFunctionStore.class);
        LambdaFunction fn = new LambdaFunction();
        fn.setFunctionName("secret-fn");
        fn.setFunctionArn(FUNCTION_ARN);
        when(store.getByUrlId(URL_ID)).thenReturn(Optional.of(fn));

        ResourceArnBuilder builder = new ResourceArnBuilder(new ObjectMapper(), null, store, null);
        ContainerRequestContext ctx = pathCtx("/lambda-url/" + URL_ID + "/hello");

        String arn = builder.build("lambda", ctx, REGION, ACCOUNT);

        assertEquals(FUNCTION_ARN, arn);
    }

    private static ContainerRequestContext pathCtx(String path) {
        ContainerRequestContext ctx = mock(ContainerRequestContext.class);
        UriInfo uriInfo = mock(UriInfo.class);
        when(uriInfo.getPath()).thenReturn(path);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        return ctx;
    }
}
