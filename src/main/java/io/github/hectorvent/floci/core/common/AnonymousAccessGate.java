package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.apigateway.ApiGatewayResourceMatcher;
import io.github.hectorvent.floci.services.apigateway.ApiGatewayService;
import io.github.hectorvent.floci.services.apigateway.ExecuteAuthzGate;
import io.github.hectorvent.floci.services.apigateway.model.ApiGatewayResource;
import io.github.hectorvent.floci.services.apigateway.model.MethodConfig;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator.Decision;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.lambda.model.LambdaFunction;
import io.github.hectorvent.floci.services.lambda.model.LambdaUrlConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;

import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * AWS-intentional anonymous invoke paths under strict IAM: public S3 reads,
 * API Gateway {@code authorizationType=NONE}, and Lambda function URLs with {@code AuthType=NONE}.
 */
@ApplicationScoped
public class AnonymousAccessGate {

    private static final Pattern EXECUTE_API_PATH =
            Pattern.compile("^/?execute-api/([^/]+)/([^/]+)(?:/(.*))?$");
    private static final Pattern USER_REQUEST_PATH =
            Pattern.compile("^/?restapis/([^/]+)/([^/]+)/_user_request_(?:/(.*))?$");
    private static final Pattern LAMBDA_URL_PATH =
            Pattern.compile("^/?lambda-url/([^/]+)(?:/(.*))?$");

    private final ApiGatewayService apiGatewayService;
    private final LambdaService lambdaService;
    private final IamActionRegistry actionRegistry;
    private final ResourceArnBuilder arnBuilder;
    private final ResourcePolicyResolver resourcePolicyResolver;
    private final IamPolicyEvaluator evaluator;
    private final RegionResolver regionResolver;
    private final AccountResolver accountResolver;
    private final ExecuteAuthzGate executeAuthzGate;
    private final EmulatorConfig config;

    @Inject
    public AnonymousAccessGate(ApiGatewayService apiGatewayService,
                               LambdaService lambdaService,
                               IamActionRegistry actionRegistry,
                               ResourceArnBuilder arnBuilder,
                               ResourcePolicyResolver resourcePolicyResolver,
                               IamPolicyEvaluator evaluator,
                               RegionResolver regionResolver,
                               AccountResolver accountResolver,
                               ExecuteAuthzGate executeAuthzGate,
                               EmulatorConfig config) {
        this.apiGatewayService = apiGatewayService;
        this.lambdaService = lambdaService;
        this.actionRegistry = actionRegistry;
        this.arnBuilder = arnBuilder;
        this.resourcePolicyResolver = resourcePolicyResolver;
        this.evaluator = evaluator;
        this.regionResolver = regionResolver;
        this.accountResolver = accountResolver;
        this.executeAuthzGate = executeAuthzGate;
        this.config = config;
    }

    public boolean allowsUnsignedRequest(ContainerRequestContext ctx) {
        String method = ctx.getMethod();
        if ("GET".equalsIgnoreCase(method) || "HEAD".equalsIgnoreCase(method)) {
            if (allowsAnonymousS3ObjectRead(ctx)) {
                return true;
            }
        }
        if (allowsAnonymousExecuteApi(ctx)) {
            return true;
        }
        return allowsAnonymousLambdaFunctionUrl(ctx);
    }

    private boolean allowsAnonymousS3ObjectRead(ContainerRequestContext ctx) {
        String action = actionRegistry.resolve("s3", ctx);
        if (!"s3:GetObject".equals(action) && !"s3:HeadObject".equals(action)) {
            return false;
        }
        String region = regionResolver.getDefaultRegion();
        String accountId = accountResolver.defaultAccountId();
        String resource = arnBuilder.build("s3", ctx, region, accountId);
        List<String> resourcePolicies = resourcePolicyResolver.resolve("s3", resource, region);
        if (resourcePolicies.isEmpty()) {
            return false;
        }
        Map<String, String> conditionCtx = anonymousConditionContext(accountId);
        return evaluator.evaluate(CallerContext.of(List.of()), resourcePolicies, action, resource, conditionCtx)
                == Decision.ALLOW;
    }

    private boolean allowsAnonymousExecuteApi(ContainerRequestContext ctx) {
        ExecuteApiPath parsed = parseExecuteApiPath(ctx.getUriInfo().getPath());
        if (parsed == null) {
            return false;
        }
        String region = regionResolver.getDefaultRegion();
        try {
            apiGatewayService.getRestApi(region, parsed.apiId());
            apiGatewayService.getStage(region, parsed.apiId(), parsed.stageName());
        } catch (RuntimeException e) {
            return false;
        }
        List<ApiGatewayResource> resources = apiGatewayService.getResources(region, parsed.apiId());
        ApiGatewayResource matched = ApiGatewayResourceMatcher.match(resources, parsed.requestPath());
        if (matched == null) {
            return false;
        }
        String httpMethod = ctx.getMethod().toUpperCase();
        MethodConfig methodConfig = matched.getResourceMethods().get(httpMethod);
        if (methodConfig == null) {
            methodConfig = matched.getResourceMethods().get("ANY");
        }
        if (methodConfig == null) {
            return false;
        }
        String authType = methodConfig.getAuthorizationType();
        boolean strict = config.services().iam().strictEnforcementEnabled();
        return executeAuthzGate.allowsAnonymous(authType, strict);
    }

    private static ExecuteApiPath parseExecuteApiPath(String rawPath) {
        String normalized = SecurityBypassPaths.normalizePath(rawPath);
        Matcher executeApi = EXECUTE_API_PATH.matcher(normalized);
        if (executeApi.matches()) {
            return toExecuteApiPath(executeApi.group(1), executeApi.group(2), executeApi.group(3));
        }
        Matcher userRequest = USER_REQUEST_PATH.matcher(normalized);
        if (userRequest.matches()) {
            return toExecuteApiPath(userRequest.group(1), userRequest.group(2), userRequest.group(3));
        }
        return null;
    }

    private static ExecuteApiPath toExecuteApiPath(String apiId, String stageName, String proxy) {
        String requestPath = "/" + (proxy == null || proxy.isBlank() ? "" : proxy);
        int queryIdx = requestPath.indexOf('?');
        if (queryIdx >= 0) {
            requestPath = requestPath.substring(0, queryIdx);
        }
        return new ExecuteApiPath(apiId, stageName, requestPath);
    }

    private record ExecuteApiPath(String apiId, String stageName, String requestPath) {
    }

    private boolean allowsAnonymousLambdaFunctionUrl(ContainerRequestContext ctx) {
        Matcher matcher = LAMBDA_URL_PATH.matcher(SecurityBypassPaths.normalizePath(ctx.getUriInfo().getPath()));
        if (!matcher.matches()) {
            return false;
        }
        String urlId = matcher.group(1);
        try {
            LambdaFunction fn = lambdaService.getFunctionByUrlId(urlId);
            LambdaUrlConfig urlConfig = fn.getUrlConfig();
            if (urlConfig == null) {
                return false;
            }
            String authType = urlConfig.getAuthType();
            if (authType != null && !"NONE".equalsIgnoreCase(authType)) {
                return false;
            }
            String region = regionResolver.getDefaultRegion();
            String accountId = accountResolver.defaultAccountId();
            String resource = functionArn(fn, region, accountId);
            List<String> resourcePolicies = resourcePolicyResolver.resolve("lambda", resource, region);
            if (resourcePolicies.isEmpty()) {
                return false;
            }
            Map<String, String> conditionCtx = anonymousConditionContext(accountId);
            return evaluator.evaluate(CallerContext.of(List.of()), resourcePolicies,
                    "lambda:InvokeFunctionUrl", resource, conditionCtx) == Decision.ALLOW;
        } catch (RuntimeException e) {
            return false;
        }
    }

    private static String functionArn(LambdaFunction fn, String region, String accountId) {
        String arn = fn.getFunctionArn();
        if (arn != null && !arn.isBlank()) {
            return arn;
        }
        return AwsArnUtils.Arn.of("lambda", region, accountId, "function:" + fn.getFunctionName()).toString();
    }

    private static Map<String, String> anonymousConditionContext(String accountId) {
        Map<String, String> out = new HashMap<>();
        out.put("aws:principalarn", "*");
        out.put("aws:principalaccount", accountId);
        out.put("aws:sourceaccount", accountId);
        out.put("aws:sourcearn", "*");
        return out;
    }
}
