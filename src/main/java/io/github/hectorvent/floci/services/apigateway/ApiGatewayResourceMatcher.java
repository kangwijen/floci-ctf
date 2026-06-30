package io.github.hectorvent.floci.services.apigateway;

import io.github.hectorvent.floci.services.apigateway.model.ApiGatewayResource;

import java.util.List;

/**
 * Matches incoming execute-api paths to API Gateway resource definitions.
 */
public final class ApiGatewayResourceMatcher {

    private ApiGatewayResourceMatcher() {
    }

    public static ApiGatewayResource match(List<ApiGatewayResource> resources, String requestPath) {
        for (ApiGatewayResource r : resources) {
            if (requestPath.equals(r.getPath())) {
                return r;
            }
        }
        for (ApiGatewayResource r : resources) {
            if (r.getPath() != null && r.getPath().contains("{") && !r.getPath().contains("{proxy+}")) {
                if (pathMatchesTemplate(r.getPath(), requestPath)) {
                    return r;
                }
            }
        }
        ApiGatewayResource best = null;
        int bestLen = -1;
        for (ApiGatewayResource r : resources) {
            if (r.getPath() == null || !r.getPath().contains("{proxy+}")) {
                continue;
            }
            String parentPrefix = r.getPath().substring(0, r.getPath().indexOf("{proxy+}"));
            if ("/".equals(parentPrefix)) {
                if (best == null) {
                    best = r;
                    bestLen = 0;
                }
                continue;
            }
            if (requestPath.startsWith(parentPrefix)
                    && requestPath.length() > parentPrefix.length()
                    && parentPrefix.length() > bestLen) {
                best = r;
                bestLen = parentPrefix.length();
            }
        }
        return best;
    }

    private static boolean pathMatchesTemplate(String templatePath, String requestPath) {
        String[] tParts = templatePath.split("/", -1);
        String[] rParts = requestPath.split("/", -1);
        if (tParts.length != rParts.length) {
            return false;
        }
        for (int i = 0; i < tParts.length; i++) {
            if (tParts[i].startsWith("{") && tParts[i].endsWith("}")) {
                continue;
            }
            if (!tParts[i].equals(rParts[i])) {
                return false;
            }
        }
        return true;
    }
}
