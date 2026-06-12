package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailEventRecorder;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailService;
import io.github.hectorvent.floci.services.configservice.ConfigSnapshotChangeHook;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerResponseContext;
import jakarta.ws.rs.container.ContainerResponseFilter;
import jakarta.ws.rs.ext.Provider;

import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Records HTTP API calls as CloudTrail management events when at least one trail
 * has {@code IsLogging=true} for the request region.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 30)
public class CloudTrailAuditFilter implements ContainerResponseFilter {

    private static final Set<String> GLOBAL_SERVICES = Set.of("iam", "sts", "cloudfront", "route53", "waf");

    /** Read-only CloudTrail APIs skipped to avoid lookup/describe noise. */
    private static final Set<String> CLOUDTRAIL_AUDIT_SKIP = Set.of(
            "LookupEvents", "DescribeTrails", "GetTrailStatus");

    private final EmulatorConfig config;
    private final CloudTrailService cloudTrailService;
    private final CloudTrailEventRecorder eventRecorder;
    private final IamActionRegistry actionRegistry;
    private final RegionResolver regionResolver;
    private final ConfigSnapshotChangeHook configSnapshotChangeHook;

    @Inject
    public CloudTrailAuditFilter(EmulatorConfig config,
                                 CloudTrailService cloudTrailService,
                                 CloudTrailEventRecorder eventRecorder,
                                 IamActionRegistry actionRegistry,
                                 RegionResolver regionResolver,
                                 ConfigSnapshotChangeHook configSnapshotChangeHook) {
        this.config = config;
        this.cloudTrailService = cloudTrailService;
        this.eventRecorder = eventRecorder;
        this.actionRegistry = actionRegistry;
        this.regionResolver = regionResolver;
        this.configSnapshotChangeHook = configSnapshotChangeHook;
    }

    @Override
    public void filter(ContainerRequestContext request, ContainerResponseContext response) {
        if (!config.services().cloudtrail().enabled() || !config.services().cloudtrail().auditEnabled()) {
            return;
        }

        String path = request.getUriInfo().getPath();
        if (shouldSkip(path, request)) {
            return;
        }

        String region = resolveRegion(request);
        String credentialScope = resolveCredentialScope(request);

        boolean cloudTrailMutatingAudit = isCloudTrailMutatingAudit(credentialScope, request);
        if (!cloudTrailMutatingAudit) {
            List<?> activeTrails = cloudTrailService.listActiveLoggingTrails(region);
            if (activeTrails.isEmpty()) {
                if (credentialScope != null && GLOBAL_SERVICES.contains(credentialScope)) {
                    activeTrails = cloudTrailService.listActiveLoggingTrailsForGlobalService();
                }
                if (activeTrails.isEmpty()) {
                    return;
                }
            }
        }

        String iamAction = credentialScope != null
                ? actionRegistry.resolve(credentialScope, request)
                : null;

        Map<String, Object> event = eventRecorder.buildEvent(request, response, iamAction, credentialScope);
        cloudTrailService.recordEvent(region, event);
        configSnapshotChangeHook.onManagementEvent(region, event, response.getStatus());
    }

    private boolean shouldSkip(String path, ContainerRequestContext request) {
        String normalized = normalize(path);
        for (String excluded : config.services().cloudtrail().excludeInternalPaths()) {
            if (excluded == null || excluded.isBlank()) {
                continue;
            }
            String prefix = excluded.startsWith("/") ? excluded : "/" + excluded;
            if (normalized.equals(prefix) || normalized.startsWith(prefix.endsWith("/") ? prefix : prefix + "/")) {
                return true;
            }
        }
        if (SecurityBypassPaths.isInternalHealthOrInfoPath(path, config.ctf().hideInternalEndpointsMode())) {
            return true;
        }
        if (SecurityBypassPaths.isPrefixedInternalPath(normalized)) {
            return true;
        }
        if (SecurityBypassPaths.isAwsInspectionPath(normalized)) {
            return true;
        }
        if (SecurityBypassPaths.isCognitoOAuthPath(path)) {
            return true;
        }
        return SecurityBypassPaths.isPresignedPostRequest(request);
    }

    private String resolveRegion(ContainerRequestContext request) {
        String auth = request.getHeaderString("Authorization");
        if (auth != null) {
            return regionResolver.resolveRegionFromAuth(auth);
        }
        String credential = request.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        if (credential != null) {
            String[] parts = credential.split("/");
            if (parts.length >= 3 && !parts[2].isBlank()) {
                return parts[2];
            }
        }
        return config.defaultRegion();
    }

    private String resolveCredentialScope(ContainerRequestContext request) {
        String auth = request.getHeaderString("Authorization");
        String scope = CloudTrailEventRecorder.extractCredentialScope(auth);
        if (scope != null) {
            return scope;
        }
        String credential = request.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
        if (credential != null) {
            String[] parts = credential.split("/");
            if (parts.length >= 4 && !parts[3].isBlank()) {
                return parts[3];
            }
        }
        String path = request.getUriInfo().getPath();
        if (path != null && !path.isBlank() && !"/".equals(path) && !path.startsWith("/_")) {
            return "s3";
        }
        String target = request.getHeaderString("X-Amz-Target");
        if (target != null) {
            if (target.contains("cloudtrail")) {
                return "cloudtrail";
            }
            if (target.contains("DynamoDB")) {
                return "dynamodb";
            }
            if (target.contains("SSM")) {
                return "ssm";
            }
        }
        String action = request.getUriInfo().getQueryParameters().getFirst("Action");
        if (action != null) {
            return inferScopeFromQueryAction(request);
        }
        return null;
    }

    private String inferScopeFromQueryAction(ContainerRequestContext request) {
        String auth = request.getHeaderString("Authorization");
        String scope = CloudTrailEventRecorder.extractCredentialScope(auth);
        return scope != null ? scope : "iam";
    }

    /**
     * Records mutating CloudTrail control-plane calls (for example {@code StopLogging})
     * even when the response filter runs after logging was disabled.
     */
    private static boolean isCloudTrailMutatingAudit(String credentialScope, ContainerRequestContext request) {
        if (!"cloudtrail".equals(credentialScope)) {
            return false;
        }
        String operation = resolveCloudTrailOperation(request);
        return operation != null && !CLOUDTRAIL_AUDIT_SKIP.contains(operation);
    }

    private static String resolveCloudTrailOperation(ContainerRequestContext request) {
        String target = request.getHeaderString("X-Amz-Target");
        if (target == null || !target.contains(".")) {
            return null;
        }
        return target.substring(target.lastIndexOf('.') + 1);
    }

    private static String normalize(String path) {
        if (path == null || path.isEmpty()) {
            return "";
        }
        return path.startsWith("/") ? path : "/" + path;
    }
}
