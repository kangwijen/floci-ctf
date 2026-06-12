package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Records in-process AWS API calls as CloudTrail events when audit is enabled and a trail is logging.
 */
@ApplicationScoped
public class InProcessCloudTrailRecorder {

    private static final Set<String> GLOBAL_SERVICES = Set.of("iam", "sts", "cloudfront", "route53", "waf");

    private final EmulatorConfig config;
    private final CloudTrailService cloudTrailService;
    private final CloudTrailEventRecorder eventRecorder;

    @Inject
    public InProcessCloudTrailRecorder(EmulatorConfig config,
                                       CloudTrailService cloudTrailService,
                                       CloudTrailEventRecorder eventRecorder) {
        this.config = config;
        this.cloudTrailService = cloudTrailService;
        this.eventRecorder = eventRecorder;
    }

    public void recordAwsServiceEvent(String region,
                                      String eventSource,
                                      String eventName,
                                      String invokedBy,
                                      Map<String, ?> requestParameters) {
        Map<String, Object> params = requestParameters == null
                ? Map.of()
                : new LinkedHashMap<>(requestParameters);
        record(InProcessAuditContext.builder()
                .region(region)
                .eventSource(eventSource)
                .eventName(eventName)
                .credentialScope(credentialScopeFromEventSource(eventSource))
                .requestParameters(params)
                .invokedBy(invokedBy)
                .build());
    }

    public void record(InProcessAuditContext ctx) {
        if (ctx == null || ctx.region() == null || ctx.region().isBlank()) {
            return;
        }
        if (!config.services().cloudtrail().enabled() || !config.services().cloudtrail().auditEnabled()) {
            return;
        }
        if ("cloudtrail".equals(ctx.credentialScope())) {
            return;
        }
        if (!hasActiveTrail(ctx.region(), ctx.credentialScope())) {
            return;
        }
        Map<String, Object> event = eventRecorder.buildInProcessEvent(ctx);
        cloudTrailService.recordEvent(ctx.region(), event);
    }

    private boolean hasActiveTrail(String region, String credentialScope) {
        List<?> activeTrails = cloudTrailService.listActiveLoggingTrails(region);
        if (!activeTrails.isEmpty()) {
            return true;
        }
        if (credentialScope != null && GLOBAL_SERVICES.contains(credentialScope)) {
            return !cloudTrailService.listActiveLoggingTrailsForGlobalService().isEmpty();
        }
        return false;
    }

    private static String credentialScopeFromEventSource(String eventSource) {
        if (eventSource == null || !eventSource.endsWith(".amazonaws.com")) {
            return null;
        }
        String scope = eventSource.substring(0, eventSource.length() - ".amazonaws.com".length());
        return "apigateway".equals(scope) ? "execute-api" : scope;
    }
}
