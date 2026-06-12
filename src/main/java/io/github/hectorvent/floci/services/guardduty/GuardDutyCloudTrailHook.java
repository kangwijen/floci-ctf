package io.github.hectorvent.floci.services.guardduty;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Map;

/**
 * Optional bridge from CloudTrail audit events to GuardDuty finding generation.
 */
@ApplicationScoped
public class GuardDutyCloudTrailHook {

    private final GuardDutyService guardDutyService;

    @Inject
    public GuardDutyCloudTrailHook(GuardDutyService guardDutyService) {
        this.guardDutyService = guardDutyService;
    }

    public void onCloudTrailEvent(String region, Map<String, Object> event) {
        guardDutyService.onCloudTrailEvent(region, event);
    }
}
