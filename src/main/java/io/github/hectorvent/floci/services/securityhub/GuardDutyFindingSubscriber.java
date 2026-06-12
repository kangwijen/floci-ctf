package io.github.hectorvent.floci.services.securityhub;

import jakarta.enterprise.context.ApplicationScoped;
import org.jboss.logging.Logger;

/**
 * Stub hook for forwarding GuardDuty findings into Security Hub when GuardDuty is available.
 */
@ApplicationScoped
public class GuardDutyFindingSubscriber {

    private static final Logger LOG = Logger.getLogger(GuardDutyFindingSubscriber.class);

    public void onGuardDutyFinding(String region, String findingId) {
        LOG.debugv("GuardDuty finding subscription stub: region={0}, findingId={1}", region, findingId);
    }
}
