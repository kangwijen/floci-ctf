package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.services.cloudtrail.CloudTrailAuditTiming;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

import java.time.Instant;

/**
 * Captures request arrival time before handlers run so CloudTrail {@code eventTime}
 * preserves caller order when responses complete out of order.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 29)
public class CloudTrailAuditRequestFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext request) {
        request.setProperty(CloudTrailAuditTiming.REQUEST_TIME_PROPERTY, Instant.now());
    }
}
