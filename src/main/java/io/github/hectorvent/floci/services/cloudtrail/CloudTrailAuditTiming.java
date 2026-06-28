package io.github.hectorvent.floci.services.cloudtrail;

/**
 * Request-scoped timing for CloudTrail audit events so {@code eventTime} reflects
 * call order rather than response-filter completion order.
 */
public final class CloudTrailAuditTiming {

    public static final String REQUEST_TIME_PROPERTY = "floci.cloudtrail.requestTime";

    private CloudTrailAuditTiming() {
    }
}
