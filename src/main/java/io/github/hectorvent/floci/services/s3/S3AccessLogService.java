package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.s3.model.Bucket;
import io.github.hectorvent.floci.services.s3.model.LoggingConfiguration;
import io.github.hectorvent.floci.services.s3.model.S3Object;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Map;

@ApplicationScoped
public class S3AccessLogService {

    private static final Logger LOG = Logger.getLogger(S3AccessLogService.class);
    private static final DateTimeFormatter LOG_OBJECT_HOUR = DateTimeFormatter
            .ofPattern("yyyy-MM-dd-HH", java.util.Locale.ROOT)
            .withZone(ZoneOffset.UTC);
    private static final ThreadLocal<Boolean> DELIVERING = ThreadLocal.withInitial(() -> false);

    private final S3Service s3Service;
    private final RegionResolver regionResolver;
    private final InProcessCloudTrailRecorder cloudTrailRecorder;

    @Inject
    public S3AccessLogService(S3Service s3Service,
                              RegionResolver regionResolver,
                              InProcessCloudTrailRecorder cloudTrailRecorder) {
        this.s3Service = s3Service;
        this.regionResolver = regionResolver;
        this.cloudTrailRecorder = cloudTrailRecorder;
    }

    void recordAccess(S3AccessLogContext ctx) {
        if (Boolean.TRUE.equals(DELIVERING.get())) {
            return;
        }
        Bucket sourceBucket = s3Service.getBucketIfExists(ctx.sourceBucket()).orElse(null);
        if (sourceBucket == null) {
            return;
        }
        LoggingConfiguration logging = sourceBucket.getLoggingConfiguration();
        if (logging == null || logging.getTargetBucket() == null || logging.getTargetBucket().isBlank()) {
            return;
        }
        String targetBucket = logging.getTargetBucket();
        if (!s3Service.bucketExists(targetBucket)) {
            LOG.warnv("Skipping S3 access log delivery: target bucket {0} does not exist", targetBucket);
            return;
        }

        String accountId = regionResolver != null ? regionResolver.getAccountId() : "000000000000";
        String bucketOwnerId = S3AccessLogFormatter.canonicalUserId(accountId);
        String sourceRegion = sourceBucket.getRegion() != null ? sourceBucket.getRegion()
                : (regionResolver != null ? regionResolver.resolveRegion(null) : "us-east-1");
        String line = S3AccessLogFormatter.formatLine(ctx, bucketOwnerId, sourceRegion) + "\n";

        String prefix = logging.getTargetPrefix() != null ? logging.getTargetPrefix() : "";
        String logObjectKey = prefix + LOG_OBJECT_HOUR.format(ctx.timestamp()) + "-floci-s3-access.log";

        try {
            DELIVERING.set(true);
            byte[] existing = readLogObjectBytes(targetBucket, logObjectKey);
            byte[] updated;
            if (existing.length == 0) {
                updated = line.getBytes(StandardCharsets.UTF_8);
            } else {
                byte[] lineBytes = line.getBytes(StandardCharsets.UTF_8);
                updated = new byte[existing.length + lineBytes.length];
                System.arraycopy(existing, 0, updated, 0, existing.length);
                System.arraycopy(lineBytes, 0, updated, existing.length, lineBytes.length);
            }
            s3Service.putAccessLogObject(targetBucket, logObjectKey, updated);
            cloudTrailRecorder.recordAwsServiceEvent(sourceRegion, "s3.amazonaws.com", "PutObject",
                    "s3.amazonaws.com", Map.of("bucketName", targetBucket, "key", logObjectKey));
        } catch (Exception e) {
            LOG.warnv("Failed to deliver S3 access log for bucket {0}: {1}", ctx.sourceBucket(), e.getMessage());
        } finally {
            DELIVERING.set(false);
        }
    }

    private byte[] readLogObjectBytes(String targetBucket, String logObjectKey) {
        try {
            S3Object existing = s3Service.getObject(targetBucket, logObjectKey);
            return existing.getData() != null ? existing.getData() : new byte[0];
        } catch (AwsException e) {
            if ("NoSuchKey".equals(e.getErrorCode())) {
                return new byte[0];
            }
            throw e;
        }
    }
}
