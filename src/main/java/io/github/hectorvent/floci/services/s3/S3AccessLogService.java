package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.RegionResolver;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.iam.InProcessTargetAuthorizer;
import io.github.hectorvent.floci.services.s3.model.Bucket;
import io.github.hectorvent.floci.services.s3.model.LoggingConfiguration;
import io.vertx.core.Vertx;
import jakarta.annotation.PostConstruct;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

@ApplicationScoped
public class S3AccessLogService {

    private static final Logger LOG = Logger.getLogger(S3AccessLogService.class);
    private static final ThreadLocal<Boolean> DELIVERING = ThreadLocal.withInitial(() -> false);

    private final S3Service s3Service;
    private final RegionResolver regionResolver;
    private final InProcessCloudTrailRecorder cloudTrailRecorder;
    private final InProcessTargetAuthorizer targetAuthorizer;
    private final EmulatorConfig config;
    private final Vertx vertx;
    private final ConcurrentHashMap<String, BufferedBatch> buffers = new ConcurrentHashMap<>();

    private volatile long flushTimerId = -1L;

    @Inject
    public S3AccessLogService(S3Service s3Service,
                              RegionResolver regionResolver,
                              InProcessCloudTrailRecorder cloudTrailRecorder,
                              InProcessTargetAuthorizer targetAuthorizer,
                              EmulatorConfig config,
                              Vertx vertx) {
        this.s3Service = s3Service;
        this.regionResolver = regionResolver;
        this.cloudTrailRecorder = cloudTrailRecorder;
        this.targetAuthorizer = targetAuthorizer;
        this.config = config;
        this.vertx = vertx;
    }

    @PostConstruct
    void startScheduledDelivery() {
        if (!isScheduledDelivery()) {
            return;
        }
        long intervalMs = deliveryIntervalSeconds() * 1000L;
        flushTimerId = vertx.setPeriodic(intervalMs, id -> flushAllBuffers());
        LOG.infov("S3 access log scheduled delivery enabled (interval={0}s)", deliveryIntervalSeconds());
    }

    @PreDestroy
    void stopScheduledDelivery() {
        if (flushTimerId >= 0L) {
            vertx.cancelTimer(flushTimerId);
            flushTimerId = -1L;
        }
        flushAllBuffers();
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
        String line = S3AccessLogFormatter.formatLine(ctx, bucketOwnerId) + "\n";

        if (isScheduledDelivery()) {
            bufferLine(ctx.sourceBucket(), targetBucket, logging, line, ctx.timestamp(), sourceRegion, accountId);
            return;
        }
        deliverLine(ctx.sourceBucket(), targetBucket, logging, line, ctx.timestamp(), sourceRegion, accountId);
    }

    void flushAllBuffersForTests() {
        flushAllBuffers();
    }

    private void bufferLine(String sourceBucket,
                            String targetBucket,
                            LoggingConfiguration logging,
                            String line,
                            Instant eventTime,
                            String sourceRegion,
                            String accountId) {
        String key = bufferKey(sourceBucket, targetBucket);
        buffers.compute(key, (ignored, existing) -> {
            BufferedBatch batch = existing != null ? existing : new BufferedBatch(sourceBucket, targetBucket, logging);
            batch.lines.add(line);
            batch.accountId = accountId;
            batch.sourceRegion = sourceRegion;
            if (batch.oldestEventTime == null || eventTime.isBefore(batch.oldestEventTime)) {
                batch.oldestEventTime = eventTime;
            }
            return batch;
        });
    }

    private void flushAllBuffers() {
        for (String key : List.copyOf(buffers.keySet())) {
            BufferedBatch batch = buffers.remove(key);
            if (batch == null || batch.lines.isEmpty()) {
                continue;
            }
            deliverBatch(batch);
        }
    }

    private void deliverBatch(BufferedBatch batch) {
        String payload = String.join("", batch.lines);
        Instant eventTime = batch.oldestEventTime != null ? batch.oldestEventTime : Instant.now();
        deliverLine(batch.sourceBucket, batch.targetBucket, batch.logging, payload,
                eventTime, batch.sourceRegion, batch.accountId);
    }

    private void deliverLine(String sourceBucket,
                             String targetBucket,
                             LoggingConfiguration logging,
                             String payload,
                             Instant eventTime,
                             String sourceRegion,
                             String accountId) {
        Instant deliveryTime = Instant.now();
        String logObjectKey = S3AccessLogKeyBuilder.buildObjectKey(
                logging, accountId, sourceRegion, sourceBucket, eventTime, deliveryTime);

        try {
            DELIVERING.set(true);
            if (config.services().iam().enforcementEnabled()) {
                targetAuthorizer.authorizeS3AccessLogDelivery(
                        sourceBucket, targetBucket, logObjectKey, sourceRegion, accountId);
            }
            s3Service.putAccessLogObject(targetBucket, logObjectKey, payload.getBytes(StandardCharsets.UTF_8));
            cloudTrailRecorder.recordAwsServiceEvent(sourceRegion, "s3.amazonaws.com", "PutObject",
                    "s3.amazonaws.com", Map.of("bucketName", targetBucket, "key", logObjectKey));
        } catch (AwsException e) {
            LOG.warnv("Failed to deliver S3 access log for bucket {0}: {1}", sourceBucket, e.getMessage());
        } catch (Exception e) {
            LOG.warnv("Failed to deliver S3 access log for bucket {0}: {1}", sourceBucket, e.getMessage());
        } finally {
            DELIVERING.set(false);
        }
    }

    private boolean isScheduledDelivery() {
        String mode = config.services().s3().accessLogDeliveryMode();
        if (mode == null || mode.isBlank()) {
            return false;
        }
        String normalized = mode.trim().toLowerCase(Locale.ROOT);
        return "scheduled".equals(normalized)
                || "aws".equals(normalized)
                || "normal".equals(normalized);
    }

    private int deliveryIntervalSeconds() {
        int seconds = config.services().s3().accessLogDeliveryIntervalSeconds();
        return seconds > 0 ? seconds : 3600;
    }

    private static String bufferKey(String sourceBucket, String targetBucket) {
        return sourceBucket + '\0' + targetBucket;
    }

    private static final class BufferedBatch {
        private final String sourceBucket;
        private final String targetBucket;
        private final LoggingConfiguration logging;
        private final List<String> lines = new ArrayList<>();
        private Instant oldestEventTime;
        private String sourceRegion;
        private String accountId;

        private BufferedBatch(String sourceBucket, String targetBucket, LoggingConfiguration logging) {
            this.sourceBucket = sourceBucket;
            this.targetBucket = targetBucket;
            this.logging = logging;
        }
    }
}
