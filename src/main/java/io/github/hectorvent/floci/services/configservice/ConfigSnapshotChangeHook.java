package io.github.hectorvent.floci.services.configservice;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Map;
import java.util.Set;

/**
 * Bridges CloudTrail management events to Config configuration item capture when
 * the recorder is running.
 */
@ApplicationScoped
public class ConfigSnapshotChangeHook {

    private static final Set<String> IAM_USER_MUTATIONS = Set.of(
            "CreateUser", "DeleteUser", "UpdateUser", "TagUser", "UntagUser");
    private static final Set<String> S3_BUCKET_MUTATIONS = Set.of(
            "CreateBucket", "DeleteBucket", "PutBucketTagging", "DeleteBucketTagging",
            "PutBucketVersioning", "PutBucketPolicy");
    private static final Set<String> TRAIL_MUTATIONS = Set.of(
            "CreateTrail", "UpdateTrail", "DeleteTrail", "StartLogging", "StopLogging");

    private final ConfigResourceChangeNotifier notifier;

    @Inject
    public ConfigSnapshotChangeHook(ConfigResourceChangeNotifier notifier) {
        this.notifier = notifier;
    }

    public void onManagementEvent(String region, Map<String, Object> event, int httpStatus) {
        if (httpStatus < 200 || httpStatus >= 300) {
            return;
        }
        if (Boolean.TRUE.equals(event.get("readOnly"))) {
            return;
        }
        String eventSource = stringValue(event.get("eventSource"));
        String eventName = stringValue(event.get("eventName"));
        if (eventSource == null || eventName == null) {
            return;
        }
        Map<?, ?> params = event.get("requestParameters") instanceof Map<?, ?> requestParams
                ? requestParams
                : Map.of();

        if (eventSource.startsWith("iam.") && IAM_USER_MUTATIONS.contains(eventName)) {
            String userName = stringParam(params, "UserName");
            if (userName != null) {
                notifier.notifyResourceChanged(region, "AWS::IAM::User", userName);
            }
            return;
        }
        if (eventSource.startsWith("s3.") && S3_BUCKET_MUTATIONS.contains(eventName)) {
            String bucketName = stringParam(params, "bucketName");
            if (bucketName != null) {
                notifier.notifyResourceChanged(region, "AWS::S3::Bucket", bucketName);
            }
            return;
        }
        if (eventSource.startsWith("cloudtrail.") && TRAIL_MUTATIONS.contains(eventName)) {
            String trailName = stringParam(params, "Name");
            if (trailName == null) {
                trailName = stringParam(params, "name");
            }
            if (trailName != null) {
                notifier.notifyResourceChanged(region, "AWS::CloudTrail::Trail", trailName);
            }
        }
    }

    private static String stringParam(Map<?, ?> params, String key) {
        Object value = params.get(key);
        return value != null ? value.toString() : null;
    }

    private static String stringValue(Object value) {
        return value != null ? value.toString() : null;
    }
}
