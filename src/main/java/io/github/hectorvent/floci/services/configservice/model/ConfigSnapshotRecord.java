package io.github.hectorvent.floci.services.configservice.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConfigSnapshotRecord(
        @JsonProperty("snapshotId") String snapshotId,
        @JsonProperty("region") String region,
        @JsonProperty("s3BucketName") String s3BucketName,
        @JsonProperty("s3Key") String s3Key,
        @JsonProperty("captureTime") Double captureTime,
        @JsonProperty("configurationItemCount") int configurationItemCount) {
}
