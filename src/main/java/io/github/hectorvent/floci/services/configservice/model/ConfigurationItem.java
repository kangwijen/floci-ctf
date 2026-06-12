package io.github.hectorvent.floci.services.configservice.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.Map;

@RegisterForReflection
@JsonInclude(JsonInclude.Include.NON_NULL)
@JsonIgnoreProperties(ignoreUnknown = true)
public record ConfigurationItem(
        @JsonProperty("version") String version,
        @JsonProperty("accountId") String accountId,
        @JsonProperty("configurationItemCaptureTime") Double configurationItemCaptureTime,
        @JsonProperty("configurationItemStatus") String configurationItemStatus,
        @JsonProperty("configurationStateId") String configurationStateId,
        @JsonProperty("arn") String arn,
        @JsonProperty("resourceType") String resourceType,
        @JsonProperty("resourceId") String resourceId,
        @JsonProperty("resourceName") String resourceName,
        @JsonProperty("awsRegion") String awsRegion,
        @JsonProperty("availabilityZone") String availabilityZone,
        @JsonProperty("configuration") Object configuration,
        @JsonProperty("supplementaryConfiguration") Map<String, Object> supplementaryConfiguration,
        @JsonProperty("tags") Map<String, String> tags,
        @JsonProperty("configurationItemMD5Hash") String configurationItemMD5Hash) {
}
