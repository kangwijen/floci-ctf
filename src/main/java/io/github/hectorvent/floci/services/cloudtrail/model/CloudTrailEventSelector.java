package io.github.hectorvent.floci.services.cloudtrail.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CloudTrailEventSelector {
    private String readWriteType;
    private boolean includeManagementEvents;
    private List<CloudTrailDataResource> dataResources;
    private List<String> excludeManagementEventSources;

    public CloudTrailEventSelector() {
        this.dataResources = new ArrayList<>();
        this.excludeManagementEventSources = new ArrayList<>();
    }

    public String getReadWriteType() {
        return readWriteType;
    }

    public void setReadWriteType(String readWriteType) {
        this.readWriteType = readWriteType;
    }

    public boolean isIncludeManagementEvents() {
        return includeManagementEvents;
    }

    public void setIncludeManagementEvents(boolean includeManagementEvents) {
        this.includeManagementEvents = includeManagementEvents;
    }

    public List<CloudTrailDataResource> getDataResources() {
        return dataResources;
    }

    public void setDataResources(List<CloudTrailDataResource> dataResources) {
        this.dataResources = dataResources == null ? new ArrayList<>() : new ArrayList<>(dataResources);
    }

    public List<String> getExcludeManagementEventSources() {
        return excludeManagementEventSources;
    }

    public void setExcludeManagementEventSources(List<String> excludeManagementEventSources) {
        this.excludeManagementEventSources = excludeManagementEventSources == null
                ? new ArrayList<>()
                : new ArrayList<>(excludeManagementEventSources);
    }
}
