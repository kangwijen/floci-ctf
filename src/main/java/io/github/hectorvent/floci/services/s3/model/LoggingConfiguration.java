package io.github.hectorvent.floci.services.s3.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
public class LoggingConfiguration {

    private String targetBucket;
    private String targetPrefix;
    private List<TargetGrant> targetGrants = new ArrayList<>();
    private TargetObjectKeyFormat targetObjectKeyFormat;

    public LoggingConfiguration() {
    }

    public LoggingConfiguration(String targetBucket, String targetPrefix) {
        this.targetBucket = targetBucket;
        this.targetPrefix = targetPrefix != null ? targetPrefix : "";
        this.targetObjectKeyFormat = TargetObjectKeyFormat.simplePrefix();
    }

    public String getTargetBucket() {
        return targetBucket;
    }

    public void setTargetBucket(String targetBucket) {
        this.targetBucket = targetBucket;
    }

    public String getTargetPrefix() {
        return targetPrefix;
    }

    public void setTargetPrefix(String targetPrefix) {
        this.targetPrefix = targetPrefix;
    }

    public List<TargetGrant> getTargetGrants() {
        return targetGrants;
    }

    public void setTargetGrants(List<TargetGrant> targetGrants) {
        this.targetGrants = targetGrants != null ? targetGrants : new ArrayList<>();
    }

    public TargetObjectKeyFormat getTargetObjectKeyFormat() {
        if (targetObjectKeyFormat == null) {
            targetObjectKeyFormat = TargetObjectKeyFormat.simplePrefix();
        }
        return targetObjectKeyFormat;
    }

    public void setTargetObjectKeyFormat(TargetObjectKeyFormat targetObjectKeyFormat) {
        this.targetObjectKeyFormat = targetObjectKeyFormat != null
                ? targetObjectKeyFormat : TargetObjectKeyFormat.simplePrefix();
    }
}
