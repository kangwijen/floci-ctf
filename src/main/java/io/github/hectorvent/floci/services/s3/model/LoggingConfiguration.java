package io.github.hectorvent.floci.services.s3.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class LoggingConfiguration {

    private String targetBucket;
    private String targetPrefix;

    public LoggingConfiguration() {
    }

    public LoggingConfiguration(String targetBucket, String targetPrefix) {
        this.targetBucket = targetBucket;
        this.targetPrefix = targetPrefix != null ? targetPrefix : "";
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
}
