package io.github.hectorvent.floci.services.securityhub.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

@RegisterForReflection
public class SecurityHubAccount {

    private String hubArn;
    private Instant subscribedAt;
    private boolean autoEnableControls = true;
    private String controlFindingGenerator = "SECURITY_CONTROL";

    public String getHubArn() {
        return hubArn;
    }

    public void setHubArn(String hubArn) {
        this.hubArn = hubArn;
    }

    public Instant getSubscribedAt() {
        return subscribedAt;
    }

    public void setSubscribedAt(Instant subscribedAt) {
        this.subscribedAt = subscribedAt;
    }

    public boolean isAutoEnableControls() {
        return autoEnableControls;
    }

    public void setAutoEnableControls(boolean autoEnableControls) {
        this.autoEnableControls = autoEnableControls;
    }

    public String getControlFindingGenerator() {
        return controlFindingGenerator;
    }

    public void setControlFindingGenerator(String controlFindingGenerator) {
        this.controlFindingGenerator = controlFindingGenerator;
    }
}
