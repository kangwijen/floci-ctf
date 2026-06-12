package io.github.hectorvent.floci.services.ec2.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class FlowLogUnsuccessfulItem {

    private String resourceId;
    private String errorCode;
    private String errorMessage;

    public FlowLogUnsuccessfulItem() {}

    public FlowLogUnsuccessfulItem(String resourceId, String errorCode, String errorMessage) {
        this.resourceId = resourceId;
        this.errorCode = errorCode;
        this.errorMessage = errorMessage;
    }

    public String getResourceId() { return resourceId; }
    public void setResourceId(String resourceId) { this.resourceId = resourceId; }

    public String getErrorCode() { return errorCode; }
    public void setErrorCode(String errorCode) { this.errorCode = errorCode; }

    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}
