package io.github.hectorvent.floci.services.cloudtrail.model;

import java.util.Map;

/**
 * Context for recording in-process AWS API calls (Step Functions, API Gateway, service delivery).
 */
public record InProcessAuditContext(
        String region,
        String eventSource,
        String eventName,
        String credentialScope,
        Map<String, Object> requestParameters,
        String errorCode,
        String invokedBy,
        String executionRoleArn,
        String inScopeSourceArn,
        String issuerType,
        String servicePrincipal,
        Boolean managementEvent,
        String eventCategory) {

    public static Builder builder() {
        return new Builder();
    }

    public static final class Builder {
        private String region;
        private String eventSource;
        private String eventName;
        private String credentialScope;
        private Map<String, Object> requestParameters;
        private String errorCode;
        private String invokedBy;
        private String executionRoleArn;
        private String inScopeSourceArn;
        private String issuerType;
        private String servicePrincipal;
        private Boolean managementEvent;
        private String eventCategory;

        public Builder region(String region) {
            this.region = region;
            return this;
        }

        public Builder eventSource(String eventSource) {
            this.eventSource = eventSource;
            return this;
        }

        public Builder eventName(String eventName) {
            this.eventName = eventName;
            return this;
        }

        public Builder credentialScope(String credentialScope) {
            this.credentialScope = credentialScope;
            return this;
        }

        public Builder requestParameters(Map<String, Object> requestParameters) {
            this.requestParameters = requestParameters;
            return this;
        }

        public Builder errorCode(String errorCode) {
            this.errorCode = errorCode;
            return this;
        }

        public Builder invokedBy(String invokedBy) {
            this.invokedBy = invokedBy;
            return this;
        }

        public Builder executionRoleArn(String executionRoleArn) {
            this.executionRoleArn = executionRoleArn;
            return this;
        }

        public Builder inScopeSourceArn(String inScopeSourceArn) {
            this.inScopeSourceArn = inScopeSourceArn;
            return this;
        }

        public Builder issuerType(String issuerType) {
            this.issuerType = issuerType;
            return this;
        }

        public Builder servicePrincipal(String servicePrincipal) {
            this.servicePrincipal = servicePrincipal;
            return this;
        }

        public Builder managementEvent(Boolean managementEvent) {
            this.managementEvent = managementEvent;
            return this;
        }

        public Builder eventCategory(String eventCategory) {
            this.eventCategory = eventCategory;
            return this;
        }

        public InProcessAuditContext build() {
            return new InProcessAuditContext(
                    region,
                    eventSource,
                    eventName,
                    credentialScope,
                    requestParameters,
                    errorCode,
                    invokedBy,
                    executionRoleArn,
                    inScopeSourceArn,
                    issuerType,
                    servicePrincipal,
                    managementEvent,
                    eventCategory);
        }
    }
}
