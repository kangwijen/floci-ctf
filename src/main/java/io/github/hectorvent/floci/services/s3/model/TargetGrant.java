package io.github.hectorvent.floci.services.s3.model;

import io.quarkus.runtime.annotations.RegisterForReflection;

@RegisterForReflection
public class TargetGrant {

    private String granteeId;
    private String granteeDisplayName;
    private String granteeType;
    private String permission;

    public String getGranteeId() {
        return granteeId;
    }

    public void setGranteeId(String granteeId) {
        this.granteeId = granteeId;
    }

    public String getGranteeDisplayName() {
        return granteeDisplayName;
    }

    public void setGranteeDisplayName(String granteeDisplayName) {
        this.granteeDisplayName = granteeDisplayName;
    }

    public String getGranteeType() {
        return granteeType;
    }

    public void setGranteeType(String granteeType) {
        this.granteeType = granteeType;
    }

    public String getPermission() {
        return permission;
    }

    public void setPermission(String permission) {
        this.permission = permission;
    }
}
