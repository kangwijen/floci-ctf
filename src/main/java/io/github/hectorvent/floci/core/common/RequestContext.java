package io.github.hectorvent.floci.core.common;

import jakarta.enterprise.context.RequestScoped;

/**
 * Holds per-request derived values — account ID, region, and the signing access key ID —
 * extracted from the incoming AWS credential and Authorization header. Populated by
 * {@link AccountContextFilter} before any handler runs.
 */
@RequestScoped
public class RequestContext {

    private String accountId;
    private String region;
    private String accessKeyId;

    public String getAccountId() {
        return accountId;
    }

    public void setAccountId(String accountId) {
        this.accountId = accountId;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    /**
     * The SigV4 access key ID (or presigned {@code X-Amz-Credential} access key ID) that signed
     * the current request, or {@code null} for unauthenticated requests. Used by in-process
     * authorization checks (e.g. {@code iam:PassRole}) that need the caller's identity outside
     * the JAX-RS filter chain, including background CloudFormation provisioning threads that run
     * under a synthetic request scope.
     */
    public String getAccessKeyId() {
        return accessKeyId;
    }

    public void setAccessKeyId(String accessKeyId) {
        this.accessKeyId = accessKeyId;
    }
}
