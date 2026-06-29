package io.github.hectorvent.floci.services.iam.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.time.Instant;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class SessionCredential {

    private String accessKeyId;
    private String secretAccessKey;
    private String roleArn;
    private Instant expiration;
    /** Inline session policy passed to AssumeRole/GetFederationToken — further restricts role policies. */
    private String sessionPolicyDocument;
    /** Values returned by {@code sts:GetCallerIdentity} for this session, when set at issuance. */
    private String callerIdentityUserId;
    private String callerIdentityArn;
    /** Long-term access key that issued this session ({@code GetSessionToken}); used for policy intersection. */
    private String parentAccessKeyId;
    /** {@code x-amz-security-token} value returned with temporary credentials. */
    private String sessionToken;
    /**
     * Account of the caller that minted this session, captured at mint time. Used to route
     * temporary credentials that carry no role ARN (e.g. GetSessionToken) back to the caller.
     */
    private String originAccountId;

    public SessionCredential() {}

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
    }

    public SessionCredential(String accessKeyId, String roleArn, Instant expiration, String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
    }

    public SessionCredential(String accessKeyId, String secretAccessKey, String roleArn, Instant expiration,
                              String sessionPolicyDocument, String originAccountId) {
        this.accessKeyId = accessKeyId;
        this.secretAccessKey = secretAccessKey;
        this.roleArn = roleArn;
        this.expiration = expiration;
        this.sessionPolicyDocument = sessionPolicyDocument;
        this.originAccountId = originAccountId;
    }

    public String getAccessKeyId() { return accessKeyId; }
    public void setAccessKeyId(String accessKeyId) { this.accessKeyId = accessKeyId; }

    public String getSecretAccessKey() { return secretAccessKey; }
    public void setSecretAccessKey(String secretAccessKey) { this.secretAccessKey = secretAccessKey; }

    public String getRoleArn() { return roleArn; }
    public void setRoleArn(String roleArn) { this.roleArn = roleArn; }

    public Instant getExpiration() { return expiration; }
    public void setExpiration(Instant expiration) { this.expiration = expiration; }

    public String getSessionPolicyDocument() { return sessionPolicyDocument; }
    public void setSessionPolicyDocument(String sessionPolicyDocument) { this.sessionPolicyDocument = sessionPolicyDocument; }

    public String getCallerIdentityUserId() { return callerIdentityUserId; }
    public void setCallerIdentityUserId(String callerIdentityUserId) {
        this.callerIdentityUserId = callerIdentityUserId;
    }

    public String getCallerIdentityArn() { return callerIdentityArn; }
    public void setCallerIdentityArn(String callerIdentityArn) {
        this.callerIdentityArn = callerIdentityArn;
    }

    public String getParentAccessKeyId() { return parentAccessKeyId; }
    public void setParentAccessKeyId(String parentAccessKeyId) {
        this.parentAccessKeyId = parentAccessKeyId;
    }

    public String getSessionToken() { return sessionToken; }
    public void setSessionToken(String sessionToken) { this.sessionToken = sessionToken; }

    public String getOriginAccountId() { return originAccountId; }
    public void setOriginAccountId(String originAccountId) { this.originAccountId = originAccountId; }
}
