package io.github.hectorvent.floci.services.iam.model;

/**
 * STS {@code GetCallerIdentity} result fields.
 */
public record CallerIdentity(String userId, String account, String arn) {

    public static CallerIdentity root(String accountId) {
        return new CallerIdentity(accountId, accountId, "arn:aws:iam::" + accountId + ":root");
    }
}
