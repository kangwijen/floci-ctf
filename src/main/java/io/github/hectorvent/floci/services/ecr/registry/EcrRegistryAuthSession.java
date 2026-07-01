package io.github.hectorvent.floci.services.ecr.registry;

import java.time.Instant;

/**
 * Caller identity bound to an ECR registry docker-login token issued by
 * {@link io.github.hectorvent.floci.services.ecr.EcrService#getAuthorizationToken(String)}.
 */
public record EcrRegistryAuthSession(
        String principalArn,
        String accessKeyId,
        String accountId,
        String region,
        Instant expiresAt) {

    public boolean isExpired(Instant now) {
        return expiresAt != null && !expiresAt.isAfter(now);
    }
}
