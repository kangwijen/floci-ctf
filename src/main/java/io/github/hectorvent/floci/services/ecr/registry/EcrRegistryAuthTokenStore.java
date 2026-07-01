package io.github.hectorvent.floci.services.ecr.registry;

import jakarta.enterprise.context.ApplicationScoped;

import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.Optional;
import java.util.concurrent.ConcurrentHashMap;

/**
 * In-memory store for short-lived ECR registry docker-login passwords.
 */
@ApplicationScoped
public class EcrRegistryAuthTokenStore {

    private static final SecureRandom RANDOM = new SecureRandom();

    private final ConcurrentHashMap<String, EcrRegistryAuthSession> sessions = new ConcurrentHashMap<>();

    /**
     * Issues a new random token bound to {@code session} and returns the raw password value
     * (the segment after {@code AWS:} in docker Basic auth).
     */
    public String issue(EcrRegistryAuthSession session) {
        purgeExpired();
        String token = generateToken();
        sessions.put(token, session);
        return token;
    }

    public Optional<EcrRegistryAuthSession> validate(String token) {
        if (token == null || token.isBlank()) {
            return Optional.empty();
        }
        EcrRegistryAuthSession session = sessions.get(token);
        if (session == null) {
            return Optional.empty();
        }
        if (session.isExpired(Instant.now())) {
            sessions.remove(token);
            return Optional.empty();
        }
        return Optional.of(session);
    }

    public void revoke(String token) {
        if (token != null && !token.isBlank()) {
            sessions.remove(token);
        }
    }

    private void purgeExpired() {
        Instant now = Instant.now();
        sessions.entrySet().removeIf(e -> e.getValue().isExpired(now));
    }

    private static String generateToken() {
        byte[] bytes = new byte[32];
        RANDOM.nextBytes(bytes);
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes);
    }
}
