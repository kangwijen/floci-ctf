package io.github.hectorvent.floci.core.common.auth;

/**
 * IAM resource extraction result. Distinguishes a concrete (or intentional {@code *}) ARN from
 * an extraction failure so CTF/strict enforcement can deny {@link Unresolved} instead of treating
 * it like an intentional wildcard.
 */
public sealed interface ResourceRef {

    /**
     * Wire token embedded in String-based ARN builder APIs when extraction fails.
     * Distinct from intentional {@code *} (AWS Resource:{@code *} / catalog-only scopes).
     */
    String UNRESOLVED_PREFIX = "arn:floci:unresolved:::";

    record Arn(String value) implements ResourceRef {
        public Arn {
            if (value == null || value.isBlank()) {
                throw new IllegalArgumentException("ARN value required");
            }
        }
    }

    record Unresolved(String reason) implements ResourceRef {
        public Unresolved {
            if (reason == null || reason.isBlank()) {
                reason = "extraction-failed";
            }
        }
    }

    static ResourceRef arn(String value) {
        return new Arn(value);
    }

    static ResourceRef unresolved(String reason) {
        return new Unresolved(reason);
    }

    static String unresolvedToken(String reason) {
        String safe = (reason == null || reason.isBlank()) ? "extraction-failed" : reason.trim();
        return UNRESOLVED_PREFIX + safe;
    }

    static boolean isUnresolvedToken(String value) {
        return value != null && value.startsWith(UNRESOLVED_PREFIX);
    }

    static ResourceRef fromBuilt(String value) {
        if (value == null) {
            return new Unresolved("null");
        }
        if (isUnresolvedToken(value)) {
            return new Unresolved(value.substring(UNRESOLVED_PREFIX.length()));
        }
        return new Arn(value);
    }

    default boolean isUnresolved() {
        return this instanceof Unresolved;
    }
}
