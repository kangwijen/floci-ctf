package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.config.EmulatorConfig;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

@ApplicationScoped
public class AccountResolver {

    private static final Pattern AKID_PATTERN = Pattern.compile("Credential=([^/]+)/");

    private final String defaultAccountId;

    @Inject
    public AccountResolver(EmulatorConfig config) {
        this.defaultAccountId = config.defaultAccountId();
    }

    /**
     * Returns the account ID for the given Authorization header.
     * When the access key ID is exactly 12 digits it is used directly as the account ID,
     * matching LocalStack's multi-account convention. Any other key format falls back to
     * the configured default account.
     */
    public String resolve(String authorizationHeader) {
        String akid = extractAccessKeyId(authorizationHeader);
        if (akid != null && akid.matches("\\d{12}")) {
            return akid;
        }
        return defaultAccountId;
    }

    /**
     * Extracts the raw access key ID from an AWS SigV4 Authorization header,
     * or returns null if the header is absent or does not contain a Credential field.
     */
    public String extractAccessKeyId(String authorizationHeader) {
        if (authorizationHeader == null) {
            return null;
        }
        Matcher m = AKID_PATTERN.matcher(authorizationHeader);
        return m.find() ? m.group(1) : null;
    }

    /**
     * Extracts the access key id from an {@code X-Amz-Credential} query value
     * ({@code AKID/date/region/service/aws4_request}).
     */
    public String extractAccessKeyIdFromCredential(String credential) {
        if (credential == null || credential.isBlank()) {
            return null;
        }
        int slash = credential.indexOf('/');
        return slash > 0 ? credential.substring(0, slash) : credential;
    }

    public String defaultAccountId() {
        return defaultAccountId;
    }
}
