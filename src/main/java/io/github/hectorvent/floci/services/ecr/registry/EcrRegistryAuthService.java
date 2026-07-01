package io.github.hectorvent.floci.services.ecr.registry;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Optional;

/**
 * Parses docker registry Basic auth ({@code AWS:password}) and validates issued tokens.
 */
@ApplicationScoped
public class EcrRegistryAuthService {

    private final EcrRegistryAuthTokenStore tokenStore;

    @Inject
    public EcrRegistryAuthService(EcrRegistryAuthTokenStore tokenStore) {
        this.tokenStore = tokenStore;
    }

    public Optional<EcrRegistryAuthSession> authenticate(String authorizationHeader) {
        Optional<String> password = parseBasicPassword(authorizationHeader);
        if (password.isEmpty()) {
            return Optional.empty();
        }
        return tokenStore.validate(password.get());
    }

    /**
     * Extracts the password segment from {@code Authorization: Basic base64(AWS:token)}.
     */
    public Optional<String> parseBasicPassword(String authorizationHeader) {
        if (authorizationHeader == null || authorizationHeader.isBlank()) {
            return Optional.empty();
        }
        if (!authorizationHeader.regionMatches(true, 0, "Basic ", 0, 6)) {
            return Optional.empty();
        }
        String encoded = authorizationHeader.substring(6).trim();
        if (encoded.isEmpty()) {
            return Optional.empty();
        }
        String decoded;
        try {
            decoded = new String(Base64.getDecoder().decode(encoded), StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            return Optional.empty();
        }
        if (!decoded.startsWith("AWS:")) {
            return Optional.empty();
        }
        String password = decoded.substring(4);
        if (password.isBlank()) {
            return Optional.empty();
        }
        return Optional.of(password);
    }
}
