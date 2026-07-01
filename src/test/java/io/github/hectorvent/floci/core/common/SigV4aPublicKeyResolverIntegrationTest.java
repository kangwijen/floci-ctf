package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.testsupport.SigV4aValidationProfile;
import io.quarkus.test.junit.QuarkusTest;
import io.quarkus.test.junit.TestProfile;
import jakarta.inject.Inject;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertTrue;

@QuarkusTest
@TestProfile(SigV4aValidationProfile.class)
class SigV4aPublicKeyResolverIntegrationTest {

    @Inject
    SigV4aPublicKeyResolver resolver;

    @Test
    void resolvesConfiguredTestAccessKey() {
        assertTrue(resolver.resolve(SigV4aTestSupport.ACCESS_KEY_ID).isPresent());
    }
}
