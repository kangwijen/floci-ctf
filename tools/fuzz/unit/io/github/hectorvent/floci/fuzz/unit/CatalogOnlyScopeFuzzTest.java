package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
import net.jqwik.api.Property;

import java.util.List;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Catalog-only scopes (no {@code ResourceArnBuilder} arm and not documented intentional
 * wildcards) must be exhausted. When new catalog services land, either add a builder arm
 * or move the scope to {@link FuzzCredentialScopes#intentionalWildcardScopes()}.
 */
class CatalogOnlyScopeFuzzTest {

    @Property(tries = 1)
    void catalogOnlyScopesExhausted() {
        List<String> remaining = FuzzCredentialScopes.catalogOnlyScopes();
        assertTrue(
                remaining.isEmpty(),
                () -> "catalog-only gaps remain (add ResourceArnBuilder arm or intentional wildcard): "
                        + remaining);
    }
}
