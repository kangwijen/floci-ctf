package io.github.hectorvent.floci.core.common.auth;

import org.junit.jupiter.api.Tag;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;

@Tag("security-regression")
class ResourceRefTest {

    @Test
    void unresolvedTokenIsDistinctFromIntentionalStar() {
        String token = ResourceRef.unresolvedToken("lambda-url-unknown");
        assertTrue(ResourceRef.isUnresolvedToken(token));
        assertFalse(ResourceRef.isUnresolvedToken("*"));
        assertFalse(ResourceRef.isUnresolvedToken("arn:aws:lambda:us-east-1:1:function:fn"));
    }

    @Test
    void fromBuiltMapsTokenToUnresolvedAndStarToArn() {
        assertInstanceOf(ResourceRef.Unresolved.class,
                ResourceRef.fromBuilt(ResourceRef.unresolvedToken("tagging-empty")));
        ResourceRef star = ResourceRef.fromBuilt("*");
        assertInstanceOf(ResourceRef.Arn.class, star);
        assertFalse(star.isUnresolved());
        assertEquals("*", ((ResourceRef.Arn) star).value());
    }
}
