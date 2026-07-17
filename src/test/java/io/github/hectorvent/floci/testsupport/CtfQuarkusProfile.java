package io.github.hectorvent.floci.testsupport;

import io.quarkus.test.junit.QuarkusTestProfile;

/**
 * Activates the named Quarkus {@code ctf} profile ({@code application-ctf.yml}) so AuthPosture
 * matches Compose CTF without repeating FLOCI_* env overrides.
 */
public class CtfQuarkusProfile implements QuarkusTestProfile {

    @Override
    public String getConfigProfile() {
        return "ctf";
    }
}
