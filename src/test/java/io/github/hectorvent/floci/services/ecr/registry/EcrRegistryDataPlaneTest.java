package io.github.hectorvent.floci.services.ecr.registry;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class EcrRegistryDataPlaneTest {

    @Test
    void rewriteRegistryLocation_remapsInternalRegistryHostToClientAuthority() {
        String location = "http://172.18.0.3:5000/v2/000000000000/us-east-1/probe/ecr-smoke/blobs/uploads/uuid?_state=abc";
        String rewritten = EcrRegistryDataPlane.rewriteRegistryLocation(
                location,
                "localhost:5106",
                "http://172.18.0.3:5000",
                false);
        assertEquals(
                "http://localhost:5106/v2/000000000000/us-east-1/probe/ecr-smoke/blobs/uploads/uuid?_state=abc",
                rewritten);
    }

    @Test
    void rewriteRegistryLocation_rewritesRelativePaths() {
        assertEquals(
                "http://localhost:5100/v2/repo/blobs/uploads/id",
                EcrRegistryDataPlane.rewriteRegistryLocation(
                        "/v2/repo/blobs/uploads/id",
                        "localhost:5100",
                        "http://172.18.0.3:5000",
                        false));
    }

    @Test
    void rewriteRegistryLocation_leavesExternalLocationsUntouched() {
        String location = "https://example.com/v2/repo/blobs/uploads/id";
        assertEquals(location, EcrRegistryDataPlane.rewriteRegistryLocation(
                location, "localhost:5100", "http://172.18.0.3:5000", false));
    }
}
