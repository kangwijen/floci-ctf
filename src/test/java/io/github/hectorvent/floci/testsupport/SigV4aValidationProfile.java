package io.github.hectorvent.floci.testsupport;

import io.github.hectorvent.floci.core.common.SigV4aTestSupport;
import io.quarkus.test.junit.QuarkusTestProfile;

import java.util.HashMap;
import java.util.Map;

/** SigV4a presign verification on without full IAM enforcement (setup-friendly). */
public class SigV4aValidationProfile implements QuarkusTestProfile {

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> overrides = new HashMap<>();
        overrides.put("floci.auth.validate-signatures", "true");
        overrides.put("floci.services.iam.enforcement-enabled", "false");
        overrides.put("floci.services.iam.strict-enforcement-enabled", "false");
        overrides.put(
                "floci.ctf.sigv4a-signing-public-keys." + SigV4aTestSupport.ACCESS_KEY_ID,
                SigV4aTestSupport.publicKeyPem());
        return overrides;
    }
}
