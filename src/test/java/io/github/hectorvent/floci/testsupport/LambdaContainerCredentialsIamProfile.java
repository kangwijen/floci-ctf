package io.github.hectorvent.floci.testsupport;

import java.util.HashMap;
import java.util.Map;

/**
 * CTF Compose parity plus dedicated container credential ports for integration tests.
 */
public class LambdaContainerCredentialsIamProfile extends CtfComposeParityProfile {

    public static final int LAMBDA_CREDS_PORT = 59171;
    public static final int ECS_CREDS_PORT = 59170;
    public static final int CODEBUILD_CREDS_PORT = 59172;

    @Override
    public Map<String, String> getConfigOverrides() {
        Map<String, String> overrides = new HashMap<>(super.getConfigOverrides());
        overrides.put("floci.services.lambda.container-credentials-port", String.valueOf(LAMBDA_CREDS_PORT));
        overrides.put("floci.services.ecs.container-credentials-port", String.valueOf(ECS_CREDS_PORT));
        overrides.put("floci.services.codebuild.container-credentials-port", String.valueOf(CODEBUILD_CREDS_PORT));
        return overrides;
    }
}
