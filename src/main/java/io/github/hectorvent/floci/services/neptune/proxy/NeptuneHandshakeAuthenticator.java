package io.github.hectorvent.floci.services.neptune.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import io.github.hectorvent.floci.services.iam.IamService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CTF bind for Neptune Gremlin WebSocket upgrades: require an AWS4 Authorization header
 * whose Credential access key is known to Floci (operator root or IAM key). Full canonical
 * request re-signing of the upgrade is not required for the fail-closed bind.
 */
@ApplicationScoped
public class NeptuneHandshakeAuthenticator implements NeptuneGremlinProxy.HandshakeAuthenticator {

    private static final Logger LOG = Logger.getLogger(NeptuneHandshakeAuthenticator.class);
    private static final Pattern CREDENTIAL = Pattern.compile(
            "Credential=([A-Z0-9]{16,})/", Pattern.CASE_INSENSITIVE);

    private final IamService iamService;
    private final EmulatorConfig config;
    private final boolean required;

    @Inject
    public NeptuneHandshakeAuthenticator(IamService iamService, EmulatorConfig config) {
        this.iamService = iamService;
        this.config = config;
        this.required = AuthPosture.from(config).iamEnforced();
    }

    NeptuneHandshakeAuthenticator(IamService iamService, EmulatorConfig config, boolean required) {
        this.iamService = iamService;
        this.config = config;
        this.required = required;
    }

    public boolean isRequired() {
        return required;
    }

    @Override
    public boolean accept(String headersText, String clusterId) {
        if (!required) {
            return true;
        }
        if (headersText == null || headersText.isBlank()) {
            return false;
        }
        String lower = headersText.toLowerCase(Locale.ROOT);
        if (!lower.contains("authorization:") || !lower.contains("aws4-hmac-sha256")) {
            LOG.debugv("Neptune handshake missing AWS4 Authorization for cluster {0}", clusterId);
            return false;
        }
        Matcher matcher = CREDENTIAL.matcher(headersText);
        if (!matcher.find()) {
            LOG.debugv("Neptune handshake missing Credential= for cluster {0}", clusterId);
            return false;
        }
        String accessKeyId = matcher.group(1);
        if (iamService.findSecretKey(accessKeyId).isPresent()) {
            return true;
        }
        Optional<String> root = config.auth().rootAccessKeyId();
        if (root.filter(accessKeyId::equals).isPresent()
                && config.auth().resolveRootSecretAccessKey().isPresent()) {
            return true;
        }
        LOG.debugv("Neptune handshake unknown access key for cluster {0}", clusterId);
        return false;
    }
}
