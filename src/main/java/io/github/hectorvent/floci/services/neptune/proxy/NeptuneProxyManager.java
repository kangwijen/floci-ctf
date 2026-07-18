package io.github.hectorvent.floci.services.neptune.proxy;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of all active Neptune Gremlin proxies. One proxy per DB cluster.
 */
@ApplicationScoped
public class NeptuneProxyManager {

    private static final Logger LOG = Logger.getLogger(NeptuneProxyManager.class);

    private final NeptuneHandshakeAuthenticator handshakeAuthenticator;
    private final ConcurrentHashMap<String, NeptuneGremlinProxy> proxies = new ConcurrentHashMap<>();

    @Inject
    public NeptuneProxyManager(NeptuneHandshakeAuthenticator handshakeAuthenticator) {
        this.handshakeAuthenticator = handshakeAuthenticator;
    }

    public void startProxy(String clusterId, int proxyPort, String backendHost, int backendPort) {
        NeptuneGremlinProxy.HandshakeAuthenticator auth =
                handshakeAuthenticator.isRequired() ? handshakeAuthenticator : null;
        NeptuneGremlinProxy proxy = new NeptuneGremlinProxy(clusterId, backendHost, backendPort, auth);
        try {
            proxy.start(proxyPort);
            proxies.put(clusterId, proxy);
        } catch (IOException e) {
            throw new RuntimeException("Failed to start Gremlin proxy for cluster " + clusterId
                    + " on port " + proxyPort, e);
        }
    }

    public void stopProxy(String clusterId) {
        NeptuneGremlinProxy proxy = proxies.remove(clusterId);
        if (proxy != null) {
            proxy.stop();
            LOG.infov("Stopped Gremlin proxy for cluster {0}", clusterId);
        }
    }

    public void stopAll() {
        proxies.values().forEach(NeptuneGremlinProxy::stop);
        proxies.clear();
        LOG.info("Stopped all Neptune Gremlin proxies");
    }
}
