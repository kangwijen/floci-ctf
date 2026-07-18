package io.github.hectorvent.floci.services.docdb.proxy;

import io.github.hectorvent.floci.services.rds.proxy.RdsSigV4Validator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of active DocumentDB AuthProxy instances (one per cluster).
 */
@ApplicationScoped
public class DocDbProxyManager {

    private static final Logger LOG = Logger.getLogger(DocDbProxyManager.class);

    private final RdsSigV4Validator sigV4Validator;
    private final ConcurrentHashMap<String, DocDbAuthProxy> proxies = new ConcurrentHashMap<>();

    @Inject
    public DocDbProxyManager(RdsSigV4Validator sigV4Validator) {
        this.sigV4Validator = sigV4Validator;
    }

    public void startProxy(String clusterId, boolean iamEnabled, int proxyPort,
                           String backendHost, int backendPort,
                           String masterUsername, String masterPassword) {
        DocDbAuthProxy proxy = new DocDbAuthProxy(
                clusterId, iamEnabled, backendHost, backendPort,
                masterUsername, masterPassword, sigV4Validator);
        try {
            proxy.start(proxyPort);
            proxies.put(clusterId, proxy);
        } catch (IOException e) {
            throw new RuntimeException("Failed to start DocumentDB AuthProxy for cluster "
                    + clusterId + " on port " + proxyPort, e);
        }
    }

    public void stopProxy(String clusterId) {
        DocDbAuthProxy proxy = proxies.remove(clusterId);
        if (proxy != null) {
            proxy.stop();
            LOG.infov("Stopped DocumentDB AuthProxy for cluster {0}", clusterId);
        }
    }

    public void stopAll() {
        proxies.values().forEach(DocDbAuthProxy::stop);
        proxies.clear();
        LOG.info("Stopped all DocumentDB AuthProxies");
    }
}
