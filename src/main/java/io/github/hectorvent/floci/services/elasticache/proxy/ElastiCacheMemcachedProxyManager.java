package io.github.hectorvent.floci.services.elasticache.proxy;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.io.IOException;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Registry of Memcached AuthProxy instances (one per cache cluster).
 */
@ApplicationScoped
public class ElastiCacheMemcachedProxyManager {

    private static final Logger LOG = Logger.getLogger(ElastiCacheMemcachedProxyManager.class);

    private final SigV4Validator sigV4Validator;
    private final EmulatorConfig config;
    private final ConcurrentHashMap<String, ElastiCacheMemcachedAuthProxy> proxies = new ConcurrentHashMap<>();

    @Inject
    public ElastiCacheMemcachedProxyManager(SigV4Validator sigV4Validator, EmulatorConfig config) {
        this.sigV4Validator = sigV4Validator;
        this.config = config;
    }

    public boolean authRequired() {
        return AuthPosture.from(config).iamEnforced();
    }

    public void startProxy(String clusterId, int proxyPort, String backendHost, int backendPort) {
        ElastiCacheMemcachedAuthProxy proxy = new ElastiCacheMemcachedAuthProxy(
                clusterId, authRequired(), backendHost, backendPort, sigV4Validator);
        try {
            proxy.start(proxyPort);
            proxies.put(clusterId, proxy);
        } catch (IOException e) {
            throw new RuntimeException("Failed to start Memcached proxy for cluster " + clusterId
                    + " on port " + proxyPort, e);
        }
    }

    public void stopProxy(String clusterId) {
        ElastiCacheMemcachedAuthProxy proxy = proxies.remove(clusterId);
        if (proxy != null) {
            proxy.stop();
            LOG.infov("Stopped Memcached proxy for cluster {0}", clusterId);
        }
    }

    public void stopAll() {
        proxies.values().forEach(ElastiCacheMemcachedAuthProxy::stop);
        proxies.clear();
        LOG.info("Stopped all ElastiCache Memcached proxies");
    }
}
