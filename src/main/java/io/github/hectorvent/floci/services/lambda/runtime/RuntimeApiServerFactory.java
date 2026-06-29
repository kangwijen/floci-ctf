package io.github.hectorvent.floci.services.lambda.runtime;

import io.github.hectorvent.floci.core.common.port.PortAllocator;
import io.vertx.core.Vertx;
import jakarta.annotation.PreDestroy;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Creates RuntimeApiServer instances, each on a unique port.
 */
@ApplicationScoped
public class RuntimeApiServerFactory {

    private static final Logger LOG = Logger.getLogger(RuntimeApiServerFactory.class);

    private final Vertx vertx;
    private final PortAllocator portAllocator;
    private final Set<RuntimeApiServer> activeServers = ConcurrentHashMap.newKeySet();

    @Inject
    public RuntimeApiServerFactory(Vertx vertx, PortAllocator portAllocator) {
        this.vertx = vertx;
        this.portAllocator = portAllocator;
    }

    public RuntimeApiServer create() {
        IllegalStateException exhausted = null;
        while (true) {
            int port;
            try {
                port = portAllocator.allocate();
            } catch (IllegalStateException e) {
                exhausted = e;
                break;
            }

            try {
                RuntimeApiServer server = new RuntimeApiServer(vertx, port);
                server.start().get(10, TimeUnit.SECONDS);
                activeServers.add(server);
                LOG.debugv("Created RuntimeApiServer on port {0}", String.valueOf(port));
                return server;
            } catch (InterruptedException e) {
                portAllocator.release(port);
                Thread.currentThread().interrupt();
                throw new RuntimeException("Interrupted while starting RuntimeApiServer", e);
            } catch (ExecutionException | TimeoutException e) {
                portAllocator.release(port);
                LOG.debugv(e, "RuntimeApiServer failed to bind on port {0}, trying next port", String.valueOf(port));
            }
        }

        if (exhausted != null) {
            throw exhausted;
        }
        throw new RuntimeException("Failed to start RuntimeApiServer: no bindable port in configured range");
    }

    public void release(RuntimeApiServer server) {
        activeServers.remove(server);
        portAllocator.release(server.getPort());
    }

    @PreDestroy
    void shutdown() {
        for (RuntimeApiServer server : new ArrayList<>(activeServers)) {
            try {
                server.stop().get(5, TimeUnit.SECONDS);
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
            } catch (ExecutionException | TimeoutException e) {
                LOG.warnv(e, "RuntimeApiServer on port {0} did not stop cleanly during factory shutdown",
                        String.valueOf(server.getPort()));
            } finally {
                release(server);
            }
        }
    }
}
