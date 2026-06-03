package io.github.hectorvent.floci.core.common;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import org.jboss.logging.Logger;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Registry of enabled AWS services based on configuration.
 */
@ApplicationScoped
public class ServiceRegistry {

    private static final Logger LOG = Logger.getLogger(ServiceRegistry.class);

    private final ResolvedServiceCatalog catalog;

    @Inject
    public ServiceRegistry(ResolvedServiceCatalog catalog) {
        this.catalog = catalog;
    }

    public boolean isServiceEnabled(String serviceName) {
        return catalog.byExternalKey(serviceName)
                .map(ServiceDescriptor::enabled)
                .orElse(true);
    }

    public List<String> getEnabledServices() {
        List<String> enabled = new ArrayList<>();
        for (ServiceDescriptor descriptor : catalog.allStatusDescriptors()) {
            if (descriptor.enabled()) {
                enabled.add(descriptor.configKey());
            }
        }
        return enabled;
    }

    /**
     * Returns enabled services for health and info endpoints. Disabled services are omitted so
     * recon does not list APIs that are turned off via {@code FLOCI_SERVICES_*_ENABLED}.
     */
    public Map<String, String> getServices() {
        Map<String, String> services = new LinkedHashMap<>();
        for (ServiceDescriptor descriptor : catalog.allStatusDescriptors()) {
            if (descriptor.enabled()) {
                services.put(descriptor.externalKey(), "running");
            }
        }
        return services;
    }

    public void logEnabledServices() {
        LOG.infov("Enabled services: {0}", getEnabledServices());
    }
}
