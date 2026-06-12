package io.github.hectorvent.floci.services.configservice.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
public class ConfigurationItemHistory {

    private List<ConfigurationItem> items = new ArrayList<>();

    public ConfigurationItemHistory() {
    }

    public List<ConfigurationItem> getItems() {
        return items;
    }

    public void setItems(List<ConfigurationItem> items) {
        this.items = items != null ? items : new ArrayList<>();
    }
}
