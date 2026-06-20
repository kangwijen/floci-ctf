package io.github.hectorvent.floci.services.cloudtrail.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CloudTrailAdvancedEventSelector {
    private String name;
    private List<CloudTrailAdvancedFieldSelector> fieldSelectors;

    public CloudTrailAdvancedEventSelector() {
        this.fieldSelectors = new ArrayList<>();
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        this.name = name;
    }

    public List<CloudTrailAdvancedFieldSelector> getFieldSelectors() {
        return fieldSelectors;
    }

    public void setFieldSelectors(List<CloudTrailAdvancedFieldSelector> fieldSelectors) {
        this.fieldSelectors = fieldSelectors == null ? new ArrayList<>() : new ArrayList<>(fieldSelectors);
    }
}
