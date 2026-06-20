package io.github.hectorvent.floci.services.cloudtrail.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonInclude;
import io.quarkus.runtime.annotations.RegisterForReflection;

import java.util.ArrayList;
import java.util.List;

@RegisterForReflection
@JsonIgnoreProperties(ignoreUnknown = true)
@JsonInclude(JsonInclude.Include.NON_NULL)
public class CloudTrailAdvancedFieldSelector {
    private String field;
    private List<String> equals;
    private List<String> notEquals;

    public CloudTrailAdvancedFieldSelector() {
        this.equals = new ArrayList<>();
        this.notEquals = new ArrayList<>();
    }

    public String getField() {
        return field;
    }

    public void setField(String field) {
        this.field = field;
    }

    public List<String> getEquals() {
        return equals;
    }

    public void setEquals(List<String> equals) {
        this.equals = equals == null ? new ArrayList<>() : new ArrayList<>(equals);
    }

    public List<String> getNotEquals() {
        return notEquals;
    }

    public void setNotEquals(List<String> notEquals) {
        this.notEquals = notEquals == null ? new ArrayList<>() : new ArrayList<>(notEquals);
    }
}
