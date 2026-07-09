package io.github.hectorvent.floci.services.securityhub.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import io.quarkus.runtime.annotations.RegisterForReflection;

@JsonInclude(JsonInclude.Include.NON_NULL)
@RegisterForReflection(targets = {
        AwsSecurityFindingFormat.Severity.class,
        AwsSecurityFindingFormat.Compliance.class,
        AwsSecurityFindingFormat.Workflow.class
})
public class AwsSecurityFindingFormat {

    @JsonProperty("SchemaVersion")
    private String schemaVersion;

    @JsonProperty("Id")
    private String id;

    @JsonProperty("ProductArn")
    private String productArn;

    @JsonProperty("GeneratorId")
    private String generatorId;

    @JsonProperty("AwsAccountId")
    private String awsAccountId;

    @JsonProperty("Region")
    private String region;

    @JsonProperty("Title")
    private String title;

    @JsonProperty("Description")
    private String description;

    @JsonProperty("Severity")
    private Severity severity;

    @JsonProperty("Compliance")
    private Compliance compliance;

    @JsonProperty("Workflow")
    private Workflow workflow;

    @JsonProperty("CreatedAt")
    private String createdAt;

    @JsonProperty("UpdatedAt")
    private String updatedAt;

    @JsonProperty("RecordState")
    private String recordState;

    public String getSchemaVersion() {
        return schemaVersion;
    }

    public void setSchemaVersion(String schemaVersion) {
        this.schemaVersion = schemaVersion;
    }

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public String getProductArn() {
        return productArn;
    }

    public void setProductArn(String productArn) {
        this.productArn = productArn;
    }

    public String getGeneratorId() {
        return generatorId;
    }

    public void setGeneratorId(String generatorId) {
        this.generatorId = generatorId;
    }

    public String getAwsAccountId() {
        return awsAccountId;
    }

    public void setAwsAccountId(String awsAccountId) {
        this.awsAccountId = awsAccountId;
    }

    public String getRegion() {
        return region;
    }

    public void setRegion(String region) {
        this.region = region;
    }

    public String getTitle() {
        return title;
    }

    public void setTitle(String title) {
        this.title = title;
    }

    public String getDescription() {
        return description;
    }

    public void setDescription(String description) {
        this.description = description;
    }

    public Severity getSeverity() {
        return severity;
    }

    public void setSeverity(Severity severity) {
        this.severity = severity;
    }

    public Compliance getCompliance() {
        return compliance;
    }

    public void setCompliance(Compliance compliance) {
        this.compliance = compliance;
    }

    public Workflow getWorkflow() {
        return workflow;
    }

    public void setWorkflow(Workflow workflow) {
        this.workflow = workflow;
    }

    public String getCreatedAt() {
        return createdAt;
    }

    public void setCreatedAt(String createdAt) {
        this.createdAt = createdAt;
    }

    public String getUpdatedAt() {
        return updatedAt;
    }

    public void setUpdatedAt(String updatedAt) {
        this.updatedAt = updatedAt;
    }

    public String getRecordState() {
        return recordState;
    }

    public void setRecordState(String recordState) {
        this.recordState = recordState;
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Severity {
        @JsonProperty("Label")
        private String label;

        @JsonProperty("Normalized")
        private Integer normalized;

        @JsonProperty("Product")
        private Double product;

        public String getLabel() {
            return label;
        }

        public void setLabel(String label) {
            this.label = label;
        }

        public Integer getNormalized() {
            return normalized;
        }

        public void setNormalized(Integer normalized) {
            this.normalized = normalized;
        }

        public Double getProduct() {
            return product;
        }

        public void setProduct(Double product) {
            this.product = product;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Compliance {
        @JsonProperty("Status")
        private String status;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }
    }

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public static class Workflow {
        @JsonProperty("Status")
        private String status;

        public String getStatus() {
            return status;
        }

        public void setStatus(String status) {
            this.status = status;
        }
    }
}
