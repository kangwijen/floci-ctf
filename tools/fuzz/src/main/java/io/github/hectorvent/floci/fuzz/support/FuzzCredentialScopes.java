package io.github.hectorvent.floci.fuzz.support;

import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Credential scopes for fuzz oracles: {@link ResourceArnBuilder} switch cases plus
 * full emulator catalog entries from {@code ResolvedServiceCatalog}.
 */
public final class FuzzCredentialScopes {

    private FuzzCredentialScopes() {
    }

    /** Full ARN-builder switch list (including multi-label cases). */
    public static List<String> allArnBuilderScopes() {
        return List.of(
                "s3", "lambda", "sqs", "sns", "dynamodb", "kinesis", "secretsmanager", "ssm",
                "kms", "iam", "sts", "ec2", "cloudformation", "elasticache", "rds", "neptune",
                "email", "ses", "sesv2", "monitoring", "elasticloadbalancing", "autoscaling",
                "logs", "events", "states", "ecr", "ecs", "firehose", "cognito-idp",
                "apigateway", "execute-api", "glue", "athena", "es", "servicediscovery",
                "appsync", "eks", "cloudtrail", "guardduty", "config", "rds-data",
                "elasticmapreduce", "wafv2", "securityhub", "apigatewayv2", "scheduler",
                "kafka", "pipes", "codebuild", "codedeploy", "acm", "backup", "route53",
                "cloudfront", "bedrock", "bedrock-runtime", "cur", "bcm-data-exports",
                "transfer", "transcribe", "appconfig", "appconfigdata", "iot", "iotdata",
                "textract", "tagging", "mq", "batch", "lightsail", "memorydb", "codepipeline",
                "elasticbeanstalk", "s3vectors", "docdb"
        );
    }

    /**
     * All SigV4 credential scopes registered in {@code ResolvedServiceCatalog}
     * (includes mocked services without {@code ResourceArnBuilder} cases).
     */
    public static List<String> catalogCredentialScopes() {
        return List.of(
                "ssm", "sqs", "s3", "dynamodb", "sns", "lambda", "apigateway", "execute-api",
                "iam", "kafka", "mq", "sts", "elasticache", "memorydb", "rds", "rds-data",
                "neptune", "docdb", "events", "servicediscovery", "elasticmapreduce", "wafv2",
                "scheduler", "logs", "monitoring", "secretsmanager", "apigatewayv2", "kinesis",
                "kms", "cognito-idp", "states", "cloudformation", "acm", "athena", "glue",
                "firehose", "email", "ses", "sesv2", "es", "ec2", "ecs", "appconfig",
                "appconfigdata", "ecr", "tagging", "bedrock", "bedrock-runtime", "eks", "pipes",
                "elasticloadbalancing", "codebuild", "batch", "codedeploy", "codepipeline",
                "config", "cloudtrail", "lightsail", "cloudcontrolapi", "guardduty", "securityhub",
                "autoscaling", "elasticbeanstalk", "backup", "ec2messages", "transfer", "route53",
                "textract", "pricing", "api.pricing", "transcribe", "ce", "cur", "bcm-data-exports",
                "cloudfront", "appsync", "s3vectors", "iot", "iotdata"
        );
    }

    /** Catalog scopes with no {@code ResourceArnBuilder} switch arm (protocol-only services). */
    public static List<String> nonArnBuilderCatalogScopes() {
        Set<String> arnBuilder = Set.copyOf(allArnBuilderScopes());
        return catalogCredentialScopes().stream()
                .filter(scope -> !arnBuilder.contains(scope))
                .collect(Collectors.toList());
    }

    /**
     * Documented intentional {@code *} IAM resources (AGENTS.md): no per-resource ARN builder arm.
     */
    public static List<String> intentionalWildcardScopes() {
        return List.of("ce", "pricing", "api.pricing", "ec2messages", "cloudcontrolapi");
    }

    /** Catalog-only scopes excluding documented intentional wildcards. */
    public static List<String> catalogOnlyScopes() {
        Set<String> intentional = Set.copyOf(intentionalWildcardScopes());
        return nonArnBuilderCatalogScopes().stream()
                .filter(scope -> !intentional.contains(scope))
                .collect(Collectors.toList());
    }

    /** REST paths for thin-corpus services (batch, amazonmq, s3vectors) from controllers. */
    public static List<String> thinRestServicePaths() {
        return List.of(
                "/v1/createcomputeenvironment",
                "/v1/describecomputeenvironments",
                "/v1/createjobqueue",
                "/v1/describejobqueues",
                "/v1/registerjobdefinition",
                "/v1/deregisterjobdefinition",
                "/v1/describejobdefinitions",
                "/v1/submitjob",
                "/v1/describejobs",
                "/v1/listjobs",
                "/v1/brokers",
                "/v1/brokers/broker-1",
                "/v1/brokers/broker-1/reboot",
                "/v1/brokers/broker-1/users",
                "/v1/brokers/broker-1/users/alice",
                "/CreateVectorBucket",
                "/GetVectorBucket",
                "/ListVectorBuckets",
                "/DeleteVectorBucket",
                "/CreateIndex",
                "/GetIndex",
                "/ListIndexes",
                "/DeleteIndex",
                "/PutVectors",
                "/GetVectors",
                "/DeleteVectors",
                "/QueryVectors"
        );
    }

    /** Intentional transparent TCP data-plane relays (no wire SigV4 validator under CTF). */
    public static List<String> openDataPlaneTcpScopes() {
        return List.of("neptune", "docdb");
    }

    /** Expected ARN service segment for namespace oracles (aliases map to canonical). */
    public static String expectedArnService(String scope) {
        return switch (scope) {
            case "email", "ses", "sesv2" -> "ses";
            case "neptune", "rds-data", "docdb" -> "rds";
            case "monitoring" -> "cloudwatch";
            case "es" -> "es";
            case "servicediscovery" -> "servicediscovery";
            case "config" -> "config";
            case "elasticmapreduce" -> "elasticmapreduce";
            case "kafka" -> "kafka";
            case "bcm-data-exports" -> "bcm-data-exports";
            case "bedrock", "bedrock-runtime" -> "bedrock";
            case "iot", "iotdata" -> "iot";
            case "appconfigdata" -> "appconfig";
            case "apigateway", "apigatewayv2" -> "apigateway";
            case "execute-api" -> "execute-api";
            case "tagging" -> null; // multi-ARN / wildcard
            default -> scope;
        };
    }

    /** REST route services from IamActionRegistry RULES and catalog controllers. */
    public static List<String> restRouteServices() {
        return List.of(
                "execute-api", "s3", "lambda", "rds-data", "apigateway", "apigatewayv2",
                "appsync", "eks", "scheduler", "pipes", "kafka", "cloudfront", "bedrock",
                "bedrock-runtime", "appconfig", "appconfigdata", "backup", "route53",
                "iot", "iotdata", "es", "batch", "mq", "s3vectors"
        );
    }
}
