package io.github.hectorvent.floci.fuzz.support;

import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Shaped request bodies for ARN / action fuzzing across Floci protocols.
 * Field names follow AWS API shapes used by ResourceArnBuilder.
 */
public final class FuzzBodyGenerators {

    private FuzzBodyGenerators() {
    }

    public static String jsonForScope(String scope, String name) {
        String n = sanitize(name);
        return switch (scope) {
            case "ssm" -> "{\"Name\":\"/" + n + "\"}";
            case "secretsmanager" -> "{\"SecretId\":\"" + n + "\"}";
            case "dynamodb" -> "{\"TableName\":\"" + n + "\"}";
            case "kinesis" -> "{\"StreamName\":\"" + n + "\"}";
            case "kms" -> "{\"KeyId\":\"" + n + "\"}";
            case "sqs" -> "{\"QueueUrl\":\"http://localhost:4566/000000000000/" + n + "\"}";
            case "sns" -> "{\"TopicArn\":\"arn:aws:sns:us-east-1:000000000000:" + n + "\"}";
            case "lambda" -> "{\"FunctionName\":\"" + n + "\"}";
            case "athena" -> "{\"WorkGroup\":\"" + n + "\"}";
            case "states" -> "{\"stateMachineArn\":\"arn:aws:states:us-east-1:000000000000:stateMachine:" + n + "\"}";
            case "events" -> "{\"Name\":\"" + n + "\"}";
            case "logs" -> "{\"logGroupName\":\"/aws/" + n + "\"}";
            case "cloudtrail" -> "{\"Name\":\"" + n + "\"}";
            case "guardduty" -> "{\"DetectorId\":\"" + n + "\"}";
            case "config" -> "{\"ConfigRule\":{\"ConfigRuleName\":\"" + n + "\"}}";
            case "rds-data" -> "{\"resourceArn\":\"arn:aws:rds:us-east-1:000000000000:cluster:" + n + "\"}";
            case "codebuild" -> "{\"projectName\":\"" + n + "\"}";
            case "codedeploy" -> "{\"applicationName\":\"" + n + "\",\"deploymentGroupName\":\"g\"}";
            case "acm" -> "{\"CertificateArn\":\"arn:aws:acm:us-east-1:000000000000:certificate/" + n + "\"}";
            case "backup" -> "{\"BackupVaultName\":\"" + n + "\"}";
            case "scheduler" -> "{\"Name\":\"" + n + "\",\"GroupName\":\"default\"}";
            case "pipes" -> "{\"Name\":\"" + n + "\"}";
            case "transfer" -> "{\"ServerId\":\"" + n + "\"}";
            case "transcribe" -> "{\"TranscriptionJobName\":\"" + n + "\"}";
            case "cur" -> "{\"ReportName\":\"" + n + "\"}";
            case "bcm-data-exports" -> "{\"ExportArn\":\"arn:aws:bcm-data-exports:us-east-1:000000000000:export/" + n + "\"}";
            case "textract" -> "{\"JobId\":\"" + n + "\"}";
            case "wafv2" -> "{\"Id\":\"" + n + "\",\"Name\":\"" + n + "\",\"Scope\":\"REGIONAL\"}";
            case "elasticmapreduce" -> emrBody(n);
            case "firehose" -> "{\"DeliveryStreamName\":\"" + n + "\"}";
            case "ecs" -> "{\"cluster\":\"" + n + "\"}";
            case "ecr" -> "{\"repositoryName\":\"" + n + "\"}";
            case "glue" -> "{\"DatabaseName\":\"" + n + "\"}";
            case "kafka" -> "{\"clusterName\":\"" + n + "\"}";
            case "mq" -> "{\"brokerName\":\"" + n + "\",\"brokerId\":\"b-" + n + "\"}";
            case "batch" -> "{\"jobQueueName\":\"" + n + "\",\"jobName\":\"job-" + n + "\",\"jobDefinition\":\"def-" + n + "\"}";
            case "lightsail" -> "{\"instanceName\":\"" + n + "\"}";
            case "memorydb" -> "{\"ClusterName\":\"" + n + "\"}";
            case "codepipeline" -> "{\"name\":\"" + n + "\"}";
            case "s3vectors" -> "{\"vectorBucketName\":\"fuzz-" + n + "\",\"indexName\":\"idx-" + n + "\"}";
            case "securityhub" -> securityHubBody(n);
            case "apigatewayv2" -> "{\"ApiId\":\"" + n + "\"}";
            case "servicediscovery" -> "{\"ServiceId\":\"srv-" + n + "\"}";
            case "appconfigdata" -> appConfigDataBody(n);
            case "tagging" -> taggingBody(n);
            case "monitoring" -> "{\"Namespace\":\"AWS/" + n + "\",\"MetricData\":[]}";
            case "cognito-idp" -> "{\"UserPoolId\":\"us-east-1_" + n + "\",\"Username\":\"" + n + "\"}";
            case "iam" -> "Action=GetUser&UserName=" + n;
            case "sts" -> "Action=AssumeRole&RoleArn=arn:aws:iam::000000000000:role/" + n
                    + "&RoleSessionName=fuzz";
            case "cloudformation" -> "Action=DescribeStacks&StackName=" + n;
            case "ec2" -> "Action=DescribeInstances&InstanceId.1=i-" + n;
            case "elasticache" -> "Action=DescribeCacheClusters&CacheClusterId=" + n;
            case "rds", "neptune", "docdb" -> "Action=DescribeDBInstances&DBInstanceIdentifier=" + n;
            case "autoscaling" -> "Action=DescribeAutoScalingGroups&AutoScalingGroupNames.member.1=" + n;
            case "elasticloadbalancing" -> "Action=DescribeLoadBalancers&LoadBalancerArns.member.1=arn:aws:elasticloadbalancing:us-east-1:000000000000:loadbalancer/app/" + n + "/id";
            case "elasticbeanstalk" -> "Action=DescribeEnvironments&EnvironmentNames.member.1=" + n;
            case "email", "ses", "sesv2" -> "Action=SendEmail&Source=" + n + "@example.com";
            default -> "{\"Name\":\"" + n + "\"}";
        };
    }

    public static String emrJobFlowIds(String... ids) {
        StringBuilder sb = new StringBuilder("{\"JobFlowIds\":[");
        for (int i = 0; i < ids.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(sanitize(ids[i])).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    public static String taggingResourceList(String... arns) {
        StringBuilder sb = new StringBuilder("{\"ResourceARNList\":[");
        for (int i = 0; i < arns.length; i++) {
            if (i > 0) {
                sb.append(',');
            }
            sb.append('"').append(arns[i]).append('"');
        }
        sb.append("]}");
        return sb.toString();
    }

    public static String queryAction(String action, Map<String, String> params) {
        StringBuilder sb = new StringBuilder("Action=").append(action);
        if (params != null) {
            for (Map.Entry<String, String> e : params.entrySet()) {
                sb.append('&').append(e.getKey()).append('=').append(e.getValue());
            }
        }
        return sb.toString();
    }

    public static List<String> highValueJson11Targets() {
        return List.of(
                "DynamoDB_20120810.GetItem",
                "DynamoDB_20120810.PutItem",
                "DynamoDB_20120810.ExecuteStatement",
                "DynamoDB_20120810.BatchExecuteStatement",
                "TrentService.Decrypt",
                "TrentService.Encrypt",
                "secretsmanager.GetSecretValue",
                "secretsmanager.PutSecretValue",
                "AWSEvents.PutEvents",
                "AWSEvents.PutRule",
                "AWSEvents.StartReplay",
                "AmazonSSM.GetParameter",
                "AWSStepFunctions.StartExecution",
                "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.LookupEvents",
                "com.amazonaws.cloudtrail.v20131101.CloudTrail_20131101.StopLogging",
                "AmazonAthena.StartQueryExecution",
                "CodeBuild_20161006.BatchGetProjects",
                "CodeDeploy_20141006.GetDeployment",
                "CodePipeline_20150709.GetPipeline",
                "Firehose_20150804.PutRecord",
                "AWSGlue.GetDatabase",
                "AmazonEKSV3.DescribeCluster",
                "GuardDuty_2017-11-28.GetFindings",
                "StarlingDoveService.PutConfigRule",
                "AWSSecurityHub.GetFindings",
                "AWSCognitoIdentityProviderService.AdminGetUser",
                "Kinesis_20131202.PutRecord",
                "AWSWAF_20190729.GetWebACL",
                "ElasticMapReduce.TerminateJobFlows",
                "AmazonApiGatewayV2.GetApi",
                "Route53AutoNaming_v20170314.GetService",
                "AmazonMemoryDB.DescribeClusters",
                "Lightsail_20161128.GetInstance",
                "CloudApiService.GetResource",
                "TransferService.DescribeServer",
                "Transcribe.GetTranscriptionJob",
                "Textract.GetDocumentTextDetection",
                "AWSPriceListService.GetProducts",
                "AWSInsightsIndexService.GetCostAndUsage",
                "AWSOrigamiServiceGatewayService.PutReportDefinition",
                "AWSBillingAndCostManagementDataExports.GetExport",
                "ResourceGroupsTaggingAPI_20170126.TagResources"
        );
    }

    public static List<String> highValueQueryActions() {
        return List.of(
                "GetCallerIdentity", "AssumeRole", "AssumeRoleWithWebIdentity", "GetSessionToken",
                "ListUsers", "CreateAccessKey", "GetPolicyVersion", "CreatePolicyVersion",
                "ReceiveMessage", "SendMessage", "ListQueues", "PurgeQueue",
                "Publish", "Subscribe", "ListTopics",
                "DescribeStacks", "CreateStack",
                "DescribeInstances", "CreateNetworkAcl",
                "DescribeDBInstances", "CreateDBInstance",
                "DescribeCacheClusters", "DescribeLoadBalancers",
                "DescribeAutoScalingGroups", "DescribeEnvironments",
                "SendEmail", "ListIdentities",
                "GetMetricStatistics", "ListMetrics"
        );
    }

    public static List<String> highValueRestPaths() {
        return List.of(
                "/2015-03-31/functions",
                "/2015-03-31/functions/fn/invocations",
                "/restapis",
                "/restapis/api/prod/_user_request_/x",
                "/execute-api/api/prod/GET/x",
                "/v2/apis",
                "/v1/pipes",
                "/v1/pipes/my-pipe",
                "/schedules/my-schedule",
                "/schedule-groups/default",
                "/things/my-thing/shadow",
                "/clusters/c/node-groups",
                "/api/v2/clusters/msk-1",
                "/backup-vaults/v",
                "/hostedzone/Z123",
                "/2020-05-31/distribution/D123",
                "/model/amazon.titan-text/converse",
                "/model/amazon.titan-text/invoke",
                "/applications/app",
                "/configurationsessions",
                "/Execute",
                "/lambda-url/fn",
                "/v1/apis",
                "/v1/brokers",
                "/v1/brokers/broker-1",
                "/v1/createcomputeenvironment",
                "/v1/submitjob",
                "/v1/describejobs",
                "/CreateVectorBucket",
                "/GetVectorBucket",
                "/ListVectorBuckets",
                "/CreateIndex",
                "/PutVectors",
                "/QueryVectors",
                "/2021-01-01/opensearch/domain/d",
                "/v2/",
                "/_floci/health",
                "/_localstack/health",
                "/cognito-idp/oauth2/token",
                "/health",
                "/fuzz-bucket/key"
        );
    }

    public static String partiqlJoin(String tableA, String tableB) {
        return "{\"Statement\":\"SELECT * FROM \\\"" + sanitize(tableA)
                + "\\\" JOIN \\\"" + sanitize(tableB) + "\\\" ON true\"}";
    }

    private static String emrBody(String name) {
        return "{\"ClusterId\":\"" + name + "\",\"JobFlowIds\":[\"" + name + "\",\"j-" + name + "\"]}";
    }

    private static String securityHubBody(String name) {
        return "{\"Findings\":[{\"ProductArn\":\"arn:aws:securityhub:us-east-1:000000000000:product/" + name + "\"}]}";
    }

    private static String appConfigDataBody(String name) {
        return "{\"ApplicationIdentifier\":\"" + name + "\","
                + "\"EnvironmentIdentifier\":\"env-" + name + "\","
                + "\"ConfigurationProfileIdentifier\":\"profile-" + name + "\"}";
    }

    private static String taggingBody(String name) {
        return taggingResourceList(
                "arn:aws:s3:::fuzz-" + name,
                "arn:aws:sqs:us-east-1:000000000000:fuzz-" + name);
    }

    private static String sanitize(String name) {
        if (name == null || name.isBlank()) {
            return "x";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < Math.min(name.length(), 40); i++) {
            char c = name.charAt(i);
            if (Character.isLetterOrDigit(c) || c == '-' || c == '_' || c == '/') {
                sb.append(c);
            }
        }
        return sb.isEmpty() ? "x" : sb.toString().toLowerCase(Locale.ROOT);
    }
}
