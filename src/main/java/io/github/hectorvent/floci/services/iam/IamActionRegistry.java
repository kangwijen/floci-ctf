package io.github.hectorvent.floci.services.iam;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.regex.Pattern;

import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import io.github.hectorvent.floci.core.common.ResolvedServiceCatalog;
import io.github.hectorvent.floci.core.common.ServiceDescriptor;
import org.jboss.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedMap;

/**
 * Maps (credentialScope, httpMethod, requestPath) → IAM action string.
 *
 * For Query-protocol services (SQS, SNS, IAM, STS, ...) the Action form
 * parameter is mapped directly to {@code <service>:<Action>}.
 *
 * For REST-JSON services the first matching rule wins (specific before wildcard).
 */
@ApplicationScoped
public class IamActionRegistry {

    private static final Logger LOG = Logger.getLogger(IamActionRegistry.class);

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final ResolvedServiceCatalog catalog;

    @Inject
    public IamActionRegistry(ResolvedServiceCatalog catalog) {
        this.catalog = catalog;
    }

    private record ActionRule(String service, String method, Pattern pathPattern, String action) {}

    /** API Gateway control-plane paths under {@code /restapis/...}, excluding data-plane {@code _user_request_}. */
    private static final String APIGW_CONTROL_REST_PATH = ".*/restapis/(?!.*/_user_request_/).+";

    /** S3 Vectors REST action paths (single-segment; must not match generic S3 bucket rules). */
    private static final Set<String> S3_VECTORS_REST_PATHS = Set.of(
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

    private static final List<ActionRule> RULES = List.of(
        // ── API Gateway execute-api (data plane; must precede generic /{bucket}/key S3 rules) ──
        rule("execute-api", "GET",     "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "POST",    "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "PUT",     "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "PATCH",   "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "DELETE",  "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "HEAD",    "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "OPTIONS", "^/execute-api/.+",      "execute-api:Invoke"),
        rule("execute-api", "GET",     ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "POST",    ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "PUT",     ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "PATCH",   ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "DELETE",  ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "HEAD",    ".*/_user_request_.+",   "execute-api:Invoke"),
        rule("execute-api", "OPTIONS", ".*/_user_request_.+",   "execute-api:Invoke"),

        // ── S3 ─────────────────────────────────────────────────────────────────
        rule("s3", "GET",    "^/?$",                              "s3:ListAllMyBuckets"),
        rule("s3", "PUT",    "^/[^/]+/?$",                       "s3:CreateBucket"),
        rule("s3", "DELETE", "^/[^/]+/?$",                       "s3:DeleteBucket"),
        rule("s3", "HEAD",   "^/[^/]+/?$",                       "s3:ListBucket"),
        rule("s3", "GET",    "^/[^/]+/?$",                       "s3:ListBucket"),
        rule("s3", "GET",    "^/[^/]+/.+",                       "s3:GetObject"),
        rule("s3", "PUT",    "^/[^/]+/.+",                       "s3:PutObject"),
        rule("s3", "DELETE", "^/[^/]+/.+",                       "s3:DeleteObject"),
        rule("s3", "HEAD",   "^/[^/]+/.+",                       "s3:GetObject"),

        // ── Lambda (REST host prefix /2015-03-31) ───────────────────────────────
        rule("lambda", "GET",    "^/2015-03-31/functions/?$",                          "lambda:ListFunctions"),
        rule("lambda", "POST",   "^/2015-03-31/functions/?$",                          "lambda:CreateFunction"),
        rule("lambda", "GET",    "^/2015-03-31/functions/[^/]+/?$",                    "lambda:GetFunction"),
        rule("lambda", "PUT",    "^/2015-03-31/functions/[^/]+/code/?$",               "lambda:UpdateFunctionCode"),
        rule("lambda", "PUT",    "^/2015-03-31/functions/[^/]+/configuration/?$",      "lambda:UpdateFunctionConfiguration"),
        rule("lambda", "DELETE", "^/2015-03-31/functions/[^/]+/?$",                    "lambda:DeleteFunction"),
        rule("lambda", "POST",   "^/2015-03-31/functions/[^/]+/invocations/?$",        "lambda:InvokeFunction"),
        rule("lambda", "GET",    "^/2015-03-31/functions/[^/]+/aliases/?$",            "lambda:ListAliases"),
        rule("lambda", "POST",   "^/2015-03-31/functions/[^/]+/aliases/?$",            "lambda:CreateAlias"),
        rule("lambda", "GET",    "^/2015-03-31/functions/[^/]+/aliases/[^/]+/?$",      "lambda:GetAlias"),
        rule("lambda", "PUT",    "^/2015-03-31/functions/[^/]+/aliases/[^/]+/?$",      "lambda:UpdateAlias"),
        rule("lambda", "DELETE", "^/2015-03-31/functions/[^/]+/aliases/[^/]+/?$",      "lambda:DeleteAlias"),
        rule("lambda", "GET",    "^/2015-03-31/functions/[^/]+/policy/?$",             "lambda:GetPolicy"),
        rule("lambda", "POST",   "^/2015-03-31/functions/[^/]+/policy/?$",             "lambda:AddPermission"),
        rule("lambda", "DELETE", "^/2015-03-31/functions/[^/]+/policy/.+",           "lambda:RemovePermission"),
        rule("lambda", "GET",    "^/2015-03-31/event-source-mappings/?$",              "lambda:ListEventSourceMappings"),
        rule("lambda", "POST",   "^/2015-03-31/event-source-mappings/?$",              "lambda:CreateEventSourceMapping"),
        rule("lambda", "DELETE", "^/2015-03-31/event-source-mappings/[^/]+/?$",        "lambda:DeleteEventSourceMapping"),
        rule("lambda", "GET",    "^/2015-03-31/functions/[^/]+/url/?$",                "lambda:GetFunctionUrlConfig"),
        rule("lambda", "POST",   "^/2015-03-31/functions/[^/]+/url/?$",                "lambda:CreateFunctionUrlConfig"),
        rule("lambda", "PUT",    "^/2015-03-31/functions/[^/]+/url/?$",                "lambda:UpdateFunctionUrlConfig"),
        rule("lambda", "DELETE", "^/2015-03-31/functions/[^/]+/url/?$",                "lambda:DeleteFunctionUrlConfig"),
        rule("lambda", "GET",    "^/2021-10-31/functions/[^/]+/url/?$",                "lambda:GetFunctionUrlConfig"),
        rule("lambda", "POST",   "^/2021-10-31/functions/[^/]+/url/?$",                "lambda:CreateFunctionUrlConfig"),
        rule("lambda", "PUT",    "^/2021-10-31/functions/[^/]+/url/?$",                "lambda:UpdateFunctionUrlConfig"),
        rule("lambda", "DELETE", "^/2021-10-31/functions/[^/]+/url/?$",                "lambda:DeleteFunctionUrlConfig"),
        rule("lambda", "PUT",    "^/2017-10-31/functions/[^/]+/concurrency/?$",         "lambda:PutFunctionConcurrency"),
        rule("lambda", "DELETE", "^/2017-10-31/functions/[^/]+/concurrency/?$",         "lambda:DeleteFunctionConcurrency"),
        rule("lambda", "GET",    "^/2019-09-30/functions/[^/]+/concurrency/?$",         "lambda:GetFunctionConcurrency"),
        rule("lambda", "GET",    "^/2019-09-25/functions/[^/]+/event-invoke-config/?$", "lambda:GetFunctionEventInvokeConfig"),
        rule("lambda", "PUT",    "^/2019-09-25/functions/[^/]+/event-invoke-config/?$", "lambda:PutFunctionEventInvokeConfig"),
        rule("lambda", "POST",   "^/2019-09-25/functions/[^/]+/event-invoke-config/?$", "lambda:UpdateFunctionEventInvokeConfig"),
        rule("lambda", "DELETE", "^/2019-09-25/functions/[^/]+/event-invoke-config/?$", "lambda:DeleteFunctionEventInvokeConfig"),
        rule("lambda", "GET",    "^/2018-10-31/layers/?$",                              "lambda:ListLayers"),
        rule("lambda", "POST",   "^/2018-10-31/layers/[^/]+/versions/?$",             "lambda:PublishLayerVersion"),
        rule("lambda", "GET",    "^/2018-10-31/layers/[^/]+/versions/?$",             "lambda:ListLayerVersions"),
        rule("lambda", "GET",    "^/2018-10-31/layers/[^/]+/versions/[^/]+/?$",       "lambda:GetLayerVersion"),
        rule("lambda", "DELETE", "^/2018-10-31/layers/[^/]+/versions/[^/]+/?$",       "lambda:DeleteLayerVersion"),
        rule("lambda", "GET",    "^/2017-03-31/tags/.+",                               "lambda:ListTags"),
        rule("lambda", "POST",   "^/2017-03-31/tags/.+",                               "lambda:TagResource"),
        rule("lambda", "DELETE", "^/2017-03-31/tags/.+",                               "lambda:UntagResource"),
        rule("lambda", "GET",    "^/2020-06-30/functions/[^/]+/code-signing-config/?$", "lambda:GetFunctionCodeSigningConfig"),
        rule("lambda", "GET",    "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "POST",   "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "PUT",    "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "PATCH",  "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "DELETE", "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "HEAD",   "^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),
        rule("lambda", "OPTIONS","^/lambda-url/[^/]+(?:/.*)?$",                        "lambda:InvokeFunctionUrl"),

        // ── DynamoDB (JSON 1.1, action from X-Amz-Target handled separately) ──
        // Handled via Query-style action extraction in the filter

        // ── RDS Data API ───────────────────────────────────────────────────────
        rule("rds-data", "POST", "^/Execute/?$",              "rds-data:ExecuteStatement"),
        rule("rds-data", "POST", "^/ExecuteSql/?$",           "rds-data:ExecuteSql"),
        rule("rds-data", "POST", "^/BatchExecute/?$",         "rds-data:BatchExecuteStatement"),
        rule("rds-data", "POST", "^/BeginTransaction/?$",     "rds-data:BeginTransaction"),
        rule("rds-data", "POST", "^/CommitTransaction/?$",    "rds-data:CommitTransaction"),
        rule("rds-data", "POST", "^/RollbackTransaction/?$",  "rds-data:RollbackTransaction"),

        // ── API Gateway ────────────────────────────────────────────────────────
        rule("apigateway", "GET",    ".*/account$",                       "apigateway:GET"),
        rule("apigateway", "PATCH",  ".*/account$",                       "apigateway:PATCH"),
        rule("apigateway", "GET",    ".*/restapis$",                        "apigateway:GET"),
        rule("apigateway", "POST",   ".*/restapis$",                        "apigateway:POST"),
        rule("apigateway", "GET",    APIGW_CONTROL_REST_PATH,               "apigateway:GET"),
        rule("apigateway", "PUT",    APIGW_CONTROL_REST_PATH,               "apigateway:PUT"),
        rule("apigateway", "PATCH",  APIGW_CONTROL_REST_PATH,               "apigateway:PATCH"),
        rule("apigateway", "DELETE", APIGW_CONTROL_REST_PATH,               "apigateway:DELETE"),
        rule("apigateway", "POST",   APIGW_CONTROL_REST_PATH,               "apigateway:POST"),

        // ── API Gateway v2 (REST JSON /v2/apis) ─────────────────────────────────
        rule("apigatewayv2", "POST",   "^/v2/apis/?$",                                    "apigatewayv2:CreateApi"),
        rule("apigatewayv2", "GET",    "^/v2/apis/?$",                                    "apigatewayv2:GetApis"),
        rule("apigatewayv2", "GET",    "^/v2/apis/[^/]+/?$",                              "apigatewayv2:GetApi"),
        rule("apigatewayv2", "PATCH",  "^/v2/apis/[^/]+/?$",                              "apigatewayv2:UpdateApi"),
        rule("apigatewayv2", "DELETE", "^/v2/apis/[^/]+/?$",                              "apigatewayv2:DeleteApi"),
        rule("apigatewayv2", "POST",   "^/v2/apis/[^/]+/.+",                              "apigatewayv2:POST"),
        rule("apigatewayv2", "GET",    "^/v2/apis/[^/]+/.+",                              "apigatewayv2:GET"),
        rule("apigatewayv2", "PUT",    "^/v2/apis/[^/]+/.+",                              "apigatewayv2:PUT"),
        rule("apigatewayv2", "PATCH",  "^/v2/apis/[^/]+/.+",                              "apigatewayv2:PATCH"),
        rule("apigatewayv2", "DELETE", "^/v2/apis/[^/]+/.+",                              "apigatewayv2:DELETE"),
        rule("apigatewayv2", "POST",   "^/v2/vpclinks/?$",                                 "apigatewayv2:CreateVpcLink"),
        rule("apigatewayv2", "GET",    "^/v2/vpclinks/?$",                                 "apigatewayv2:GetVpcLinks"),
        rule("apigatewayv2", "GET",    "^/v2/vpclinks/[^/]+/?$",                           "apigatewayv2:GetVpcLink"),
        rule("apigatewayv2", "DELETE", "^/v2/vpclinks/[^/]+/?$",                           "apigatewayv2:DeleteVpcLink"),

        // ── AppSync (REST JSON) ────────────────────────────────────────────────
        rule("appsync", "POST",   "^/v1/apis/?$",                              "appsync:CreateGraphqlApi"),
        rule("appsync", "GET",    "^/v1/apis/?$",                              "appsync:ListGraphqlApis"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/?$",                        "appsync:GetGraphqlApi"),
        rule("appsync", "PUT",    "^/v1/apis/[^/]+/?$",                        "appsync:UpdateGraphqlApi"),
        rule("appsync", "DELETE", "^/v1/apis/[^/]+/?$",                        "appsync:DeleteGraphqlApi"),
        rule("appsync", "POST",   "^/v1/apis/[^/]+/datasources/?$",            "appsync:CreateDataSource"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/datasources/?$",            "appsync:ListDataSources"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/datasources/[^/]+/?$",      "appsync:GetDataSource"),
        rule("appsync", "PUT",    "^/v1/apis/[^/]+/datasources/[^/]+/?$",      "appsync:UpdateDataSource"),
        rule("appsync", "DELETE", "^/v1/apis/[^/]+/datasources/[^/]+/?$",      "appsync:DeleteDataSource"),
        rule("appsync", "POST",   "^/v1/apis/[^/]+/types/[^/]+/resolvers/?$",  "appsync:CreateResolver"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/types/[^/]+/resolvers/?$",  "appsync:ListResolvers"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/types/[^/]+/resolvers/[^/]+/?$", "appsync:GetResolver"),
        rule("appsync", "PUT",    "^/v1/apis/[^/]+/types/[^/]+/resolvers/[^/]+/?$", "appsync:UpdateResolver"),
        rule("appsync", "DELETE", "^/v1/apis/[^/]+/types/[^/]+/resolvers/[^/]+/?$", "appsync:DeleteResolver"),
        rule("appsync", "POST",   "^/v1/apis/[^/]+/schemacreation/?$",         "appsync:StartSchemaCreation"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/schemacreation/?$",         "appsync:GetSchemaCreationStatus"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/schema/?$",                 "appsync:GetIntrospectionSchema"),
        rule("appsync", "POST",   "^/v1/apis/[^/]+/functions/?$",              "appsync:CreateFunction"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/functions/?$",              "appsync:ListFunctions"),
        rule("appsync", "GET",    "^/v1/apis/[^/]+/functions/[^/]+/?$",        "appsync:GetFunction"),
        rule("appsync", "PUT",    "^/v1/apis/[^/]+/functions/[^/]+/?$",        "appsync:UpdateFunction"),
        rule("appsync", "DELETE", "^/v1/apis/[^/]+/functions/[^/]+/?$",        "appsync:DeleteFunction"),

        // ── EKS (REST JSON) ────────────────────────────────────────────────────
        rule("eks", "POST",   "^/clusters/?$",                                    "eks:CreateCluster"),
        rule("eks", "GET",    "^/clusters/?$",                                    "eks:ListClusters"),
        rule("eks", "GET",    "^/clusters/[^/]+/?$",                              "eks:DescribeCluster"),
        rule("eks", "DELETE", "^/clusters/[^/]+/?$",                              "eks:DeleteCluster"),
        rule("eks", "POST",   "^/clusters/[^/]+/node-groups/?$",                  "eks:CreateNodegroup"),
        rule("eks", "GET",    "^/clusters/[^/]+/node-groups/?$",                  "eks:ListNodegroups"),
        rule("eks", "GET",    "^/clusters/[^/]+/node-groups/[^/]+/?$",            "eks:DescribeNodegroup"),
        rule("eks", "DELETE", "^/clusters/[^/]+/node-groups/[^/]+/?$",            "eks:DeleteNodegroup"),

        // ── EventBridge Scheduler (REST JSON) ───────────────────────────────────
        rule("scheduler", "POST",   "^/schedules/[^/]+/?$",                       "scheduler:CreateSchedule"),
        rule("scheduler", "GET",    "^/schedules/[^/]+/?$",                       "scheduler:GetSchedule"),
        rule("scheduler", "PUT",    "^/schedules/[^/]+/?$",                       "scheduler:UpdateSchedule"),
        rule("scheduler", "DELETE", "^/schedules/[^/]+/?$",                       "scheduler:DeleteSchedule"),
        rule("scheduler", "GET",    "^/schedules/?$",                              "scheduler:ListSchedules"),
        rule("scheduler", "POST",   "^/schedule-groups/[^/]+/?$",                 "scheduler:CreateScheduleGroup"),
        rule("scheduler", "GET",    "^/schedule-groups/[^/]+/?$",                 "scheduler:GetScheduleGroup"),
        rule("scheduler", "DELETE", "^/schedule-groups/[^/]+/?$",                 "scheduler:DeleteScheduleGroup"),
        rule("scheduler", "GET",    "^/schedule-groups/?$",                        "scheduler:ListScheduleGroups"),

        // ── EventBridge Pipes (REST JSON) ───────────────────────────────────────
        rule("pipes", "POST",   "^/v1/pipes/[^/]+/?$",                             "pipes:CreatePipe"),
        rule("pipes", "GET",    "^/v1/pipes/[^/]+/?$",                             "pipes:DescribePipe"),
        rule("pipes", "PUT",    "^/v1/pipes/[^/]+/?$",                             "pipes:UpdatePipe"),
        rule("pipes", "DELETE", "^/v1/pipes/[^/]+/?$",                             "pipes:DeletePipe"),
        rule("pipes", "GET",    "^/v1/pipes/?$",                                   "pipes:ListPipes"),
        rule("pipes", "POST",   "^/v1/pipes/[^/]+/start/?$",                       "pipes:StartPipe"),
        rule("pipes", "POST",   "^/v1/pipes/[^/]+/stop/?$",                        "pipes:StopPipe"),

        // ── MSK (kafka REST) ──────────────────────────────────────────────────
        rule("kafka", "POST",   "^/v1/clusters/?$",                                "kafka:CreateCluster"),
        rule("kafka", "POST",   "^/api/v2/clusters/?$",                           "kafka:CreateClusterV2"),
        rule("kafka", "GET",    "^/v1/clusters/[^/]+/?$",                          "kafka:DescribeCluster"),
        rule("kafka", "GET",    "^/api/v2/clusters/[^/]+/?$",                     "kafka:DescribeClusterV2"),
        rule("kafka", "DELETE", "^/v1/clusters/[^/]+/?$",                          "kafka:DeleteCluster"),
        rule("kafka", "GET",    "^/v1/clusters/?$",                                "kafka:ListClusters"),

        // ── CloudFront (REST XML) ─────────────────────────────────────────────
        rule("cloudfront", "GET",    ".*/distribution/[^/]+/?$",                 "cloudfront:GetDistribution"),
        rule("cloudfront", "PUT",    ".*/distribution/[^/]+/config/?$",          "cloudfront:UpdateDistribution"),
        rule("cloudfront", "DELETE", ".*/distribution/[^/]+/?$",                 "cloudfront:DeleteDistribution"),
        rule("cloudfront", "POST",   ".*/distribution/[^/]+/invalidation/?$",    "cloudfront:CreateInvalidation"),

        // ── Bedrock Runtime (REST JSON) ───────────────────────────────────────
        rule("bedrock", "POST",         ".*/model/.+/converse/?$",               "bedrock:Converse"),
        rule("bedrock", "POST",         ".*/model/.+/invoke/?$",                "bedrock:InvokeModel"),
        rule("bedrock-runtime", "POST", ".*/model/.+/converse/?$",               "bedrock:Converse"),
        rule("bedrock-runtime", "POST", ".*/model/.+/invoke/?$",                "bedrock:InvokeModel"),

        // ── AppConfig (REST JSON) ───────────────────────────────────────────────
        rule("appconfig", "POST",   "^/applications/[^/]+/environments/[^/]+/deployments/?$",
                "appconfig:StartDeployment"),
        rule("appconfig", "GET",    "^/applications/[^/]+/environments/[^/]+/deployments/[^/]+/?$",
                "appconfig:GetDeployment"),
        rule("appconfig", "GET",    "^/applications/[^/]+/configurationprofiles/[^/]+/hostedconfigurationversions/[^/]+/?$",
                "appconfig:GetHostedConfigurationVersion"),
        rule("appconfig", "POST",   "^/applications/[^/]+/configurationprofiles/[^/]+/hostedconfigurationversions/?$",
                "appconfig:CreateHostedConfigurationVersion"),
        rule("appconfig", "GET",    "^/applications/[^/]+/configurationprofiles/[^/]+/hostedconfigurationversions/?$",
                "appconfig:ListHostedConfigurationVersions"),
        rule("appconfig", "GET",    "^/applications/[^/]+/configurationprofiles/[^/]+/?$",
                "appconfig:GetConfigurationProfile"),
        rule("appconfig", "POST",   "^/applications/[^/]+/configurationprofiles/?$",
                "appconfig:CreateConfigurationProfile"),
        rule("appconfig", "GET",    "^/applications/[^/]+/configurationprofiles/?$",
                "appconfig:ListConfigurationProfiles"),
        rule("appconfig", "GET",    "^/applications/[^/]+/environments/[^/]+/?$",
                "appconfig:GetEnvironment"),
        rule("appconfig", "POST",   "^/applications/[^/]+/environments/?$",
                "appconfig:CreateEnvironment"),
        rule("appconfig", "GET",    "^/applications/[^/]+/environments/?$",
                "appconfig:ListEnvironments"),
        rule("appconfig", "GET",    "^/deploymentstrategies/[^/]+/?$",
                "appconfig:GetDeploymentStrategy"),
        rule("appconfig", "POST",   "^/deploymentstrategies/?$",
                "appconfig:CreateDeploymentStrategy"),
        rule("appconfig", "GET",    "^/applications/[^/]+/?$",
                "appconfig:GetApplication"),
        rule("appconfig", "DELETE", "^/applications/[^/]+/?$",
                "appconfig:DeleteApplication"),
        rule("appconfig", "POST",   "^/applications/?$",
                "appconfig:CreateApplication"),
        rule("appconfig", "GET",    "^/applications/?$",
                "appconfig:ListApplications"),

        // ── AppConfig Data (REST JSON; IAM actions use appconfig: prefix per AWS) ─
        rule("appconfigdata", "POST", "^/configurationsessions/?$",
                "appconfig:StartConfigurationSession"),
        rule("appconfigdata", "GET",  "^/configuration/?$",
                "appconfig:GetLatestConfiguration"),

        // ── AWS Backup (REST JSON) ────────────────────────────────────────────
        rule("backup", "GET",    "^/backup-vaults/[^/]+/?$",  "backup:DescribeBackupVault"),
        rule("backup", "PUT",    "^/backup-vaults/[^/]+/?$",  "backup:CreateBackupVault"),

        // ── Route 53 (REST XML) ───────────────────────────────────────────────
        rule("route53", "GET",    ".*/hostedzone/[^/]+/?$",    "route53:GetHostedZone"),
        rule("route53", "POST",   ".*/hostedzone/?$",          "route53:CreateHostedZone"),

        // ── IoT Data (REST JSON; SigV4 scope iotdata; IAM actions use iot: prefix) ─
        rule("iotdata", "GET",    "^/things/[^/]+/shadow/?$", "iot:GetThingShadow"),
        rule("iotdata", "POST",   "^/things/[^/]+/shadow/?$", "iot:UpdateThingShadow"),
        rule("iotdata", "DELETE", "^/things/[^/]+/shadow/?$", "iot:DeleteThingShadow"),
        rule("iotdata", "GET",    "^/api/things/shadow/ListNamedShadowsForThing/[^/]+/?$",
                "iot:ListNamedShadowsForThing"),
        rule("iotdata", "POST",   "^/topics/.+",               "iot:Publish"),
        rule("iotdata", "GET",    "^/retainedMessage/.+",      "iot:GetRetainedMessage"),
        rule("iotdata", "GET",    "^/retainedMessage/?$",      "iot:ListRetainedMessages"),

        // ── IoT control plane (REST JSON) ─────────────────────────────────────
        rule("iot", "GET",    "^/endpoint/?$",              "iot:DescribeEndpoint"),
        rule("iot", "POST",   "^/things/[^/]+/?$",          "iot:CreateThing"),
        rule("iot", "GET",    "^/things/[^/]+/?$",          "iot:DescribeThing"),
        rule("iot", "DELETE", "^/things/[^/]+/?$",          "iot:DeleteThing"),
        rule("iot", "PATCH",  "^/things/[^/]+/?$",          "iot:UpdateThing"),
        rule("iot", "PUT",    "^/things/[^/]+/?$",          "iot:UpdateThing"),
        rule("iot", "GET",    "^/things/?$",                "iot:ListThings"),
        rule("iot", "POST",   "^/policies/[^/]+/?$",        "iot:CreatePolicy"),
        rule("iot", "GET",    "^/policies/[^/]+/?$",        "iot:GetPolicy"),
        rule("iot", "DELETE", "^/policies/[^/]+/?$",        "iot:DeletePolicy"),
        rule("iot", "GET",    "^/policies/?$",              "iot:ListPolicies"),
        rule("iot", "POST",   "^/certificates/?$",          "iot:CreateKeysAndCertificate"),
        rule("iot", "GET",    "^/certificates/[^/]+/?$",    "iot:DescribeCertificate"),
        rule("iot", "POST",   "^/rules/[^/]+/?$",           "iot:CreateTopicRule"),
        rule("iot", "GET",    "^/rules/[^/]+/?$",           "iot:GetTopicRule"),
        rule("iot", "DELETE", "^/rules/[^/]+/?$",           "iot:DeleteTopicRule"),
        rule("iot", "GET",    "^/rules/?$",                 "iot:ListTopicRules"),

        // ── AWS Batch (REST JSON /v1) ─────────────────────────────────────────
        rule("batch", "POST", "^/v1/createcomputeenvironment/?$",   "batch:CreateComputeEnvironment"),
        rule("batch", "POST", "^/v1/describecomputeenvironments/?$", "batch:DescribeComputeEnvironments"),
        rule("batch", "POST", "^/v1/createjobqueue/?$",             "batch:CreateJobQueue"),
        rule("batch", "POST", "^/v1/describejobqueues/?$",          "batch:DescribeJobQueues"),
        rule("batch", "POST", "^/v1/registerjobdefinition/?$",      "batch:RegisterJobDefinition"),
        rule("batch", "POST", "^/v1/deregisterjobdefinition/?$",    "batch:DeregisterJobDefinition"),
        rule("batch", "POST", "^/v1/describejobdefinitions/?$",    "batch:DescribeJobDefinitions"),
        rule("batch", "POST", "^/v1/submitjob/?$",                  "batch:SubmitJob"),
        rule("batch", "POST", "^/v1/describejobs/?$",               "batch:DescribeJobs"),
        rule("batch", "POST", "^/v1/listjobs/?$",                   "batch:ListJobs"),

        // ── Amazon MQ (REST JSON /v1/brokers) ─────────────────────────────────
        rule("mq", "POST",   "^/v1/brokers/?$",                           "mq:CreateBroker"),
        rule("mq", "GET",    "^/v1/brokers/?$",                           "mq:ListBrokers"),
        rule("mq", "GET",    "^/v1/brokers/[^/]+/?$",                     "mq:DescribeBroker"),
        rule("mq", "DELETE", "^/v1/brokers/[^/]+/?$",                     "mq:DeleteBroker"),
        rule("mq", "POST",   "^/v1/brokers/[^/]+/reboot/?$",             "mq:RebootBroker"),
        rule("mq", "POST",   "^/v1/brokers/[^/]+/users/[^/]+/?$",        "mq:CreateUser"),
        rule("mq", "GET",    "^/v1/brokers/[^/]+/users/[^/]+/?$",        "mq:DescribeUser"),
        rule("mq", "GET",    "^/v1/brokers/[^/]+/users/?$",              "mq:ListUsers"),
        rule("mq", "DELETE", "^/v1/brokers/[^/]+/users/[^/]+/?$",        "mq:DeleteUser"),

        // ── S3 Vectors (REST JSON; excluded from generic S3 bucket rules) ─────
        rule("s3vectors", "POST", "^/CreateVectorBucket/?$",  "s3vectors:CreateVectorBucket"),
        rule("s3vectors", "POST", "^/GetVectorBucket/?$",      "s3vectors:GetVectorBucket"),
        rule("s3vectors", "POST", "^/ListVectorBuckets/?$",    "s3vectors:ListVectorBuckets"),
        rule("s3vectors", "POST", "^/DeleteVectorBucket/?$",   "s3vectors:DeleteVectorBucket"),
        rule("s3vectors", "POST", "^/CreateIndex/?$",          "s3vectors:CreateIndex"),
        rule("s3vectors", "POST", "^/GetIndex/?$",             "s3vectors:GetIndex"),
        rule("s3vectors", "POST", "^/ListIndexes/?$",          "s3vectors:ListIndexes"),
        rule("s3vectors", "POST", "^/DeleteIndex/?$",          "s3vectors:DeleteIndex"),
        rule("s3vectors", "POST", "^/PutVectors/?$",           "s3vectors:PutVectors"),
        rule("s3vectors", "POST", "^/GetVectors/?$",           "s3vectors:GetVectors"),
        rule("s3vectors", "POST", "^/DeleteVectors/?$",        "s3vectors:DeleteVectors"),
        rule("s3vectors", "POST", "^/QueryVectors/?$",         "s3vectors:QueryVectors")
    );

    private static ActionRule rule(String service, String method, String path, String action) {
        return new ActionRule(service, method, Pattern.compile(path, Pattern.CASE_INSENSITIVE), action);
    }

    /**
     * Maps S3 versioning, sub-resource, and multipart/batch operations to AWS IAM actions
     * ({@code s3:ListBucketVersions}, {@code s3:GetObjectVersion}, {@code s3:PutBucketVersioning},
     * {@code s3:PutBucketPolicy}, {@code s3:DeleteObject}, ...).
     *
     * <p>Without this mapping, sub-resource writes (e.g. {@code PUT /{bucket}?policy}) and
     * POST operations (e.g. {@code POST /{bucket}?delete}) fall through to the generic
     * path-based {@code RULES} table or resolve to {@code null}, which either evaluates the
     * wrong IAM action (bypassing an explicit {@code Deny} on the real action) or skips IAM
     * evaluation entirely in non-strict mode.
     */
    private static String resolveS3Action(ContainerRequestContext ctx) {
        var query = ctx.getUriInfo().getQueryParameters();
        String method = ctx.getMethod().toUpperCase();
        if (query.containsKey("versions") && "GET".equals(method)) {
            return "s3:ListBucketVersions";
        }
        if (query.containsKey("versioning")) {
            if ("PUT".equals(method)) {
                return "s3:PutBucketVersioning";
            }
            if ("GET".equals(method)) {
                return "s3:GetBucketVersioning";
            }
        }
        String path = ctx.getUriInfo().getPath();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        boolean objectKey = path.matches("^/[^/]+/.+");
        String versionId = query.getFirst("versionId");
        if (objectKey && versionId != null && !versionId.isBlank()) {
            if ("GET".equals(method) || "HEAD".equals(method)) {
                return "s3:GetObjectVersion";
            }
            if ("DELETE".equals(method)) {
                return "s3:DeleteObjectVersion";
            }
        }

        String subResourceAction = objectKey
                ? resolveS3ObjectSubResourceAction(query, method)
                : resolveS3BucketSubResourceAction(query, method);
        if (subResourceAction != null) {
            return subResourceAction;
        }

        if ("POST".equals(method)) {
            return resolveS3PostAction(query, objectKey);
        }
        return null;
    }

    /**
     * Maps bucket sub-resource query parameters on PUT/DELETE requests to the AWS IAM bucket
     * policy action documented for the corresponding S3 API operation (e.g. {@code ?policy}
     * on PUT is {@code s3:PutBucketPolicy}, not {@code s3:CreateBucket}).
     *
     * @see <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/using-with-s3-policy-actions.html">
     *      Required permissions for Amazon S3 API operations</a>
     */
    private static String resolveS3BucketSubResourceAction(MultivaluedMap<String, String> query, String method) {
        boolean put = "PUT".equals(method);
        boolean delete = "DELETE".equals(method);
        if (!put && !delete) {
            return null;
        }
        if (query.containsKey("policy")) {
            return put ? "s3:PutBucketPolicy" : "s3:DeleteBucketPolicy";
        }
        if (query.containsKey("acl")) {
            return put ? "s3:PutBucketAcl" : null;
        }
        if (query.containsKey("lifecycle")) {
            return "s3:PutLifecycleConfiguration";
        }
        if (query.containsKey("cors")) {
            return "s3:PutBucketCORS";
        }
        if (query.containsKey("tagging")) {
            return "s3:PutBucketTagging";
        }
        if (query.containsKey("website")) {
            return put ? "s3:PutBucketWebsite" : "s3:DeleteBucketWebsite";
        }
        if (query.containsKey("logging")) {
            return "s3:PutBucketLogging";
        }
        if (query.containsKey("notification")) {
            return put ? "s3:PutBucketNotification" : null;
        }
        if (query.containsKey("object-lock")) {
            return put ? "s3:PutBucketObjectLockConfiguration" : null;
        }
        if (query.containsKey("encryption")) {
            return "s3:PutEncryptionConfiguration";
        }
        if (query.containsKey("publicAccessBlock")) {
            return "s3:PutBucketPublicAccessBlock";
        }
        if (query.containsKey("ownershipControls")) {
            return "s3:PutBucketOwnershipControls";
        }
        if (query.containsKey("requestPayment")) {
            return put ? "s3:PutBucketRequestPayment" : null;
        }
        if (delete && query.containsKey("replication")) {
            return "s3:PutReplicationConfiguration";
        }
        return null;
    }

    /**
     * Maps object sub-resource query parameters on PUT/DELETE requests to the AWS IAM object
     * policy action documented for the corresponding S3 API operation.
     */
    private static String resolveS3ObjectSubResourceAction(MultivaluedMap<String, String> query, String method) {
        if ("PUT".equals(method)) {
            if (query.containsKey("tagging")) {
                return "s3:PutObjectTagging";
            }
            if (query.containsKey("retention")) {
                return "s3:PutObjectRetention";
            }
            if (query.containsKey("legal-hold")) {
                return "s3:PutObjectLegalHold";
            }
            if (query.containsKey("acl")) {
                return "s3:PutObjectAcl";
            }
        }
        if ("DELETE".equals(method)) {
            if (query.containsKey("tagging")) {
                return "s3:DeleteObjectTagging";
            }
            if (query.containsKey("uploadId")) {
                return "s3:AbortMultipartUpload";
            }
        }
        return null;
    }

    /**
     * Maps S3 POST sub-resource operations to AWS IAM actions. AWS S3 has no dedicated POST
     * rules in the generic {@code RULES} table, so without this mapping every POST resolves
     * to {@code null}: allowed unconditionally in non-strict mode, denied for every legitimate
     * POST in strict mode.
     */
    private static String resolveS3PostAction(MultivaluedMap<String, String> query, boolean objectKey) {
        if (!objectKey) {
            if (query.containsKey("delete")) {
                return "s3:DeleteObject";
            }
            return null;
        }
        if (query.containsKey("uploads")) {
            return "s3:PutObject";
        }
        if (query.containsKey("restore")) {
            return "s3:RestoreObject";
        }
        if (query.containsKey("select")) {
            return "s3:GetObject";
        }
        if (query.containsKey("uploadId")) {
            return "s3:PutObject";
        }
        return null;
    }

    /**
     * Resolves the IAM action for an incoming request.
     *
     * For Query-protocol services the action comes directly from the {@code Action}
     * form param (e.g. {@code sqs:SendMessage}).
     *
     * For JSON 1.1 protocol the action comes from {@code X-Amz-Target}
     * (e.g. {@code DynamoDB_20120810.PutItem} → {@code dynamodb:PutItem}).
     *
     * For REST-JSON services the action is derived from the path rule table.
     *
     * Returns {@code null} when the action is unknown (caller treats this as ALLOW).
     */
    public String resolve(String credentialScope, ContainerRequestContext ctx) {
        // Query-protocol: Action param → service:Action.
        // AWS SDKs send Query-protocol calls (IAM, STS, EC2, SQS, SNS, ...) as
        // POST with Action=... in the application/x-www-form-urlencoded body,
        // not the URL query string — so we look in both places.
        String queryAction = ctx.getUriInfo().getQueryParameters().getFirst("Action");
        if (queryAction == null || queryAction.isBlank()) {
            queryAction = readFormAction(ctx);
        }
        if (queryAction != null && !queryAction.isBlank()) {
            String operation = IamUnrestrictedActions.canonicalQueryOperation(credentialScope, queryAction);
            return credentialScope + ":" + operation;
        }

        // JSON 1.1: X-Amz-Target → targetService:OperationName (not SigV4 credential scope).
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target != null && target.contains(".")) {
            String operationName = target.substring(target.lastIndexOf('.') + 1);
            String targetScope = resolveJson11TargetCredentialScope(target);
            if (targetScope == null) {
                targetScope = credentialScope;
            }
            if ("dynamodb".equals(targetScope)) {
                String partiqlAction = resolveDynamoDbPartiQLAction(operationName, ctx);
                if (partiqlAction != null) {
                    return partiqlAction;
                }
            }
            return IamUnrestrictedActions.canonicalAction(targetScope + ":" + operationName);
        }

        // REST-JSON: match against rule table
        String method = ctx.getMethod().toUpperCase();
        String path   = ctx.getUriInfo().getPath();
        if (!path.startsWith("/")) path = "/" + path;

        // S3: query params disambiguate versioning APIs (AWS IAM action names).
        // Non-bucket reserved paths must not resolve as S3 actions.
        if ("s3".equals(credentialScope) && isS3BucketStylePath(path)) {
            String s3Action = resolveS3Action(ctx);
            if (s3Action != null) {
                return s3Action;
            }
        }

        for (ActionRule rule : RULES) {
            if ("s3".equals(rule.service()) && !isS3BucketStylePath(path)) {
                continue;
            }
            if (rule.service().equals(credentialScope)
                    && rule.method().equals(method)
                    && rule.pathPattern().matcher(path).find()) {
                return rule.action();
            }
        }

        LOG.debugv("No action mapping for {0} {1} {2} — defaulting to ALLOW", credentialScope, method, path);
        return null;
    }

    /**
     * Returns the SigV4 credential scope implied by a REST route (method + path),
     * independent of the Authorization header scope.
     *
     * <p>Returns JSON 1.1 target service scope from {@code X-Amz-Target}, query-protocol
     * POST {@code /} without a target, and paths with no REST rule match as {@code null}
     * where noted below.
     */
    public String resolveRestRouteScope(ContainerRequestContext ctx) {
        String jsonScope = resolveJson11TargetCredentialScope(ctx);
        if (jsonScope != null) {
            return jsonScope;
        }

        String method = ctx.getMethod().toUpperCase();
        String path = ctx.getUriInfo().getPath();
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        if ("/".equals(path) && !"GET".equals(method)) {
            return null;
        }

        for (ActionRule rule : RULES) {
            if ("s3".equals(rule.service()) && !isS3BucketStylePath(path)) {
                continue;
            }
            if (rule.method().equals(method) && rule.pathPattern().matcher(path).find()) {
                return rule.service();
            }
        }
        return null;
    }

    /**
     * SigV4 credential scope implied by {@code X-Amz-Target}, independent of Authorization.
     */
    public String resolveJson11TargetCredentialScope(ContainerRequestContext ctx) {
        return resolveJson11TargetCredentialScope(ctx.getHeaderString("X-Amz-Target"));
    }

    public String resolveJson11TargetCredentialScope(String target) {
        if (target == null || target.isBlank() || !target.contains(".")) {
            return null;
        }
        return catalog.matchTarget(target)
                .map(match -> primaryCredentialScope(match.descriptor()))
                .orElse(null);
    }

    private static String primaryCredentialScope(ServiceDescriptor descriptor) {
        if (descriptor.credentialScopes().isEmpty()) {
            return descriptor.externalKey();
        }
        return descriptor.credentialScopes().iterator().next();
    }

    /**
     * S3 REST rules use {@code /{bucket}/key} shapes that also match other services (e.g.
     * {@code /restapis/{id}/resources}, {@code /applications/{id}}). Restrict S3 route
     * inference and action mapping to real bucket paths on the shared emulator endpoint.
     *
     * <p>{@code /v20180820} (S3 Control) is intentionally not excluded: AWS signs those
     * calls with credential scope {@code s3}.
     */
    static boolean isS3BucketStylePath(String path) {
        if (path == null || path.isBlank() || "/".equals(path)) {
            return true;
        }
        String normalized = path.startsWith("/") ? path : "/" + path;
        return !normalized.startsWith("/restapis")
                && !normalized.startsWith("/execute-api")
                && !normalized.startsWith("/_floci")
                && !normalized.startsWith("/_localstack")
                && !normalized.startsWith("/_aws")
                && !normalized.startsWith("/cognito-idp")
                && !"/health".equals(normalized)
                && !normalized.startsWith("/v1/")
                && !normalized.startsWith("/v2/")
                && !normalized.startsWith("/api/")
                // Function URLs only. Do not use "/lambda" — that excludes S3 buckets whose
                // names start with "lambda" (e.g. lambda-cred-allowed/object.txt).
                && !normalized.startsWith("/lambda-url")
                && !normalized.startsWith("/2015-03-31/")
                && !normalized.startsWith("/2013-04-01/")
                && !normalized.startsWith("/2017-10-31/")
                && !normalized.startsWith("/2018-10-31/")
                && !normalized.startsWith("/2019-09-25/")
                && !normalized.startsWith("/2019-09-30/")
                && !normalized.startsWith("/2017-03-31/")
                && !normalized.startsWith("/2020-06-30/")
                && !normalized.startsWith("/2021-10-31/")
                && !normalized.startsWith("/2021-01-01/")
                && !normalized.startsWith("/2020-05-31/")
                && !normalized.startsWith("/backup-vaults")
                && !normalized.startsWith("/backup/")
                && !normalized.startsWith("/clusters/")
                && !normalized.startsWith("/Execute")
                && !normalized.startsWith("/applications")
                && !normalized.startsWith("/things")
                && !normalized.startsWith("/schedules")
                && !normalized.startsWith("/schedule-groups")
                && !normalized.startsWith("/model/")
                && !normalized.startsWith("/policies")
                && !normalized.startsWith("/deploymentstrategies")
                && !normalized.startsWith("/configurationsessions")
                && !normalized.startsWith("/configuration")
                && !normalized.startsWith("/certificates")
                && !normalized.startsWith("/endpoint")
                && !normalized.startsWith("/topics/")
                && !normalized.startsWith("/retainedMessage")
                && !normalized.startsWith("/hostedzone")
                && !normalized.startsWith("/distribution")
                && !normalized.startsWith("/rules")
                && !S3_VECTORS_REST_PATHS.contains(normalized);
    }

    /**
     * Maps {@code ExecuteStatement} / {@code BatchExecuteStatement} to AWS PartiQL IAM actions
     * ({@code dynamodb:PartiQLSelect}, etc.) based on the leading statement keyword.
     *
     * @see <a href="https://docs.aws.amazon.com/amazondynamodb/latest/developerguide/ql-iam.html">PartiQL IAM</a>
     */
    /**
     * Resolves IAM actions for each statement in a {@code BatchExecuteStatement} body.
     */
    public List<String> resolveAllDynamoDbBatchActions(ContainerRequestContext ctx) {
        List<String> statementTexts = readAllPartiQLStatements(ctx);
        if (statementTexts.isEmpty()) {
            return List.of();
        }
        List<String> actions = new ArrayList<>(statementTexts.size());
        for (String statement : statementTexts) {
            String actionSuffix = mapPartiQLStatementToActionSuffix(statement);
            actions.add(actionSuffix != null ? "dynamodb:" + actionSuffix : null);
        }
        return Collections.unmodifiableList(actions);
    }

    static String resolveDynamoDbPartiQLAction(String operationName, ContainerRequestContext ctx) {
        if (!"ExecuteStatement".equals(operationName) && !"BatchExecuteStatement".equals(operationName)) {
            return null;
        }
        String statement = readPartiQLStatement(ctx);
        String actionSuffix = mapPartiQLStatementToActionSuffix(statement);
        if (actionSuffix == null) {
            return null;
        }
        return "dynamodb:" + actionSuffix;
    }

    /**
     * Maps a PartiQL statement to the AWS IAM action suffix (e.g. {@code PartiQLSelect}).
     */
    static String mapPartiQLStatementToActionSuffix(String statement) {
        if (statement == null || statement.isBlank()) {
            return null;
        }
        String trimmed = statement.trim();
        if (trimmed.regionMatches(true, 0, "SELECT", 0, 6)) {
            return "PartiQLSelect";
        }
        if (trimmed.regionMatches(true, 0, "INSERT", 0, 6)) {
            return "PartiQLInsert";
        }
        if (trimmed.regionMatches(true, 0, "UPDATE", 0, 6)) {
            return "PartiQLUpdate";
        }
        if (trimmed.regionMatches(true, 0, "DELETE", 0, 6)) {
            return "PartiQLDelete";
        }
        return null;
    }

    private static String readPartiQLStatement(ContainerRequestContext ctx) {
        List<String> all = readAllPartiQLStatements(ctx);
        return all.isEmpty() ? null : all.getFirst();
    }

    private static List<String> readAllPartiQLStatements(ContainerRequestContext ctx) {
        byte[] body = bufferBody(ctx);
        if (body == null || body.length == 0) {
            return List.of();
        }
        try {
            JsonNode node = OBJECT_MAPPER.readTree(body);
            JsonNode statements = node.get("Statements");
            if (statements != null && statements.isArray() && !statements.isEmpty()) {
                List<String> out = new ArrayList<>(statements.size());
                for (JsonNode entry : statements) {
                    if (entry != null) {
                        JsonNode statement = entry.get("Statement");
                        if (statement != null && statement.isTextual()) {
                            out.add(statement.asText());
                        }
                    }
                }
                return Collections.unmodifiableList(out);
            }
            JsonNode statement = node.get("Statement");
            if (statement != null && statement.isTextual()) {
                return List.of(statement.asText());
            }
        } catch (Exception ignored) {
        }
        return List.of();
    }

    private static byte[] bufferBody(ContainerRequestContext ctx) {
        byte[] body = RequestBodyBuffer.buffer(ctx);
        return body.length == 0 && ctx.getEntityStream() == null ? null : body;
    }

    /**
     * Reads {@code Action} from a {@code application/x-www-form-urlencoded}
     * request body and restores the entity stream so downstream consumers
     * (e.g. {@code AwsQueryController}'s {@code MultivaluedMap} injection)
     * can still parse the form themselves. Returns {@code null} if the
     * request is not form-encoded or the body has no {@code Action} field.
     */
    private static String readFormAction(ContainerRequestContext ctx) {
        MediaType mt = ctx.getMediaType();
        if (mt == null
                || !"application".equalsIgnoreCase(mt.getType())
                || !"x-www-form-urlencoded".equalsIgnoreCase(mt.getSubtype())) {
            return null;
        }
        byte[] body = RequestBodyBuffer.peek(ctx);
        if (body == null) {
            body = RequestBodyBuffer.buffer(ctx);
        }
        if (body.length == 0) {
            return null;
        }
        Charset charset = resolveCharset(mt);
        String form = new String(body, charset);
        for (String pair : form.split("&")) {
            int eq = pair.indexOf('=');
            String key = eq < 0 ? pair : pair.substring(0, eq);
            if (!"Action".equals(URLDecoder.decode(key, charset))) {
                continue;
            }
            return eq < 0 ? "" : URLDecoder.decode(pair.substring(eq + 1), charset);
        }
        return null;
    }

    private static Charset resolveCharset(MediaType mt) {
        String name = mt.getParameters().get("charset");
        if (name == null || name.isBlank()) {
            return StandardCharsets.UTF_8;
        }
        try {
            return Charset.forName(name);
        } catch (RuntimeException e) {
            return StandardCharsets.UTF_8;
        }
    }
}
