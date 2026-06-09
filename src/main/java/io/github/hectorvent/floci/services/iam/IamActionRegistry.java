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
import java.util.regex.Pattern;

import io.github.hectorvent.floci.core.common.IamUnrestrictedActions;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import org.jboss.logging.Logger;

import jakarta.enterprise.context.ApplicationScoped;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;

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

    private record ActionRule(String service, String method, Pattern pathPattern, String action) {}

    private static final List<ActionRule> RULES = List.of(
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

        // ── Lambda ──────────────────────────────────────────────────────────────
        rule("lambda", "GET",    ".*/functions$",                          "lambda:ListFunctions"),
        rule("lambda", "POST",   ".*/functions$",                          "lambda:CreateFunction"),
        rule("lambda", "GET",    ".*/functions/[^/]+$",                    "lambda:GetFunction"),
        rule("lambda", "PUT",    ".*/functions/[^/]+/code$",               "lambda:UpdateFunctionCode"),
        rule("lambda", "PUT",    ".*/functions/[^/]+/configuration$",      "lambda:UpdateFunctionConfiguration"),
        rule("lambda", "DELETE", ".*/functions/[^/]+$",                    "lambda:DeleteFunction"),
        rule("lambda", "POST",   ".*/functions/[^/]+/invocations$",        "lambda:InvokeFunction"),
        rule("lambda", "GET",    ".*/functions/[^/]+/aliases$",            "lambda:ListAliases"),
        rule("lambda", "POST",   ".*/functions/[^/]+/aliases$",            "lambda:CreateAlias"),
        rule("lambda", "GET",    ".*/functions/[^/]+/aliases/[^/]+$",      "lambda:GetAlias"),
        rule("lambda", "PUT",    ".*/functions/[^/]+/aliases/[^/]+$",      "lambda:UpdateAlias"),
        rule("lambda", "DELETE", ".*/functions/[^/]+/aliases/[^/]+$",      "lambda:DeleteAlias"),
        rule("lambda", "GET",    ".*/functions/[^/]+/policy$",             "lambda:GetPolicy"),
        rule("lambda", "POST",   ".*/functions/[^/]+/policy$",             "lambda:AddPermission"),
        rule("lambda", "DELETE", ".*/functions/[^/]+/policy/.+",           "lambda:RemovePermission"),
        rule("lambda", "GET",    ".*/event-source-mappings$",              "lambda:ListEventSourceMappings"),
        rule("lambda", "POST",   ".*/event-source-mappings$",              "lambda:CreateEventSourceMapping"),
        rule("lambda", "DELETE", ".*/event-source-mappings/[^/]+$",        "lambda:DeleteEventSourceMapping"),
        rule("lambda", "GET",    ".*/functions/[^/]+/url$",                "lambda:GetFunctionUrlConfig"),
        rule("lambda", "POST",   ".*/functions/[^/]+/url$",                "lambda:CreateFunctionUrlConfig"),
        rule("lambda", "PUT",    ".*/functions/[^/]+/url$",                "lambda:UpdateFunctionUrlConfig"),
        rule("lambda", "DELETE", ".*/functions/[^/]+/url$",                "lambda:DeleteFunctionUrlConfig"),

        // ── DynamoDB (JSON 1.1, action from X-Amz-Target handled separately) ──
        // Handled via Query-style action extraction in the filter

        // ── API Gateway ────────────────────────────────────────────────────────
        rule("apigateway", "GET",    ".*/account$",                       "apigateway:GET"),
        rule("apigateway", "PATCH",  ".*/account$",                       "apigateway:PATCH"),
        rule("apigateway", "GET",    ".*/restapis$",                        "apigateway:GET"),
        rule("apigateway", "POST",   ".*/restapis$",                        "apigateway:POST"),
        rule("apigateway", "GET",    ".*/restapis/.+",                      "apigateway:GET"),
        rule("apigateway", "PUT",    ".*/restapis/.+",                      "apigateway:PUT"),
        rule("apigateway", "PATCH",  ".*/restapis/.+",                      "apigateway:PATCH"),
        rule("apigateway", "DELETE", ".*/restapis/.+",                      "apigateway:DELETE"),
        rule("apigateway", "POST",   ".*/restapis/.+",                      "apigateway:POST"),

        // ── Kinesis ────────────────────────────────────────────────────────────
        rule("kinesis", "POST", ".*", "kinesis:*"),

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

        // ── EKS (REST JSON) ────────────────────────────────────────────────────
        rule("eks", "POST",   "^/clusters/?$",                                    "eks:CreateCluster"),
        rule("eks", "GET",    "^/clusters/?$",                                    "eks:ListClusters"),
        rule("eks", "GET",    "^/clusters/[^/]+/?$",                              "eks:DescribeCluster"),
        rule("eks", "DELETE", "^/clusters/[^/]+/?$",                              "eks:DeleteCluster"),
        rule("eks", "POST",   "^/clusters/[^/]+/node-groups/?$",                  "eks:CreateNodegroup"),
        rule("eks", "GET",    "^/clusters/[^/]+/node-groups/?$",                  "eks:ListNodegroups"),
        rule("eks", "GET",    "^/clusters/[^/]+/node-groups/[^/]+/?$",            "eks:DescribeNodegroup"),
        rule("eks", "DELETE", "^/clusters/[^/]+/node-groups/[^/]+/?$",            "eks:DeleteNodegroup")
    );

    private static ActionRule rule(String service, String method, String path, String action) {
        return new ActionRule(service, method, Pattern.compile(path, Pattern.CASE_INSENSITIVE), action);
    }

    /**
     * Maps S3 versioning and list-versions calls to AWS IAM actions
     * ({@code s3:ListBucketVersions}, {@code s3:GetObjectVersion}, {@code s3:PutBucketVersioning}).
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

        // JSON 1.1: X-Amz-Target → service:OperationName
        String target = ctx.getHeaderString("X-Amz-Target");
        if (target != null && target.contains(".")) {
            String operationName = target.substring(target.lastIndexOf('.') + 1);
            if ("dynamodb".equals(credentialScope)) {
                String partiqlAction = resolveDynamoDbPartiQLAction(operationName, ctx);
                if (partiqlAction != null) {
                    return partiqlAction;
                }
            }
            return IamUnrestrictedActions.canonicalAction(credentialScope + ":" + operationName);
        }

        // S3: query params disambiguate versioning APIs (AWS IAM action names).
        if ("s3".equals(credentialScope)) {
            String s3Action = resolveS3Action(ctx);
            if (s3Action != null) {
                return s3Action;
            }
        }

        // REST-JSON: match against rule table
        String method = ctx.getMethod().toUpperCase();
        String path   = ctx.getUriInfo().getPath();
        if (!path.startsWith("/")) path = "/" + path;

        for (ActionRule rule : RULES) {
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
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            return null;
        }
        byte[] body;
        try {
            body = in.readAllBytes();
        } catch (IOException e) {
            LOG.debugv(e, "Failed to buffer form body for IAM action resolution");
            return null;
        }
        ctx.setEntityStream(new ByteArrayInputStream(body));
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
