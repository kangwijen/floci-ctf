package io.github.hectorvent.floci.services.apigateway;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.services.acm.AcmJsonHandler;
import io.github.hectorvent.floci.services.cloudwatch.logs.CloudWatchLogsHandler;
import io.github.hectorvent.floci.services.cloudwatch.metrics.CloudWatchMetricsJsonHandler;
import io.github.hectorvent.floci.services.cognito.CognitoJsonHandler;
import io.github.hectorvent.floci.services.dynamodb.DynamoDbJsonHandler;
import io.github.hectorvent.floci.services.eventbridge.EventBridgeHandler;
import io.github.hectorvent.floci.services.kinesis.KinesisJsonHandler;
import io.github.hectorvent.floci.services.kms.KmsJsonHandler;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerJsonHandler;
import io.github.hectorvent.floci.services.sns.SnsJsonHandler;
import io.github.hectorvent.floci.services.sqs.SqsJsonHandler;
import io.github.hectorvent.floci.services.sqs.SqsQueryHandler;
import io.github.hectorvent.floci.services.ssm.SsmJsonHandler;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailEventRecorder;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.stepfunctions.StepFunctionsJsonHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.Map;

/**
 * Routes API Gateway AWS integration requests to the correct internal service handler.
 *
 * <p>Parses integration URIs of the form
 * {@code arn:aws:apigateway:{region}:{service}:action/{ActionName}}
 * and dispatches to the matching JSON handler.
 */
@ApplicationScoped
public class AwsServiceRouter {

    private static final Logger LOG = Logger.getLogger(AwsServiceRouter.class);

    private final StepFunctionsJsonHandler stepFunctionsHandler;
    private final DynamoDbJsonHandler dynamoDbHandler;
    private final SqsJsonHandler sqsHandler;
    private final SqsQueryHandler sqsQueryHandler;
    private final SnsJsonHandler snsHandler;
    private final EventBridgeHandler eventBridgeHandler;
    private final SsmJsonHandler ssmHandler;
    private final KinesisJsonHandler kinesisHandler;
    private final CloudWatchLogsHandler logsHandler;
    private final CloudWatchMetricsJsonHandler metricsHandler;
    private final SecretsManagerJsonHandler secretsManagerHandler;
    private final KmsJsonHandler kmsHandler;
    private final CognitoJsonHandler cognitoHandler;
    private final AcmJsonHandler acmHandler;
    private final InProcessIamAuthorizer inProcessIamAuthorizer;
    private final InProcessCloudTrailRecorder inProcessCloudTrailRecorder;
    private final ObjectMapper objectMapper;

    @Inject
    public AwsServiceRouter(StepFunctionsJsonHandler stepFunctionsHandler,
                            DynamoDbJsonHandler dynamoDbHandler,
                            SqsJsonHandler sqsHandler,
                            SqsQueryHandler sqsQueryHandler,
                            SnsJsonHandler snsHandler,
                            EventBridgeHandler eventBridgeHandler,
                            SsmJsonHandler ssmHandler,
                            KinesisJsonHandler kinesisHandler,
                            CloudWatchLogsHandler logsHandler,
                            CloudWatchMetricsJsonHandler metricsHandler,
                            SecretsManagerJsonHandler secretsManagerHandler,
                            KmsJsonHandler kmsHandler,
                            CognitoJsonHandler cognitoHandler,
                            AcmJsonHandler acmHandler,
                            InProcessIamAuthorizer inProcessIamAuthorizer,
                            InProcessCloudTrailRecorder inProcessCloudTrailRecorder,
                            ObjectMapper objectMapper) {
        this.stepFunctionsHandler = stepFunctionsHandler;
        this.dynamoDbHandler = dynamoDbHandler;
        this.sqsHandler = sqsHandler;
        this.sqsQueryHandler = sqsQueryHandler;
        this.snsHandler = snsHandler;
        this.eventBridgeHandler = eventBridgeHandler;
        this.ssmHandler = ssmHandler;
        this.kinesisHandler = kinesisHandler;
        this.logsHandler = logsHandler;
        this.metricsHandler = metricsHandler;
        this.secretsManagerHandler = secretsManagerHandler;
        this.kmsHandler = kmsHandler;
        this.cognitoHandler = cognitoHandler;
        this.acmHandler = acmHandler;
        this.inProcessIamAuthorizer = inProcessIamAuthorizer;
        this.inProcessCloudTrailRecorder = inProcessCloudTrailRecorder;
        this.objectMapper = objectMapper;
    }

    /**
     * Parsed components of an API Gateway AWS integration URI.
     */
    public record IntegrationTarget(String region, String service, String action) {}

    /**
     * Parses an integration URI in either of the two forms AWS accepts:
     *
     * <ul>
     *   <li><b>action</b> — {@code arn:aws:apigateway:{region}:{service}:action/{Action}}.
     *       The action is encoded in the URI and the request template renders a JSON body.</li>
     *   <li><b>path</b> — {@code arn:aws:apigateway:{region}:{service}:path/{resourcePath}}.
     *       The action is not in the URI; it is carried in the rendered request body
     *       (the AWS query protocol, e.g. {@code Action=SendMessage&...}). For this form
     *       {@link IntegrationTarget#action()} is {@code null}.</li>
     * </ul>
     *
     * @return parsed target, or null if the URI format is not recognized
     */
    public IntegrationTarget parseIntegrationUri(String uri) {
        if (uri == null || !uri.startsWith("arn:aws:apigateway:")) {
            return null;
        }
        // arn:aws:apigateway:{region}:{service}:{action/{Action}|path/{resourcePath}}
        String[] parts = uri.split(":");
        if (parts.length < 6) {
            return null;
        }
        String region = parts[3];
        String service = parts[4];
        // parts[5] is either "action/{ActionName}" or "path/{resourcePath}".
        // A path may itself contain ':' (rare), so re-join the remainder.
        String resourceSpec = parts.length > 6
                ? String.join(":", java.util.Arrays.copyOfRange(parts, 5, parts.length))
                : parts[5];
        if (resourceSpec.startsWith("action/")) {
            String action = resourceSpec.substring("action/".length());
            return new IntegrationTarget(region, service, action);
        }
        if (resourceSpec.startsWith("path/")) {
            // Action is supplied by the rendered request body (query protocol).
            return new IntegrationTarget(region, service, null);
        }
        return null;
    }

    /**
     * Dispatches to the appropriate service handler.
     *
     * @param service     the AWS service name from the URI (e.g., "states", "dynamodb")
     * @param action      the action name (e.g., "StartExecution", "PutItem")
     * @param requestBody the JSON request body
     * @param region      the AWS region
     * @return the service response
     */
    public Response invoke(String service, String action, JsonNode requestBody, String region) {
        return invoke(service, action, requestBody, region, null);
    }

    /**
     * Dispatches to the appropriate service handler with optional execution-role IAM checks.
     *
     * @param roleArn IAM role whose policies authorize the downstream call (APIGW credentials / SFN role)
     */
    public Response invoke(String service, String action, JsonNode requestBody, String region, String roleArn) {
        LOG.debugv("AWS integration dispatch: {0}:{1} in {2}", service, action, region);

        inProcessIamAuthorizer.authorize(roleArn, service, action, requestBody, region);

        try {
            Response response = switch (service) {
                case "states" -> stepFunctionsHandler.handle(action, requestBody, region);
                case "dynamodb" -> dynamoDbHandler.handle(action, requestBody, region);
                case "sqs" -> sqsHandler.handle(action, requestBody, region);
                case "sns" -> snsHandler.handle(action, requestBody, region);
                case "events" -> eventBridgeHandler.handle(action, requestBody, region);
                case "ssm" -> ssmHandler.handle(action, requestBody, region);
                case "kinesis" -> kinesisHandler.handle(action, requestBody, region);
                case "logs" -> logsHandler.handle(action, requestBody, region);
                case "monitoring" -> metricsHandler.handle(action, requestBody, region);
                case "secretsmanager" -> secretsManagerHandler.handle(action, requestBody, region);
                case "kms" -> kmsHandler.handle(action, requestBody, region);
                case "cognito-idp" -> cognitoHandler.handle(action, requestBody, region);
                case "acm" -> acmHandler.handle(action, requestBody, region);
                default -> throw new AwsException("UnknownService",
                        "Unsupported AWS service integration: " + service, 400);
            };
            recordApigwApiCall(service, action, requestBody, region, roleArn, response);
            return response;
        } catch (AwsException e) {
            recordApigwApiCall(service, action, requestBody, region, roleArn, e.getErrorCode());
            throw e;
        } catch (Exception e) {
            recordApigwApiCall(service, action, requestBody, region, roleArn, "InternalError");
            throw new AwsException("InternalError",
                    e.getMessage() != null ? e.getMessage() : "Service invocation failed", 500);
        }
    }

    private void recordApigwApiCall(String service,
                                    String action,
                                    JsonNode requestBody,
                                    String region,
                                    String roleArn,
                                    Response response) {
        String errorCode = null;
        if (response.getStatus() >= 400) {
            errorCode = "ServiceException";
            Object entity = response.getEntity();
            if (entity instanceof com.fasterxml.jackson.databind.JsonNode errorNode) {
                errorCode = errorNode.path("__type").asText(errorCode);
            }
        }
        recordApigwApiCall(service, action, requestBody, region, roleArn, errorCode);
    }

    private void recordApigwApiCall(String service,
                                    String action,
                                    JsonNode requestBody,
                                    String region,
                                    String roleArn,
                                    String errorCode) {
        String pascalAction = action != null && !action.isEmpty()
                ? Character.toUpperCase(action.charAt(0)) + action.substring(1)
                : action;
        Map<String, Object> params = jsonToRequestParameters(requestBody);
        InProcessAuditContext.Builder builder = InProcessAuditContext.builder()
                .region(region)
                .eventName(pascalAction)
                .credentialScope(service)
                .requestParameters(params)
                .errorCode(errorCode)
                .invokedBy("apigateway.amazonaws.com")
                .executionRoleArn(roleArn);
        String eventSource = CloudTrailEventRecorder.toEventSource(service);
        if (CloudTrailEventRecorder.isDataEvent(eventSource, pascalAction, null)) {
            builder.managementEvent(false).eventCategory("Data");
        }
        inProcessCloudTrailRecorder.record(builder.build());
    }

    private Map<String, Object> jsonToRequestParameters(JsonNode requestBody) {
        if (requestBody == null || requestBody.isNull() || requestBody.isMissingNode()) {
            return Map.of();
        }
        return objectMapper.convertValue(requestBody, new TypeReference<Map<String, Object>>() {});
    }

    public Response invokeQuery(String service, MultivaluedMap<String, String> params, String region) {
        return invokeQuery(service, params, region, null);
    }

    /**
     * Dispatches an AWS query-protocol (form-encoded) integration request with optional
     * execution-role IAM checks.
     */
    public Response invokeQuery(String service,
                                MultivaluedMap<String, String> params,
                                String region,
                                String roleArn) {
        String action = params.getFirst("Action");
        LOG.debugv("AWS query integration dispatch: {0}:{1} in {2}", service, action, region);

        if (action == null || action.isBlank()) {
            throw new AwsException("MissingAction",
                    "The request must contain the parameter Action", 400);
        }

        inProcessIamAuthorizer.authorizeQuery(roleArn, service, action, params, region);

        try {
            Response response = switch (service) {
                case "sqs" -> sqsQueryHandler.handle(action, params, region);
                default -> throw new AwsException("UnknownService",
                        "Unsupported AWS query-protocol service integration: " + service, 400);
            };
            recordApigwQueryCall(service, action, params, region, roleArn, response);
            return response;
        } catch (AwsException e) {
            recordApigwQueryCall(service, action, params, region, roleArn, e.getErrorCode());
            throw e;
        } catch (Exception e) {
            recordApigwQueryCall(service, action, params, region, roleArn, "InternalError");
            throw new AwsException("InternalError",
                    e.getMessage() != null ? e.getMessage() : "Service invocation failed", 500);
        }
    }

    private void recordApigwQueryCall(String service,
                                      String action,
                                      MultivaluedMap<String, String> params,
                                      String region,
                                      String roleArn,
                                      Response response) {
        String errorCode = null;
        if (response.getStatus() >= 400) {
            errorCode = "ServiceException";
        }
        recordApigwQueryCall(service, action, params, region, roleArn, errorCode);
    }

    private void recordApigwQueryCall(String service,
                                      String action,
                                      MultivaluedMap<String, String> params,
                                      String region,
                                      String roleArn,
                                      String errorCode) {
        Map<String, Object> requestParams = new java.util.LinkedHashMap<>();
        if (params != null) {
            params.forEach((key, values) -> {
                if (values != null && !values.isEmpty()) {
                    requestParams.put(key, values.getFirst());
                }
            });
        }
        String pascalAction = action != null && !action.isEmpty()
                ? Character.toUpperCase(action.charAt(0)) + action.substring(1)
                : action;
        InProcessAuditContext.Builder builder = InProcessAuditContext.builder()
                .region(region)
                .eventName(pascalAction)
                .credentialScope(service)
                .requestParameters(requestParams)
                .errorCode(errorCode)
                .invokedBy("apigateway.amazonaws.com")
                .executionRoleArn(roleArn);
        String eventSource = CloudTrailEventRecorder.toEventSource(service);
        if (CloudTrailEventRecorder.isDataEvent(eventSource, pascalAction, null)) {
            builder.managementEvent(false).eventCategory("Data");
        }
        inProcessCloudTrailRecorder.record(builder.build());
    }
}
