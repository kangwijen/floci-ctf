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
import io.github.hectorvent.floci.services.ssm.SsmJsonHandler;
import io.github.hectorvent.floci.services.cloudtrail.CloudTrailEventRecorder;
import io.github.hectorvent.floci.services.cloudtrail.InProcessCloudTrailRecorder;
import io.github.hectorvent.floci.services.cloudtrail.model.InProcessAuditContext;
import io.github.hectorvent.floci.services.iam.InProcessIamAuthorizer;
import io.github.hectorvent.floci.services.stepfunctions.StepFunctionsJsonHandler;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
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
     * Parses an integration URI like
     * {@code arn:aws:apigateway:us-east-1:states:action/StartExecution}.
     *
     * @return parsed target, or null if the URI format is not recognized
     */
    public IntegrationTarget parseIntegrationUri(String uri) {
        if (uri == null || !uri.startsWith("arn:aws:apigateway:")) {
            return null;
        }
        // arn:aws:apigateway:{region}:{service}:action/{Action}
        String[] parts = uri.split(":");
        if (parts.length < 6) {
            return null;
        }
        String region = parts[3];
        String service = parts[4];
        // parts[5] should be "action/{ActionName}"
        String actionPart = parts[5];
        if (!actionPart.startsWith("action/")) {
            return null;
        }
        String action = actionPart.substring("action/".length());
        return new IntegrationTarget(region, service, action);
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
}
