package io.github.hectorvent.floci.services.cloudtrail;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AccountResolver;
import io.github.hectorvent.floci.core.common.AwsException;
import io.github.hectorvent.floci.core.common.CtfHideInternalEndpointsMode;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.Context;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Operator-only routes to inject synthetic CloudTrail management events for audit exercise provisioning.
 */
@ApplicationScoped
@Path("_floci/cloudtrail/events")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class CloudTrailEventInjectionController {

    private static final Logger LOG = Logger.getLogger(CloudTrailEventInjectionController.class);

    private final EmulatorConfig config;
    private final AccountResolver accountResolver;
    private final CloudTrailEventInjectionService injectionService;

    @Inject
    public CloudTrailEventInjectionController(EmulatorConfig config,
                                              AccountResolver accountResolver,
                                              CloudTrailEventInjectionService injectionService) {
        this.config = config;
        this.accountResolver = accountResolver;
        this.injectionService = injectionService;
    }

    @POST
    public Response injectEvent(@Context ContainerRequestContext requestContext,
                                Map<String, Object> body) {
        Response gate = gateRequest(requestContext);
        if (gate != null) {
            return gate;
        }
        try {
            InjectionRequest request = parseRequest(body, false);
            CloudTrailEventInjectionService.InjectedEventResult result =
                    injectionService.injectEvent(
                            request.region(),
                            request.events().get(0),
                            request.preserveEventTime(),
                            request.deliverToTrails());
            return Response.ok(Map.of(
                    "eventId", result.eventId(),
                    "eventTime", result.eventTime())).build();
        } catch (AwsException e) {
            return Response.status(e.getHttpStatus())
                    .entity(Map.of("status", "error", "message", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOG.warnv("CloudTrail event injection failed: {0}", e.getMessage());
            return Response.status(500)
                    .entity(Map.of("status", "error", "message", "Injection failed"))
                    .build();
        }
    }

    @POST
    @Path("batch")
    public Response injectBatch(@Context ContainerRequestContext requestContext,
                                Map<String, Object> body) {
        Response gate = gateRequest(requestContext);
        if (gate != null) {
            return gate;
        }
        try {
            InjectionRequest request = parseRequest(body, true);
            List<CloudTrailEventInjectionService.InjectedEventResult> results =
                    injectionService.injectBatch(
                            request.region(),
                            request.events(),
                            request.preserveEventTime(),
                            request.deliverToTrails());
            List<Map<String, String>> events = results.stream()
                    .map(r -> Map.of("eventId", r.eventId(), "eventTime", r.eventTime()))
                    .toList();
            return Response.ok(Map.of("events", events)).build();
        } catch (AwsException e) {
            return Response.status(e.getHttpStatus())
                    .entity(Map.of("status", "error", "message", e.getMessage()))
                    .build();
        } catch (Exception e) {
            LOG.warnv("CloudTrail batch injection failed: {0}", e.getMessage());
            return Response.status(500)
                    .entity(Map.of("status", "error", "message", "Injection failed"))
                    .build();
        }
    }

    private Response gateRequest(ContainerRequestContext requestContext) {
        CtfHideInternalEndpointsMode hideMode = config.ctf().hideInternalEndpointsMode();
        String path = requestContext.getUriInfo().getPath();
        if (hideMode.hidesAnything() && hideMode.isPathHidden(path)) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        if (!config.ctf().cloudTrailInjectionEnabled()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
        String auth = requestContext.getHeaderString("Authorization");
        if (auth == null || auth.isBlank()) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("status", "error", "message", "Operator root credentials required"))
                    .build();
        }
        String akid = accountResolver.extractAccessKeyId(auth);
        if (akid == null || config.auth().rootAccessKeyId().filter(akid::equals).isEmpty()) {
            return Response.status(Response.Status.FORBIDDEN)
                    .entity(Map.of("status", "error", "message", "Operator root credentials required"))
                    .build();
        }
        if (config.auth().validateSignatures()) {
            var secret = config.auth().resolveRootSecretAccessKey();
            if (secret.isEmpty()) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(Map.of("status", "error", "message", "Operator root credentials required"))
                        .build();
            }
            byte[] body = RequestBodyBuffer.buffer(requestContext);
            SigV4RequestValidator.Result result = SigV4RequestValidator.validate(
                    requestContext.getMethod(),
                    requestContext.getUriInfo().getRequestUri().getRawPath(),
                    requestContext.getUriInfo().getRequestUri().getRawQuery(),
                    requestContext.getHeaders(),
                    auth,
                    secret.get(),
                    body);
            if (result != SigV4RequestValidator.Result.VALID) {
                return Response.status(Response.Status.FORBIDDEN)
                        .entity(Map.of("status", "error", "message", "SigV4 validation failed"))
                        .build();
            }
        }
        return null;
    }

    @SuppressWarnings("unchecked")
    private static InjectionRequest parseRequest(Map<String, Object> body, boolean batch) {
        if (body == null) {
            throw new AwsException("ValidationException", "Request body is required.", 400);
        }
        Object regionValue = body.get("region");
        if (regionValue == null || regionValue.toString().isBlank()) {
            throw new AwsException("ValidationException", "region is required.", 400);
        }
        boolean preserveEventTime = booleanField(body, "preserveEventTime", true);
        boolean deliverToTrails = booleanField(body, "deliverToTrails", true);
        List<Map<String, Object>> events;
        if (batch) {
            Object eventsNode = body.get("events");
            if (!(eventsNode instanceof List<?> list)) {
                throw new AwsException("ValidationException", "events array is required.", 400);
            }
            events = list.stream()
                    .filter(Map.class::isInstance)
                    .<Map<String, Object>>map(item -> new LinkedHashMap<>((Map<String, Object>) item))
                    .toList();
        } else {
            Object eventNode = body.get("event");
            if (!(eventNode instanceof Map<?, ?> map)) {
                throw new AwsException("ValidationException", "event object is required.", 400);
            }
            events = List.of(new LinkedHashMap<>((Map<String, Object>) eventNode));
        }
        return new InjectionRequest(regionValue.toString(), events, preserveEventTime, deliverToTrails);
    }

    private static boolean booleanField(Map<String, Object> body, String field, boolean defaultValue) {
        Object value = body.get(field);
        if (value == null) {
            return defaultValue;
        }
        if (value instanceof Boolean b) {
            return b;
        }
        return Boolean.parseBoolean(value.toString());
    }

    private record InjectionRequest(
            String region,
            List<Map<String, Object>> events,
            boolean preserveEventTime,
            boolean deliverToTrails) {
    }
}
