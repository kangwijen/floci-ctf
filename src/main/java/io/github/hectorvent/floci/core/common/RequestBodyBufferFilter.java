package io.github.hectorvent.floci.core.common;

import jakarta.annotation.Priority;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

/**
 * Caches request entity bodies before handlers consume the stream so response
 * filters (CloudTrail audit) and IAM helpers can read form fields safely.
 */
@Provider
@Priority(Priorities.AUTHENTICATION - 10)
public class RequestBodyBufferFilter implements ContainerRequestFilter {

    @Override
    public void filter(ContainerRequestContext requestContext) {
        if (requestContext.getEntityStream() != null) {
            RequestBodyBuffer.buffer(requestContext);
        }
    }
}
