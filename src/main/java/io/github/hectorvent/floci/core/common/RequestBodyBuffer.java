package io.github.hectorvent.floci.core.common;

import jakarta.ws.rs.container.ContainerRequestContext;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Caches the request entity body on the JAX-RS context so SigV4, IAM action
 * resolution, and ARN builders do not re-read the stream.
 */
public final class RequestBodyBuffer {

    public static final String PROPERTY = "floci.request.body";

    private RequestBodyBuffer() {
    }

    public static byte[] buffer(ContainerRequestContext ctx) {
        Object cached = ctx.getProperty(PROPERTY);
        if (cached instanceof byte[] bytes) {
            return bytes;
        }
        InputStream in = ctx.getEntityStream();
        if (in == null) {
            byte[] empty = new byte[0];
            ctx.setProperty(PROPERTY, empty);
            return empty;
        }
        try {
            byte[] body = in.readAllBytes();
            ctx.setProperty(PROPERTY, body);
            ctx.setEntityStream(new ByteArrayInputStream(body));
            return body;
        } catch (IOException e) {
            byte[] empty = new byte[0];
            ctx.setProperty(PROPERTY, empty);
            return empty;
        }
    }
}
