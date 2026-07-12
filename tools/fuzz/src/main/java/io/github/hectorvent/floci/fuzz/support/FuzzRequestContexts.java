package io.github.hectorvent.floci.fuzz.support;

import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import jakarta.ws.rs.core.UriInfo;
import org.mockito.Mockito;

import java.io.ByteArrayInputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.concurrent.atomic.AtomicReference;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doAnswer;
import static org.mockito.Mockito.when;

/**
 * Minimal JAX-RS request mocks shared by unit fuzz targets.
 */
public final class FuzzRequestContexts {

    private FuzzRequestContexts() {
    }

    public static ContainerRequestContext jsonBody(String method, String path, String body) {
        return ctx(method, path, new MultivaluedHashMap<>(),
                MediaType.valueOf("application/x-amz-json-1.1"), body, null);
    }

    public static ContainerRequestContext formBody(String method, String path, String body) {
        return ctx(method, path, new MultivaluedHashMap<>(),
                MediaType.APPLICATION_FORM_URLENCODED_TYPE, body, null);
    }

    public static ContainerRequestContext withQuery(String method, String path,
                                                    MultivaluedMap<String, String> query) {
        return ctx(method, path, query, null, "", null);
    }

    public static ContainerRequestContext withTarget(String method, String path, String target,
                                                     String body) {
        return ctx(method, path, new MultivaluedHashMap<>(),
                MediaType.valueOf("application/x-amz-json-1.1"), body, target);
    }

    public static ContainerRequestContext ctx(String method,
                                              String path,
                                              MultivaluedMap<String, String> query,
                                              MediaType contentType,
                                              String body,
                                              String amzTarget) {
        String normalizedPath = path == null ? "/" : path;
        if (!normalizedPath.startsWith("/")) {
            normalizedPath = "/" + normalizedPath;
        }
        byte[] bytes = body == null ? new byte[0] : body.getBytes(StandardCharsets.UTF_8);
        AtomicReference<InputStream> streamRef =
                new AtomicReference<>(new ByteArrayInputStream(bytes));

        ContainerRequestContext ctx = Mockito.mock(ContainerRequestContext.class);
        UriInfo uriInfo = Mockito.mock(UriInfo.class);
        when(ctx.getMethod()).thenReturn(method == null ? "POST" : method);
        when(ctx.getUriInfo()).thenReturn(uriInfo);
        when(uriInfo.getPath()).thenReturn(normalizedPath);
        when(uriInfo.getQueryParameters()).thenReturn(query == null ? new MultivaluedHashMap<>() : query);
        when(ctx.getMediaType()).thenReturn(contentType);
        when(ctx.getHeaderString("X-Amz-Target")).thenReturn(amzTarget);
        when(ctx.getHeaders()).thenReturn(new MultivaluedHashMap<>());
        try {
            when(ctx.getEntityStream()).thenAnswer(inv -> streamRef.get());
            doAnswer(inv -> {
                streamRef.set(inv.getArgument(0));
                return null;
            }).when(ctx).setEntityStream(any(InputStream.class));
        } catch (Exception e) {
            throw new IllegalStateException(e);
        }
        return ctx;
    }

    public static MultivaluedMap<String, String> queryOf(String key, String value) {
        MultivaluedMap<String, String> map = new MultivaluedHashMap<>();
        map.add(key, value);
        return map;
    }

    public static List<String> sampleScopes() {
        return FuzzCredentialScopes.allArnBuilderScopes();
    }
}
