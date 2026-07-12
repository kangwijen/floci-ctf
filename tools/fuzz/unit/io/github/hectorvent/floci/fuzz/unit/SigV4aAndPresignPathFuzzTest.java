package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.core.common.SigV4aPresignSupport;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import jakarta.ws.rs.core.MultivaluedMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.util.ArrayList;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Presigned URL/POST classification and SigV4a helpers must stay crash-free and consistent.
 */
class SigV4aAndPresignPathFuzzTest {

    private static final IamActionRegistry IAM_REGISTRY = FuzzFixtures.iamActionRegistry();

    @Property(tries = 60)
    void presignedQueryClassificationNeverThrows(
            @ForAll("s3Paths") String path,
            @ForAll("algorithms") String algorithm,
            @ForAll @StringLength(max = 120) String extraQuery) throws Exception {
        MultivaluedMap<String, String> query = new MultivaluedHashMap<>();
        if (algorithm != null && !algorithm.isBlank()) {
            query.add("X-Amz-Algorithm", algorithm);
        }
        if (extraQuery != null && !extraQuery.isBlank()) {
            query.add("X-Amz-Signature", extraQuery);
        }
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery("GET", path, query);
        String seed = path + "|" + algorithm + "|" + extraQuery;
        CrashWatchdog.run("SigV4a.presign.classify", seed, 2000, () -> {
            SecurityOracle.runCatching("SigV4a.presign.classify", seed, () -> {
                SecurityBypassPaths.isPresignedUrlRequest(ctx);
                return null;
            });
            return null;
        });
    }

    @Property(tries = 40)
    void presignedUrlRequestConsistentWithAlgorithmParam(
            @ForAll("s3Paths") String path,
            @ForAll("algorithms") String algorithm) {
        MultivaluedMap<String, String> query = FuzzRequestContexts.queryOf("X-Amz-Algorithm", algorithm);
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery("GET", path, query);
        boolean classified = SecurityBypassPaths.isPresignedUrlRequest(ctx);
        if (!classified) {
            SecurityOracle.failSecurity(
                    "SigV4a.presign.algorithmKey",
                    path + "|" + algorithm,
                    "X-Amz-Algorithm present but isPresignedUrlRequest false",
                    Map.of());
        }
    }

    @Property(tries = 40)
    void multipartPostClassificationNeverThrows(
            @ForAll("postPaths") String path,
            @ForAll("multipartBodies") String body) throws Exception {
        MultivaluedMap<String, String> headers = new MultivaluedHashMap<>();
        headers.add("Content-Type", "multipart/form-data; boundary=----fuzz");
        ContainerRequestContext ctx = FuzzRequestContexts.ctx(
                "POST", path, new MultivaluedHashMap<>(),
                MediaType.valueOf("multipart/form-data; boundary=----fuzz"), body, null);
        String seed = path + "|" + body;
        CrashWatchdog.run("SigV4a.presign.multipart", seed, 2000, () -> {
            SecurityOracle.runCatching("SigV4a.presign.multipart", seed, () -> {
                SecurityBypassPaths.isMultipartBucketPostRequest(ctx);
                SecurityBypassPaths.isPresignedPostRequest(ctx);
                return null;
            });
            return null;
        });
    }

    @Property(tries = 30)
    void internalPathsAreNotMultipartBucketPosts(@ForAll("internalPaths") String path) {
        ContainerRequestContext ctx = FuzzRequestContexts.ctx(
                "POST", path, new MultivaluedHashMap<>(),
                MediaType.valueOf("multipart/form-data; boundary=----fuzz"),
                "name=\"policy\"\r\n", null);
        if (SecurityBypassPaths.isMultipartBucketPostRequest(ctx)) {
            SecurityOracle.failSecurity(
                    "SigV4a.presign.internalMultipart",
                    path,
                    "internal or health path classified as multipart bucket POST",
                    Map.of());
        }
    }

    @Property(tries = 50)
    void validatePresignedUrlNeverThrowsError(
            @ForAll("methods") String method,
            @ForAll("s3Paths") String path,
            @ForAll("presignQueries") String query,
            @ForAll @StringLength(min = 4, max = 40) String secret) throws Exception {
        String seed = method + "|" + path + "|" + query;
        CrashWatchdog.run("SigV4a.presign.validate", seed, 2000, () -> {
            SigV4RequestValidator.Result result = SecurityOracle.runCatching(
                    "SigV4a.presign.validate", seed, () ->
                            SigV4RequestValidator.validatePresignedUrl(
                                    method.isBlank() ? "GET" : method,
                                    path,
                                    query,
                                    "localhost:4566",
                                    secret,
                                    null));
            if (result == SigV4RequestValidator.Result.VALID) {
                SecurityOracle.failSecurity(
                        "SigV4a.presign.validate",
                        seed,
                        "garbage presigned query validated as VALID",
                        Map.of("algorithm", extractAlgorithm(query)));
            }
            return null;
        });
    }

    @Property(tries = 40)
    void validatePresignedUrlSigV4aNeverThrowsError(
            @ForAll("methods") String method,
            @ForAll("s3Paths") String path,
            @ForAll("presignQueries") String query) throws Exception {
        String seed = method + "|" + path + "|" + query;
        CrashWatchdog.run("SigV4a.presign.sigv4a", seed, 2000, () -> {
            SigV4RequestValidator.Result result = SecurityOracle.runCatching(
                    "SigV4a.presign.sigv4a", seed, () ->
                            SigV4RequestValidator.validatePresignedUrlSigV4a(
                                    method.isBlank() ? "GET" : method,
                                    path,
                                    query,
                                    "localhost:4566",
                                    null,
                                    Map.of()));
            if (result == SigV4RequestValidator.Result.VALID) {
                SecurityOracle.failSecurity(
                        "SigV4a.presign.sigv4a",
                        seed,
                        "garbage SigV4a presigned query validated as VALID",
                        Map.of());
            }
            return null;
        });
    }

    @Property(tries = 40)
    void sigV4aVerifyNeverThrowsOnGarbage(
            @ForAll @StringLength(max = 200) String stringToSign,
            @ForAll @StringLength(max = 200) String signatureHex) {
        SecurityOracle.runCatching("SigV4a.verify", stringToSign + "|" + signatureHex, () -> {
            SigV4aPresignSupport.verifyStringToSign(stringToSign, signatureHex, null);
            return null;
        });
    }

    @Property(tries = 30)
    void buildPresignedUrlStringToSignNeverThrowsOnGarbage(
            @ForAll @StringLength(max = 80) String method,
            @ForAll @StringLength(max = 120) String path,
            @ForAll @StringLength(max = 200) String query,
            @ForAll @StringLength(max = 80) String host,
            @ForAll @StringLength(max = 40) String amzDate,
            @ForAll @StringLength(max = 40) String signedHeaders,
            @ForAll @StringLength(max = 80) String credentialScope) {
        SecurityOracle.runCatching(
                "SigV4a.buildStringToSign",
                method + "|" + path,
                () -> {
                    try {
                        SigV4aPresignSupport.buildPresignedUrlStringToSign(
                                method.isBlank() ? "GET" : method,
                                path.isBlank() ? "/" : path,
                                query,
                                host.isBlank() ? "localhost:4566" : host,
                                amzDate,
                                signedHeaders,
                                credentialScope,
                                Map.of());
                    } catch (Exception ignored) {
                        // canonical builder may reject malformed input
                    }
                    return null;
                });
    }

    @Property(tries = 30)
    void presignedS3PathsAreNotBucketStyleForIam(
            @ForAll("s3Paths") String path) {
        if (!isProtectedFromS3(path)) {
            return;
        }
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery("GET", path, null);
        String scope = IAM_REGISTRY.resolveRestRouteScope(ctx);
        if ("s3".equals(scope)) {
            SecurityOracle.failSecurity(
                    "SigV4a.presign.s3Style",
                    path,
                    "protected path classified as S3 bucket-style for IAM",
                    Map.of("scope", scope));
        }
    }

    private static boolean isProtectedFromS3(String path) {
        String p = path == null ? "" : (path.startsWith("/") ? path : "/" + path);
        return p.startsWith("/_floci")
                || p.startsWith("/_localstack")
                || p.startsWith("/_aws")
                || p.startsWith("/cognito-idp")
                || p.startsWith("/v2/")
                || "/health".equals(p);
    }

    private static String extractAlgorithm(String query) {
        if (query == null) {
            return "";
        }
        for (String part : query.split("&")) {
            if (part.startsWith("X-Amz-Algorithm=")) {
                return part.substring("X-Amz-Algorithm=".length());
            }
        }
        return "";
    }

    @Provide
    Arbitrary<String> methods() {
        return Arbitraries.of("GET", "PUT", "POST", "HEAD", "DELETE");
    }

    @Provide
    Arbitrary<String> algorithms() {
        return Arbitraries.of(
                "AWS4-HMAC-SHA256",
                SigV4aPresignSupport.ALGORITHM,
                "AWS4-ECDSA-P256-SHA256",
                "AWS4-HMAC-SHA1",
                "HMAC-SHA256",
                "Bearer",
                "",
                "AWS4-HMAC-SHA256%20",
                "aws4-hmac-sha256");
    }

    @Provide
    Arbitrary<String> s3Paths() {
        Set<String> all = new LinkedHashSet<>();
        all.addAll(CorpusLoader.orFallback("rest/paths.txt", List.of()));
        all.addAll(List.of(
                "/fuzz-bucket/object",
                "/my-bucket/prefix/key.txt",
                "/bucket",
                "/bucket/key/with/slashes"));
        all.removeIf(p -> p.startsWith("/v2/") || p.startsWith("/_floci")
                || p.startsWith("/_localstack") || p.startsWith("/_aws")
                || "/health".equals(p));
        return Arbitraries.of(new ArrayList<>(all));
    }

    @Provide
    Arbitrary<String> postPaths() {
        return Arbitraries.of(
                "/fuzz-bucket",
                "/my-bucket",
                "/health",
                "/_floci/health",
                "/cognito-idp/oauth2/token",
                "/v2/fuzz-repo/manifests/latest");
    }

    @Provide
    Arbitrary<String> internalPaths() {
        return Arbitraries.of(CorpusLoader.orFallback("paths/internal.txt", List.of(
                "/health",
                "/_floci/health",
                "/_localstack/health",
                "/_aws/cloudformation/ready")));
    }

    @Provide
    Arbitrary<String> multipartBodies() {
        return Arbitraries.of(
                "",
                "name=\"policy\"\r\n",
                "name=\"Policy\"\r\n",
                "name=\"x-amz-algorithm\"\r\nAWS4-HMAC-SHA256\r\n",
                "name=\"key\"\r\nfuzz/object\r\n",
                "name=\"file\"; filename=\"x.txt\"\r\nhello\r\n");
    }

    @Provide
    Arbitrary<String> presignQueries() {
        List<String> samples = List.of(
                "X-Amz-Algorithm=AWS4-HMAC-SHA256&X-Amz-Credential=AKIATEST/20200101/us-east-1/s3/aws4_request"
                        + "&X-Amz-Date=20200101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host"
                        + "&X-Amz-Signature=deadbeef",
                "X-Amz-Algorithm=" + SigV4aPresignSupport.ALGORITHM
                        + "&X-Amz-Credential=AKIATEST/20200101/us-east-1/s3/aws4_request"
                        + "&X-Amz-Date=20200101T000000Z&X-Amz-Expires=3600&X-Amz-SignedHeaders=host"
                        + "&X-Amz-Signature=" + "a".repeat(128),
                "X-Amz-Algorithm=AWS4-HMAC-SHA256",
                "X-Amz-Algorithm=garbage&X-Amz-Signature=x",
                "",
                "foo=bar");
        return Arbitraries.oneOf(
                Arbitraries.of(samples),
                Arbitraries.strings().withCharRange('a', 'z').ofMaxLength(80)
                        .map(s -> "X-Amz-Algorithm=" + s + "&X-Amz-Signature=00"));
    }
}
