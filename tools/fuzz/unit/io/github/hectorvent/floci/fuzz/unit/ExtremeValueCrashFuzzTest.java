package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.core.common.CtfHideInternalEndpointsMode;
import io.github.hectorvent.floci.core.common.CtfVelocityEngineFactory;
import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.ExtremeValueGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzCredentialScopes;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import io.github.hectorvent.floci.services.iam.FederatedTokenParser;
import io.github.hectorvent.floci.services.iam.IamActionRegistry;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.ResourceArnBuilder;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.lambda.zip.ZipExtractor;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MultivaluedHashMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * Crash/hang oracles with extreme-value inputs. Security Allow/Deny oracles use
 * {@link io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators} instead.
 */
class ExtremeValueCrashFuzzTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "222222222222";
    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();
    private static final ResourceArnBuilder ARN_BUILDER = FuzzFixtures.resourceArnBuilder();
    private static final IamActionRegistry ACTION_REGISTRY = FuzzFixtures.iamActionRegistry();
    private static final IamPolicyEvaluator POLICY_EVALUATOR = new IamPolicyEvaluator(MAPPER);
    private static final ZipExtractor ZIP_EXTRACTOR = new ZipExtractor();

    @Property(tries = 40)
    void resourceArnBuilderExtremeNeverThrows(
            @ForAll("arnScopes") String scope,
            @ForAll("extremeBodies") String body) throws Exception {
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body == null ? "" : body);
        String seed = scope + "|" + truncate(body);
        CrashWatchdog.run("ExtremeValue.ResourceArnBuilder", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.ResourceArnBuilder", seed,
                    () -> ARN_BUILDER.build(scope, ctx, REGION, ACCOUNT));
            return null;
        });
    }

    @Property(tries = 1)
    void resourceArnBuilderOversized32kOnce(@ForAll("arnScopes") String scope) throws Exception {
        String body = ExtremeValueGenerators.oversizedSampleOnce().substring(0, 32768);
        ContainerRequestContext ctx = FuzzRequestContexts.jsonBody("POST", "/", body);
        String seed = scope + "|32k";
        CrashWatchdog.run("ExtremeValue.ResourceArnBuilder.32k", seed, 3000, () -> {
            SecurityOracle.runCatching("ExtremeValue.ResourceArnBuilder.32k", seed,
                    () -> ARN_BUILDER.build(scope, ctx, REGION, ACCOUNT));
            return null;
        });
    }

    @Property(tries = 40)
    void iamActionRegistryExtremeResolveNeverThrows(
            @ForAll("arnScopes") String scope,
            @ForAll("httpMethods") String method,
            @ForAll("extremePaths") String path,
            @ForAll("extremeBodies") String body) throws Exception {
        String normalized = normalizePath(path);
        ContainerRequestContext ctx = FuzzRequestContexts.formBody(method, normalized, body == null ? "" : body);
        String seed = scope + "|" + method + "|" + normalized + "|" + truncate(body);
        CrashWatchdog.run("ExtremeValue.IamActionRegistry.resolve", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.IamActionRegistry.resolve", seed,
                    () -> ACTION_REGISTRY.resolve(scope, ctx));
            return null;
        });
    }

    @Property(tries = 35)
    void iamActionRegistryExtremeRestRouteNeverThrows(
            @ForAll("httpMethods") String method,
            @ForAll("extremePaths") String path) throws Exception {
        String normalized = normalizePath(path);
        ContainerRequestContext ctx = FuzzRequestContexts.withQuery(method, normalized, new MultivaluedHashMap<>());
        String seed = method + "|" + normalized;
        CrashWatchdog.run("ExtremeValue.IamActionRegistry.restRoute", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.IamActionRegistry.restRoute", seed,
                    () -> ACTION_REGISTRY.resolveRestRouteScope(ctx));
            return null;
        });
    }

    @Property(tries = 40)
    void iamPolicyEvaluatorExtremeNeverThrows(
            @ForAll("policyActions") String action,
            @ForAll("extremeBodies") String policyDoc,
            @ForAll("extremePaths") String resource) throws Exception {
        CallerContext caller = new CallerContext(List.of(policyDoc == null ? "" : policyDoc), null, null);
        String resourceArn = resource == null || resource.isBlank()
                ? "arn:aws:s3:::bucket/key"
                : "arn:aws:s3:::" + resource.replace('\\', '/');
        String seed = action + "|" + truncate(policyDoc) + "|" + truncate(resource);
        CrashWatchdog.run("ExtremeValue.IamPolicyEvaluator", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.IamPolicyEvaluator", seed, () ->
                    POLICY_EVALUATOR.evaluate(caller, List.of(), action, resourceArn, Map.of()));
            return null;
        });
    }

    @Property(tries = 45)
    void sigV4ValidatorExtremeNeverThrows(
            @ForAll("extremePaths") String method,
            @ForAll("extremePaths") String path,
            @ForAll("extremeBodies") String query,
            @ForAll("extremeBodies") String authHeader,
            @ForAll("extremeBodies") String secret) throws Exception {
        String seed = truncate(method) + "|" + truncate(path) + "|" + truncate(authHeader);
        MultivaluedHashMap<String, String> headers = new MultivaluedHashMap<>();
        if (authHeader != null) {
            headers.add("authorization", authHeader);
        }
        headers.add("host", "localhost:4566");
        CrashWatchdog.run("ExtremeValue.SigV4RequestValidator", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.SigV4RequestValidator", seed, () ->
                    SigV4RequestValidator.validate(
                            method == null || method.isBlank() ? "GET" : method,
                            path == null || path.isBlank() ? "/" : normalizePath(path),
                            query == null ? "" : query,
                            headers,
                            authHeader == null ? "" : authHeader,
                            secret == null || secret.isBlank() ? "secret" : secret,
                            (query == null ? "" : query).getBytes(StandardCharsets.UTF_8)));
            return null;
        });
    }

    @Property(tries = 40)
    void securityBypassPathsExtremeNeverThrows(@ForAll("extremePaths") String path) throws Exception {
        String seed = truncate(path);
        CrashWatchdog.run("ExtremeValue.SecurityBypassPaths", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.SecurityBypassPaths.normalize", seed, () ->
                    SecurityBypassPaths.normalizePath(path));
            SecurityOracle.runCatching("ExtremeValue.SecurityBypassPaths.internal", seed, () ->
                    SecurityBypassPaths.isInternalHealthOrInfoPath(path));
            SecurityOracle.runCatching("ExtremeValue.SecurityBypassPaths.prefixed", seed, () ->
                    SecurityBypassPaths.isPrefixedInternalPath(SecurityBypassPaths.normalizePath(path)));
            SecurityOracle.runCatching("ExtremeValue.SecurityBypassPaths.oauth", seed, () ->
                    SecurityBypassPaths.isCognitoOAuthPath(path));
            return null;
        });
    }

    @Property(tries = 35)
    void ctfHideInternalEndpointsExtremeNeverThrows(
            @ForAll("hideModes") CtfHideInternalEndpointsMode mode,
            @ForAll("extremePaths") String path) throws Exception {
        String seed = mode + "|" + truncate(path);
        CrashWatchdog.run("ExtremeValue.CtfHideInternalEndpointsMode", seed, 2500, () -> {
            SecurityOracle.runCatching("ExtremeValue.CtfHideInternalEndpointsMode", seed, () ->
                    mode.isPathHidden(path));
            return null;
        });
    }

    @Property(tries = 30)
    void zipExtremeTraversalNeverThrows(@ForAll("extremePaths") String entryName) throws Exception {
        Path target = Files.createTempDirectory("fuzz-zip-extreme-");
        try {
            String entry = entryName == null ? "../x" : entryName;
            byte[] zip;
            try {
                zip = zipWithEntry(entry, "pwned".getBytes(StandardCharsets.UTF_8));
            } catch (Exception ignored) {
                return;
            }
            String seed = entry;
            CrashWatchdog.run("ExtremeValue.ZipExtractor", seed, 2500, () -> {
                try {
                    ZIP_EXTRACTOR.extractTo(zip, target);
                } catch (Exception ignored) {
                    // Rejection is fine.
                }
                return null;
            });
        } finally {
            deleteRecursive(target);
        }
    }

    @Property(tries = 30)
    void vtlExtremeNeverThrows(@ForAll("extremeBodies") String noise) throws Exception {
        VelocityEngine engine = CtfVelocityEngineFactory.create("fuzz-vtl-extreme");
        String template = "#set($x=\"" + (noise == null ? "" : noise.replace("\"", "")) + "\")"
                + "#set($rt = $class.inspect(\"java.lang.Runtime\"))"
                + "$rt.getRuntime().exec(\"echo fuzz\")";
        CrashWatchdog.run("ExtremeValue.CtfVelocityEngineFactory", template, 2500, () -> {
            StringWriter out = new StringWriter();
            VelocityContext ctx = new VelocityContext();
            try {
                engine.evaluate(ctx, out, "fuzz-extreme", template);
            } catch (Exception ignored) {
                // Sandbox errors are success.
            }
            return null;
        });
    }

    @Property(tries = 35)
    void federatedTokenParserExtremeNeverThrows(@ForAll("extremeBodies") String token) throws Exception {
        String seed = truncate(token);
        CrashWatchdog.run("ExtremeValue.FederatedTokenParser.webIdentity", seed, 2500, () -> {
            try {
                FederatedTokenParser.parseWebIdentityToken(token, "example.com", ACCOUNT);
            } catch (RuntimeException ignored) {
                // Expected for malformed tokens.
            }
            return null;
        });
    }

    @Property(tries = 25)
    void federatedTokenParserExtremeSamlNeverThrows(@ForAll("extremeBodies") String xmlish) throws Exception {
        String raw = xmlish == null ? "" : xmlish;
        String b64 = Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
        CrashWatchdog.run("ExtremeValue.FederatedTokenParser.saml", b64, 2500, () -> {
            try {
                FederatedTokenParser.parseSamlAssertion(
                        b64, "arn:aws:iam::" + ACCOUNT + ":saml-provider/Example");
            } catch (RuntimeException ignored) {
                // Expected.
            }
            return null;
        });
    }

    @Property(tries = 20)
    void mqttConnectFrameVariantsAreWellFormed(@ForAll("mqttFrames") byte[] frame) {
        if (frame == null || frame.length < 2) {
            return;
        }
        SecurityOracle.runCatching("ExtremeValue.mqttConnectFrame", String.valueOf(frame.length), () -> {
            if (frame[0] != 0x10) {
                throw new IllegalStateException("not CONNECT");
            }
            return frame.length;
        });
    }

    @Provide
    Arbitrary<String> arnScopes() {
        return Arbitraries.of(FuzzCredentialScopes.allArnBuilderScopes());
    }

    @Provide
    Arbitrary<String> extremeBodies() {
        return ExtremeValueGenerators.extremeBodies();
    }

    @Provide
    Arbitrary<String> extremePaths() {
        return ExtremeValueGenerators.extremePaths();
    }

    @Provide
    Arbitrary<String> httpMethods() {
        return Arbitraries.of("GET", "POST", "PUT", "DELETE", "HEAD", "PATCH");
    }

    @Provide
    Arbitrary<String> policyActions() {
        return Arbitraries.of(
                "s3:GetObject", "s3:PutObject", "sqs:ReceiveMessage", "kms:Decrypt", "iam:GetUser", "*");
    }

    @Provide
    Arbitrary<CtfHideInternalEndpointsMode> hideModes() {
        return Arbitraries.of(CtfHideInternalEndpointsMode.values());
    }

    @Provide
    Arbitrary<byte[]> mqttFrames() {
        return ExtremeValueGenerators.mqttConnectFrameVariants();
    }

    private static String normalizePath(String path) {
        if (path == null || path.isBlank()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    private static String truncate(String value) {
        if (value == null) {
            return "null";
        }
        return value.length() <= 120 ? value : value.substring(0, 120) + "...";
    }

    private static byte[] zipWithEntry(String name, byte[] content) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
            zos.putNextEntry(new ZipEntry(name));
            zos.write(content);
            zos.closeEntry();
        }
        return bos.toByteArray();
    }

    private static void deleteRecursive(Path root) throws Exception {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        }
    }
}
