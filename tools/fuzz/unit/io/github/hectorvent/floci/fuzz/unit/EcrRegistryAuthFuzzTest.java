package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthService;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthSession;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthTokenStore;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthorizer;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryRouteResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * ECR registry {@code Authorization: Basic AWS:token} parsing and IAM authorize oracles.
 */
class EcrRegistryAuthFuzzTest {

  private static final String ACCOUNT = "000000000000";
  private static final String REGION = "us-east-1";
  private static final String HOST = ACCOUNT + ".dkr.ecr." + REGION + ".localhost:5100";

  private static final EcrRegistryRouteResolver RESOLVER = FuzzFixtures.ecrRegistryRouteResolver();
  private static final EcrRegistryAuthService AUTH_SERVICE =
          new EcrRegistryAuthService(new EcrRegistryAuthTokenStore());

  @Property(tries = 80)
  void authenticateNeverThrowsError(@ForAll("authorizationHeaders") String header) throws Exception {
    String seed = header == null ? "<null>" : header;
    CrashWatchdog.run("EcrAuth.authenticate", seed, 2000, () -> {
      SecurityOracle.runCatching("EcrAuth.authenticate", seed, () -> AUTH_SERVICE.authenticate(header));
      return null;
    });
  }

  @Property(tries = 60)
  void garbageAuthorizationNeverYieldsSession(@ForAll("garbageAuthorizationHeaders") String header) {
    Optional<EcrRegistryAuthSession> session = AUTH_SERVICE.authenticate(header);
    if (session.isPresent()) {
      SecurityOracle.failSecurity(
              "EcrAuth.garbageSession",
              header,
              "garbage Authorization header produced a registry session",
              Map.of("accessKeyId", session.get().accessKeyId()));
    }
  }

  @Property(tries = 40)
  void validIssuedTokenYieldsSession() {
    EcrRegistryAuthTokenStore store = new EcrRegistryAuthTokenStore();
    EcrRegistryAuthService service = new EcrRegistryAuthService(store);
    EcrRegistryAuthSession expected = new EcrRegistryAuthSession(
            "arn:aws:iam::" + ACCOUNT + ":user/player",
            "AKIAPLAYER01",
            ACCOUNT,
            REGION,
            Instant.now().plusSeconds(3600));
    String token = store.issue(expected);
    String header = basicHeader(token);
    Optional<EcrRegistryAuthSession> session = service.authenticate(header);
    if (session.isEmpty() || !"AKIAPLAYER01".equals(session.get().accessKeyId())) {
      SecurityOracle.failSecurity(
              "EcrAuth.validToken",
              header,
              "valid issued registry token did not authenticate",
              Map.of());
    }
  }

  @Property(tries = 40)
  void authorizeUnknownAccessKeyDenied(@ForAll("manifestPaths") String path) {
    EcrRegistryAuthorizer authorizer = authorizerWithEnforcement(true);
    Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
            RESOLVER.resolve("GET", path, HOST, false);
    if (route.isEmpty() || route.get().iamAction() == null) {
      return;
    }
    EcrRegistryAuthSession session = new EcrRegistryAuthSession(
            "arn:aws:iam::" + ACCOUNT + ":user/unknown",
            "AKIAUNKNOWN0",
            ACCOUNT,
            REGION,
            Instant.now().plusSeconds(3600));
    Optional<String> deny = authorizer.authorize(session, route.get());
    if (deny.isEmpty()) {
      SecurityOracle.failSecurity(
              "EcrAuth.authorizeUnknown",
              path,
              "unknown participant access key was authorized on registry route",
              Map.of("action", route.get().iamAction()));
    }
  }

  @Property(tries = 30)
  void authorizeNeverThrowsOnWeirdPaths(
          @ForAll("methods") String method,
          @ForAll("ecrPaths") String path,
          @ForAll @StringLength(max = 80) String authHeader) throws Exception {
    String seed = method + "|" + path + "|" + authHeader;
    CrashWatchdog.run("EcrAuth.authorizePath", seed, 2000, () -> {
      SecurityOracle.runCatching("EcrAuth.authorizePath", seed, () -> {
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                RESOLVER.resolve(method, path, HOST, false);
        EcrRegistryAuthorizer authorizer = authorizerWithEnforcement(true);
        Optional<EcrRegistryAuthSession> session = AUTH_SERVICE.authenticate(authHeader);
        if (route.isPresent() && session.isPresent()
                && route.get().iamAction() != null && route.get().repositoryArn() != null) {
          authorizer.authorize(session.get(), route.get());
        }
        return null;
      });
      return null;
    });
  }

  @Property(tries = 20)
  void parseBasicPasswordRejectsBearerAndEmpty(@ForAll("nonBasicHeaders") String header) {
    Optional<String> password = AUTH_SERVICE.parseBasicPassword(header);
    if (password.isPresent()) {
      SecurityOracle.failSecurity(
              "EcrAuth.parseBasic",
              header,
              "non-Basic Authorization header parsed as Basic password",
              Map.of("password", password.get()));
    }
  }

  private static EcrRegistryAuthorizer authorizerWithEnforcement(boolean enabled) {
    EmulatorConfig config = mock(EmulatorConfig.class);
    EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
    EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
    EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
    when(config.services()).thenReturn(services);
    when(services.iam()).thenReturn(iam);
    when(iam.enforcementEnabled()).thenReturn(enabled);
    when(config.auth()).thenReturn(auth);
    when(auth.rootAccessKeyId()).thenReturn(Optional.empty());

    IamService iamService = mock(IamService.class);
    when(iamService.resolveCallerContext(anyString())).thenReturn(null);
    when(iamService.resolveCallerIdentity(anyString(), anyString(), any())).thenReturn(Optional.empty());

    IamPolicyEvaluator evaluator = mock(IamPolicyEvaluator.class);
    ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
    when(resourcePolicyResolver.resolve(anyString(), anyString(), anyString())).thenReturn(List.of());

    return new EcrRegistryAuthorizer(config, iamService, evaluator, resourcePolicyResolver);
  }

  private static String basicHeader(String password) {
    String raw = "AWS:" + password;
    return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
  }

  @Provide
  Arbitrary<String> methods() {
    return Arbitraries.of("GET", "PUT", "HEAD", "DELETE", "POST");
  }

  @Provide
  Arbitrary<String> manifestPaths() {
    return Arbitraries.of(
            "/v2/fuzz-repo/manifests/latest",
            "/v2/fuzz-repo/blobs/sha256:deadbeef",
            "/v2/fuzz-repo/tags/list");
  }

  @Provide
  Arbitrary<String> ecrPaths() {
    List<String> paths = new ArrayList<>(CorpusLoader.orFallback("rest/paths.txt", List.of()));
    paths.addAll(List.of(
            "/v2/",
            "/v2/_catalog",
            "/v2/fuzz-repo/manifests/latest",
            "/v2/" + ACCOUNT + "/" + REGION + "/fuzz-repo/manifests/latest",
            "/v2/not-a-repo"));
    return Arbitraries.of(paths);
  }

  @Provide
  Arbitrary<String> authorizationHeaders() {
    return Arbitraries.oneOf(
            Arbitraries.of((String) null),
            Arbitraries.of(""),
            garbageAuthorizationHeaders(),
            Arbitraries.of(basicHeader("issued-but-unknown")));
  }

  @Provide
  Arbitrary<String> garbageAuthorizationHeaders() {
    return Arbitraries.of(
            "Bearer eyJhbGciOiJIUzI1NiJ9.payload.sig",
            "Basic " + Base64.getEncoder().encodeToString("not-aws-prefix".getBytes(StandardCharsets.UTF_8)),
            "Basic " + Base64.getEncoder().encodeToString("AWS:".getBytes(StandardCharsets.UTF_8)),
            "Basic !!!",
            "Digest username=\"x\"",
            "AWS4-HMAC-SHA256 Credential=AKIATEST/20300101/us-east-1/ecr/aws4_request",
            "basic " + Base64.getEncoder().encodeToString("AWS:token".getBytes(StandardCharsets.UTF_8)));
  }

  @Provide
  Arbitrary<String> nonBasicHeaders() {
    return Arbitraries.of(
            null,
            "",
            "Bearer token",
            "AWS4-HMAC-SHA256 Credential=x",
            "Basic " + Base64.getEncoder().encodeToString("user:pass".getBytes(StandardCharsets.UTF_8)));
  }
}
