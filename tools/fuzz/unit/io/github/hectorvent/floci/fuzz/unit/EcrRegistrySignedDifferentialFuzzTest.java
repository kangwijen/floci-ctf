package io.github.hectorvent.floci.fuzz.unit;

import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.ExtremeValueGenerators;
import io.github.hectorvent.floci.fuzz.support.FuzzFixtures;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthService;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthSession;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthTokenStore;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryAuthorizer;
import io.github.hectorvent.floci.services.ecr.registry.EcrRegistryRouteResolver;
import io.github.hectorvent.floci.services.iam.IamPolicyEvaluator;
import io.github.hectorvent.floci.services.iam.IamService;
import io.github.hectorvent.floci.services.iam.ResourcePolicyResolver;
import io.github.hectorvent.floci.services.iam.model.CallerContext;
import io.github.hectorvent.floci.services.iam.model.CallerIdentity;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Signed ECR registry differential: issued docker-login tokens authenticate distinct
 * sessions and {@link EcrRegistryAuthorizer} allows or denies manifest pulls per IAM.
 */
class EcrRegistrySignedDifferentialFuzzTest {

    private static final String ACCOUNT = "000000000000";
    private static final String REGION = "us-east-1";
    private static final String HOST = ACCOUNT + ".dkr.ecr." + REGION + ".localhost:5100";
    private static final String REPO = "fuzz-repo";
    private static final String REPO_ARN = "arn:aws:ecr:" + REGION + ":" + ACCOUNT + ":repository/" + REPO;
    private static final String MANIFEST_PATH = "/v2/" + REPO + "/manifests/latest";

    private static final String AKIA_ALLOW = "AKIAPLAYER01";
    private static final String AKIA_DENY = "AKIADENIED00";
    private static final String ARN_ALLOW = "arn:aws:iam::" + ACCOUNT + ":user/player-a";
    private static final String ARN_DENY = "arn:aws:iam::" + ACCOUNT + ":user/player-b";

    private static final EcrRegistryRouteResolver RESOLVER = FuzzFixtures.ecrRegistryRouteResolver();
    private static final ObjectMapper MAPPER = FuzzFixtures.objectMapper();

    @Property(tries = 20)
    void allowedSessionAuthorizePassesOnManifestRoute() {
        EcrRegistryAuthSession session = sessionFor(AKIA_ALLOW, ARN_ALLOW);
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                RESOLVER.resolve("GET", MANIFEST_PATH, HOST, false);
        if (route.isEmpty() || route.get().iamAction() == null) {
            SecurityOracle.failSecurity(
                    "EcrSigned.route",
                    MANIFEST_PATH,
                    "manifest route did not resolve to IAM action",
                    Map.of());
        }
        Optional<String> deny = authorizerFixture().authorize(session, route.get());
        if (deny.isPresent()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.allow",
                    AKIA_ALLOW,
                    "allowed participant was denied on manifest route",
                    Map.of("reason", deny.get(), "action", route.get().iamAction()));
        }
    }

    @Property(tries = 20)
    void deniedSessionAuthorizeFailsOnManifestRoute() {
        EcrRegistryAuthSession session = sessionFor(AKIA_DENY, ARN_DENY);
        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                RESOLVER.resolve("GET", MANIFEST_PATH, HOST, false);
        if (route.isEmpty() || route.get().iamAction() == null) {
            return;
        }
        Optional<String> deny = authorizerFixture().authorize(session, route.get());
        if (deny.isEmpty()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.deny",
                    AKIA_DENY,
                    "denied participant was authorized on manifest route",
                    Map.of("action", route.get().iamAction(), "resource", route.get().repositoryArn()));
        }
    }

    @Property(tries = 20)
    void issuedTokensAuthenticateAndAuthorizeDifferentially() {
        EcrRegistryAuthTokenStore store = new EcrRegistryAuthTokenStore();
        EcrRegistryAuthService authService = new EcrRegistryAuthService(store);
        EcrRegistryAuthorizer authorizer = authorizerFixture();

        String tokenA = store.issue(sessionFor(AKIA_ALLOW, ARN_ALLOW));
        String tokenB = store.issue(sessionFor(AKIA_DENY, ARN_DENY));

        Optional<EcrRegistryAuthSession> sessionA = authService.authenticate(basicHeader(tokenA));
        Optional<EcrRegistryAuthSession> sessionB = authService.authenticate(basicHeader(tokenB));
        if (sessionA.isEmpty() || sessionB.isEmpty()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.tokenAuth",
                    tokenA,
                    "issued registry tokens did not authenticate",
                    Map.of());
        }

        Optional<EcrRegistryRouteResolver.ResolvedRoute> route =
                RESOLVER.resolve("GET", MANIFEST_PATH, HOST, false);
        if (route.isEmpty() || route.get().iamAction() == null) {
            return;
        }

        if (authorizer.authorize(sessionA.get(), route.get()).isPresent()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.tokenAllow",
                    tokenA,
                    "allowed issued token was denied at authorize",
                    Map.of());
        }
        if (authorizer.authorize(sessionB.get(), route.get()).isEmpty()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.tokenDeny",
                    tokenB,
                    "denied issued token was allowed at authorize",
                    Map.of());
        }
    }

    @Property(tries = 60)
    void garbageBasicNeverAuthenticates(@ForAll("garbageBasicHeaders") String header) {
        EcrRegistryAuthTokenStore store = new EcrRegistryAuthTokenStore();
        EcrRegistryAuthService service = new EcrRegistryAuthService(store);
        Optional<EcrRegistryAuthSession> session = service.authenticate(header);
        if (session.isPresent()) {
            SecurityOracle.failSecurity(
                    "EcrSigned.garbageBasic",
                    header,
                    "garbage Basic AWS auth produced a registry session",
                    Map.of("accessKeyId", session.get().accessKeyId()));
        }
    }

    @Property(tries = 40)
    void extremeAuthorizationHeadersNeverThrow(@ForAll("extremeAuthorizationHeaders") String header)
            throws Exception {
        String seed = header == null ? "<null>" : header;
        EcrRegistryAuthService authService =
                new EcrRegistryAuthService(new EcrRegistryAuthTokenStore());
        CrashWatchdog.run("EcrSigned.extremeAuth", seed, 2000, () -> {
            SecurityOracle.runCatching("EcrSigned.extremeAuth", seed, () -> {
                authService.authenticate(header);
                authService.parseBasicPassword(header);
                return null;
            });
            return null;
        });
    }

    private static EcrRegistryAuthorizer authorizerFixture() {
        EmulatorConfig config = mock(EmulatorConfig.class);
        EmulatorConfig.ServicesConfig services = mock(EmulatorConfig.ServicesConfig.class);
        EmulatorConfig.IamServiceConfig iam = mock(EmulatorConfig.IamServiceConfig.class);
        EmulatorConfig.AuthConfig auth = mock(EmulatorConfig.AuthConfig.class);
        when(config.services()).thenReturn(services);
        when(services.iam()).thenReturn(iam);
        when(iam.enforcementEnabled()).thenReturn(true);
        when(config.auth()).thenReturn(auth);
        when(auth.rootAccessKeyId()).thenReturn(Optional.empty());

        String repoPolicy = """
                {"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"%s"},\
                "Action":"ecr:BatchGetImage","Resource":"%s"}]}
                """.formatted(ARN_ALLOW, REPO_ARN).replace("\n", "").trim();
        String denyIdentity = """
                {"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ecr:*","Resource":"*"}]}
                """.trim();

        IamService iamService = mock(IamService.class);
        when(iamService.resolveCallerContext(anyString())).thenAnswer(invocation -> {
            String accessKeyId = invocation.getArgument(0);
            if (AKIA_ALLOW.equals(accessKeyId)) {
                return CallerContext.of(List.of());
            }
            if (AKIA_DENY.equals(accessKeyId)) {
                return CallerContext.of(List.of(denyIdentity));
            }
            return null;
        });
        when(iamService.resolveCallerIdentity(eq(AKIA_ALLOW), eq(ACCOUNT), any()))
                .thenReturn(Optional.of(new CallerIdentity("AIDAALLOW", ACCOUNT, ARN_ALLOW)));
        when(iamService.resolveCallerIdentity(eq(AKIA_DENY), eq(ACCOUNT), any()))
                .thenReturn(Optional.of(new CallerIdentity("AIDADENY", ACCOUNT, ARN_DENY)));

        ResourcePolicyResolver resourcePolicyResolver = mock(ResourcePolicyResolver.class);
        when(resourcePolicyResolver.resolve(eq("ecr"), eq(REPO_ARN), eq(REGION)))
                .thenReturn(List.of(repoPolicy));

        IamPolicyEvaluator evaluator = new IamPolicyEvaluator(MAPPER);
        return new EcrRegistryAuthorizer(config, iamService, evaluator, resourcePolicyResolver);
    }

    private static EcrRegistryAuthSession sessionFor(String accessKeyId, String principalArn) {
        return new EcrRegistryAuthSession(
                principalArn,
                accessKeyId,
                ACCOUNT,
                REGION,
                Instant.now().plusSeconds(3600));
    }

    private static String basicHeader(String password) {
        String raw = "AWS:" + password;
        return "Basic " + Base64.getEncoder().encodeToString(raw.getBytes(StandardCharsets.UTF_8));
    }

    @Provide
    Arbitrary<String> garbageBasicHeaders() {
        return Arbitraries.of(
                "Basic " + Base64.getEncoder().encodeToString("AWS:garbage".getBytes(StandardCharsets.UTF_8)),
                "Basic " + Base64.getEncoder().encodeToString("AWS:".getBytes(StandardCharsets.UTF_8)),
                "Basic " + Base64.getEncoder().encodeToString("not-aws".getBytes(StandardCharsets.UTF_8)),
                "Basic !!!",
                "Bearer AWS:token",
                "basic " + Base64.getEncoder().encodeToString("AWS:wrong-case".getBytes(StandardCharsets.UTF_8)));
    }

    @Provide
    Arbitrary<String> extremeAuthorizationHeaders() {
        return Arbitraries.oneOf(
                ExtremeValueGenerators.extremeStrings(),
                garbageBasicHeaders(),
                Arbitraries.of(basicHeader("issued-but-unknown")));
    }
}
