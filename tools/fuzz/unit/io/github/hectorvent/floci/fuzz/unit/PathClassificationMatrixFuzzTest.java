package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
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
import java.util.Set;

/**
 * Consistency matrix for {@link SecurityBypassPaths} static path classifiers.
 */
class PathClassificationMatrixFuzzTest {

    @Property(tries = 50)
    void classifiersNeverThrowOnCorpusAndRestPaths(@ForAll("paths") String path) throws Exception {
        String seed = String.valueOf(path);
        CrashWatchdog.run("PathClassification.crash", seed, 2000, () -> {
            SecurityOracle.runCatching("PathClassification.crash", seed, () -> {
                String normalized = SecurityBypassPaths.normalizePath(path);
                SecurityBypassPaths.isPrefixedInternalPath(normalized);
                SecurityBypassPaths.isPrefixedInternalPath(path);
                SecurityBypassPaths.isAwsInspectionPath(normalized);
                SecurityBypassPaths.isAwsInspectionPath(path);
                SecurityBypassPaths.isCognitoOAuthPath(path);
                SecurityBypassPaths.isCognitoOAuthTokenPath(path);
                SecurityBypassPaths.isCognitoOAuthUserInfoPath(path);
                SecurityBypassPaths.isInternalHealthOrInfoPath(path);
                return null;
            });
            return null;
        });
    }

    @Property(tries = 40)
    void cognitoOauthClassificationIsConsistent(@ForAll("paths") String path) {
        boolean oauth = SecurityBypassPaths.isCognitoOAuthPath(path);
        boolean token = SecurityBypassPaths.isCognitoOAuthTokenPath(path);
        boolean userInfo = SecurityBypassPaths.isCognitoOAuthUserInfoPath(path);
        if (oauth != (token || userInfo)) {
            SecurityOracle.failSecurity(
                    "PathClassification.oauth",
                    String.valueOf(path),
                    "isCognitoOAuthPath disagree with token/userInfo helpers",
                    java.util.Map.of(
                            "oauth", String.valueOf(oauth),
                            "token", String.valueOf(token),
                            "userInfo", String.valueOf(userInfo)));
        }
    }

    @Property(tries = 40)
    void prefixedInternalPathsClassifyAsPrefixed(@ForAll("internalCorpus") String path) {
        String withSlash = ensureLeadingSlash(path);
        String lower = withSlash.toLowerCase(Locale.ROOT);
        if (lower.startsWith("/_floci") || lower.startsWith("/_localstack")) {
            if (!SecurityBypassPaths.isPrefixedInternalPath(withSlash)
                    && !SecurityBypassPaths.isPrefixedInternalPath(
                    SecurityBypassPaths.normalizePath(withSlash))) {
                SecurityOracle.failSecurity(
                        "PathClassification.prefixed",
                        path,
                        "floci/localstack path not classified as prefixed internal",
                        java.util.Map.of());
            }
        }
        if (lower.startsWith("/_aws")) {
            if (!SecurityBypassPaths.isAwsInspectionPath(withSlash)
                    && !SecurityBypassPaths.isAwsInspectionPath(
                    SecurityBypassPaths.normalizePath(withSlash))) {
                SecurityOracle.failSecurity(
                        "PathClassification.aws",
                        path,
                        "_aws path not classified as AWS inspection",
                        java.util.Map.of());
            }
        }
    }

    @Property(tries = 40)
    void normalizePathNeverThrows(@ForAll @StringLength(max = 200) String path) {
        SecurityOracle.runCatching("PathClassification.normalize", path, () ->
                SecurityBypassPaths.normalizePath(path));
    }

    @Property(tries = 30)
    void knownOauthPathsStayClassified(@ForAll("oauthPaths") String path) {
        if (!SecurityBypassPaths.isCognitoOAuthPath(path)) {
            SecurityOracle.failSecurity(
                    "PathClassification.knownOauth",
                    path,
                    "known Cognito OAuth path not classified",
                    java.util.Map.of());
        }
    }

    private static String ensureLeadingSlash(String path) {
        if (path == null || path.isEmpty()) {
            return "/";
        }
        return path.startsWith("/") ? path : "/" + path;
    }

    @Provide
    Arbitrary<String> paths() {
        Set<String> all = new LinkedHashSet<>();
        all.addAll(CorpusLoader.orFallback("paths/internal.txt", List.of(
                "/health",
                "/_floci/health",
                "/_localstack/health",
                "/_aws/cloudformation/ready")));
        all.addAll(FuzzBodyGenerators.highValueRestPaths());
        all.add("/cognito-idp/oauth2/token");
        all.add("/cognito-idp/oauth2/userInfo");
        return Arbitraries.of(new ArrayList<>(all));
    }

    @Provide
    Arbitrary<String> internalCorpus() {
        return Arbitraries.of(CorpusLoader.orFallback("paths/internal.txt", List.of(
                "/health",
                "/_floci/health",
                "/_localstack/health",
                "/_aws/cloudformation/ready",
                "/_floci",
                "/_localstack",
                "/_aws")));
    }

    @Provide
    Arbitrary<String> oauthPaths() {
        return Arbitraries.of(
                "/cognito-idp/oauth2/token",
                "/cognito-idp/oauth2/userInfo");
    }
}
