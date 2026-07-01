package io.github.hectorvent.floci.services.ecr.registry;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.AwsArnUtils;
import io.github.hectorvent.floci.core.common.RegionResolver;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.Locale;
import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Maps Docker Distribution {@code /v2/*} requests to ECR IAM actions and repository ARNs.
 */
@ApplicationScoped
public class EcrRegistryRouteResolver {

    private static final Pattern HOSTNAME_STYLE =
            Pattern.compile("^(\\d{12})\\.dkr\\.ecr\\.([a-z0-9-]+)\\.(?:localhost|amazonaws\\.com)(?::\\d+)?$",
                    Pattern.CASE_INSENSITIVE);

    private final EmulatorConfig config;
    private final RegionResolver regionResolver;

    @Inject
    public EcrRegistryRouteResolver(EmulatorConfig config, RegionResolver regionResolver) {
        this.config = config;
        this.regionResolver = regionResolver;
    }

    /**
     * @param method       HTTP method
     * @param path         request path (without query)
     * @param hostHeader   raw Host header (may include port)
     * @param pathUriStyle when true, repository paths are {@code /v2/account/region/repo/...}
     */
    public Optional<ResolvedRoute> resolve(String method,
                                           String path,
                                           String hostHeader,
                                           boolean pathUriStyle) {
        if (path == null || path.isBlank()) {
            return Optional.empty();
        }
        String normalizedPath = path.startsWith("/") ? path : "/" + path;
        if (!normalizedPath.startsWith("/v2")) {
            return Optional.empty();
        }

        String upperMethod = method == null ? "GET" : method.toUpperCase(Locale.ROOT);

        if ("/v2/".equals(normalizedPath) || "/v2".equals(normalizedPath)) {
            return Optional.of(ResolvedRoute.ping());
        }
        if ("/v2/_catalog".equals(normalizedPath)) {
            return Optional.of(new ResolvedRoute(null, null, null, null, null, normalizedPath, false));
        }

        HostContext host = resolveHost(hostHeader, pathUriStyle);
        String remainder = normalizedPath.substring("/v2/".length());
        String account;
        String region;
        String repo;
        String repoTail;

        if (pathUriStyle) {
            String[] prefix = remainder.split("/", 3);
            if (prefix.length < 3) {
                return Optional.empty();
            }
            account = prefix[0];
            region = prefix[1];
            remainder = prefix[2];
        } else {
            account = host.accountId() != null ? host.accountId() : regionResolver.getAccountId();
            region = host.region() != null ? host.region() : regionResolver.getDefaultRegion();
        }

        Optional<RepoTail> parsed = parseRepoTail(remainder);
        if (parsed.isEmpty()) {
            return Optional.empty();
        }
        repo = parsed.get().repo();
        repoTail = parsed.get().tail();

        if (repo == null || repo.isBlank()) {
            return Optional.empty();
        }

        String iamAction = mapRepoTailToAction(upperMethod, repoTail);
        if (iamAction == null) {
            return Optional.empty();
        }

        String repositoryArn = AwsArnUtils.Arn.of("ecr", region, account, "repository/" + repo).toString();
        String backendPath = buildBackendPath(pathUriStyle, account, region, repo, repoTail);

        return Optional.of(new ResolvedRoute(
                iamAction,
                repositoryArn,
                account,
                region,
                repo,
                backendPath,
                true));
    }

    public boolean usesPathUriStyle() {
        return "path".equalsIgnoreCase(config.services().ecr().uriStyle());
    }

    private HostContext resolveHost(String hostHeader, boolean pathUriStyle) {
        if (pathUriStyle || hostHeader == null || hostHeader.isBlank()) {
            return new HostContext(null, null);
        }
        String host = hostHeader;
        int colon = host.indexOf(':');
        if (colon > 0) {
            host = host.substring(0, colon);
        }
        Matcher matcher = HOSTNAME_STYLE.matcher(host);
        if (matcher.matches()) {
            return new HostContext(matcher.group(1), matcher.group(2));
        }
        return new HostContext(null, null);
    }

    private static Optional<RepoTail> parseRepoTail(String remainder) {
        if (remainder == null || remainder.isBlank()) {
            return Optional.empty();
        }
        int manifests = remainder.indexOf("/manifests/");
        if (manifests > 0) {
            return Optional.of(new RepoTail(remainder.substring(0, manifests),
                    remainder.substring(manifests + 1)));
        }
        int blobs = remainder.indexOf("/blobs/");
        if (blobs > 0) {
            return Optional.of(new RepoTail(remainder.substring(0, blobs),
                    remainder.substring(blobs + 1)));
        }
        if (remainder.endsWith("/tags/list")) {
            int tags = remainder.lastIndexOf("/tags/list");
            if (tags > 0) {
                return Optional.of(new RepoTail(remainder.substring(0, tags), "tags/list"));
            }
        }
        return Optional.empty();
    }

    private record RepoTail(String repo, String tail) {}

    private static String mapRepoTailToAction(String method, String repoTail) {
        if (repoTail == null) {
            repoTail = "";
        }
        if (repoTail.startsWith("manifests/")) {
            return switch (method) {
                case "GET", "HEAD" -> "ecr:BatchGetImage";
                case "PUT" -> "ecr:PutImage";
                case "DELETE" -> "ecr:BatchDeleteImage";
                default -> null;
            };
        }
        if (repoTail.startsWith("blobs/")) {
            if (repoTail.contains("/uploads")) {
                return switch (method) {
                    case "POST" -> "ecr:InitiateLayerUpload";
                    case "PATCH" -> "ecr:UploadLayerPart";
                    case "PUT" -> "ecr:CompleteLayerUpload";
                    case "HEAD" -> "ecr:InitiateLayerUpload";
                    default -> null;
                };
            }
            return switch (method) {
                case "GET", "HEAD" -> "ecr:GetDownloadUrlForLayer";
                default -> null;
            };
        }
        if ("tags/list".equals(repoTail) && "GET".equals(method)) {
            return "ecr:ListImages";
        }
        return null;
    }

    private static String buildBackendPath(boolean pathUriStyle,
                                           String account,
                                           String region,
                                           String repo,
                                           String repoTail) {
        if (pathUriStyle) {
            return "/v2/" + account + "/" + region + "/" + repo
                    + (repoTail.isEmpty() ? "" : "/" + repoTail);
        }
        return "/v2/" + repo + (repoTail.isEmpty() ? "" : "/" + repoTail);
    }

    private record HostContext(String accountId, String region) {}

    /**
     * @param iamAction    ECR IAM action or {@code null} when no policy check is required
     * @param repositoryArn scoped repository ARN or {@code null}
     * @param backendPath   path forwarded to the backing {@code registry:2} container
     * @param requiresAuth  when true, a valid registry token must be presented
     */
    public record ResolvedRoute(
            String iamAction,
            String repositoryArn,
            String accountId,
            String region,
            String repositoryName,
            String backendPath,
            boolean requiresAuth) {

        static ResolvedRoute ping() {
            return new ResolvedRoute(null, null, null, null, null, "/v2/", false);
        }
    }
}
