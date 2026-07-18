package io.github.hectorvent.floci.services.eks;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Consumes;
import jakarta.ws.rs.POST;
import jakarta.ws.rs.Path;
import jakarta.ws.rs.Produces;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import org.jboss.logging.Logger;

import java.util.List;
import java.util.Map;

/**
 * Kubernetes token-authentication webhook for k3s-backed EKS clusters.
 *
 * <p>The k3s API server is configured (see {@code EksClusterManager}) to POST a
 * {@code TokenReview} here whenever it receives a bearer token it does not recognise — notably the
 * {@code k8s-aws-v1.<presigned-sts-url>} token produced by {@code aws eks get-token}. Floci accepts
 * the token and maps it to a Kubernetes user. Under lab defaults the user is placed in
 * {@code system:masters} (cluster-admin). Under CTF IAM enforcement the mapping is narrowed to
 * {@code system:authenticated} only (no {@code system:masters}).
 *
 * <p>This is Floci plumbing under the {@code _floci/...} namespace, not an AWS API. With CTF
 * defaults, {@code CtfInternalEndpointFilter} returns 404 for this path. When reachable and IAM
 * enforcement is on, only SigV4-valid presigned STS {@code GetCallerIdentity} URLs are accepted.
 */
@ApplicationScoped
@Path("_floci/eks/token-webhook")
@Produces(MediaType.APPLICATION_JSON)
@Consumes(MediaType.APPLICATION_JSON)
public class EksTokenWebhookController {

    private static final Logger LOG = Logger.getLogger(EksTokenWebhookController.class);

    /** Lab / non-CTF: cluster-admin via system:masters. */
    static final List<String> LAB_GROUPS = List.of("system:masters");

    /** CTF under IAM enforcement: authenticated but not cluster-admin. */
    static final List<String> CTF_GROUPS = List.of("system:authenticated");

    private final EksTokenValidator tokenValidator;
    private final AuthPosture authPosture;

    @Inject
    public EksTokenWebhookController(EksTokenValidator tokenValidator, EmulatorConfig config) {
        this(tokenValidator, AuthPosture.from(config));
    }

    EksTokenWebhookController(EksTokenValidator tokenValidator, AuthPosture authPosture) {
        this.tokenValidator = tokenValidator;
        this.authPosture = authPosture;
    }

    @POST
    public Response review(Map<String, Object> tokenReview) {
        // The response apiVersion MUST match the request's (the kube-apiserver sends v1beta1 by
        // default and cannot convert a v1 response back). Echo whatever the apiserver sent.
        String apiVersion = tokenReview != null && tokenReview.get("apiVersion") instanceof String v
                ? v : "authentication.k8s.io/v1";

        String token = extractToken(tokenReview);
        boolean authenticated = tokenValidator.accepts(token);

        if (authenticated) {
            List<String> groups = groupsForPosture();
            LOG.debugv("EKS token-webhook: authenticated aws-iam token groups={0}", groups);
            return Response.ok(Map.of(
                    "apiVersion", apiVersion,
                    "kind", "TokenReview",
                    "status", Map.of(
                            "authenticated", true,
                            "user", Map.of(
                                    "username", "floci:aws-iam",
                                    "uid", "floci-aws-iam",
                                    "groups", groups)))).build();
        }

        LOG.debug("EKS token-webhook: rejecting unrecognised token");
        return Response.ok(Map.of(
                "apiVersion", apiVersion,
                "kind", "TokenReview",
                "status", Map.of("authenticated", false))).build();
    }

    List<String> groupsForPosture() {
        if (authPosture.iamEnforced()) {
            return CTF_GROUPS;
        }
        return LAB_GROUPS;
    }

    @SuppressWarnings("unchecked")
    private String extractToken(Map<String, Object> tokenReview) {
        if (tokenReview == null) {
            return null;
        }
        Object spec = tokenReview.get("spec");
        if (spec instanceof Map<?, ?> specMap) {
            Object token = ((Map<String, Object>) specMap).get("token");
            if (token instanceof String s) {
                return s;
            }
        }
        return null;
    }
}
