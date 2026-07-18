package io.github.hectorvent.floci.services.s3;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.RequestBodyBuffer;
import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.core.common.SigV4aPublicKeyResolver;
import io.github.hectorvent.floci.core.common.XmlBuilder;
import io.github.hectorvent.floci.services.iam.IamService;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.Response;
import jakarta.ws.rs.ext.Provider;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;

/**
 * Verifies S3 browser-based (presigned) POST SigV4 policy signatures before IAM evaluation.
 * Sets {@link #PRESIGN_POST_VERIFIED_PROPERTY} and credential/key properties for
 * {@link io.github.hectorvent.floci.core.common.IamEnforcementFilter}.
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION + 10)
public class PreSignedPostFilter implements ContainerRequestFilter {

    public static final String PRESIGN_POST_VERIFIED_PROPERTY = "floci.s3.presign.post.verified";
    public static final String PRESIGN_POST_CREDENTIAL_PROPERTY = "floci.s3.presign.post.credential";
    public static final String PRESIGN_POST_KEY_PROPERTY = "floci.s3.presign.post.key";

    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private final EmulatorConfig config;
    private final IamService iamService;
    private final SigV4aPublicKeyResolver sigV4aPublicKeyResolver;

    @Inject
    public PreSignedPostFilter(EmulatorConfig config,
                               IamService iamService,
                               SigV4aPublicKeyResolver sigV4aPublicKeyResolver) {
        this.config = config;
        this.iamService = iamService;
        this.sigV4aPublicKeyResolver = sigV4aPublicKeyResolver;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        if (!SecurityBypassPaths.isPresignedPostRequest(ctx)) {
            return;
        }

        byte[] body = RequestBodyBuffer.peek(ctx);
        if (body == null) {
            body = RequestBodyBuffer.buffer(ctx);
        }
        Map<String, String> lcFields = PresignedPostFormParser.lowerCaseKeys(
                PresignedPostFormParser.parseTextFields(ctx.getHeaderString("Content-Type"), body));

        String key = lcFields.get("key");
        String policy = lcFields.get("policy");
        String algorithm = lcFields.get("x-amz-algorithm");
        String credential = lcFields.get("x-amz-credential");
        String amzDate = lcFields.get("x-amz-date");
        String signature = lcFields.get("x-amz-signature");

        boolean hasAllSigFields = policy != null && !policy.isEmpty()
                && algorithm != null && !algorithm.isEmpty()
                && credential != null && !credential.isEmpty()
                && amzDate != null && !amzDate.isEmpty()
                && signature != null && !signature.isEmpty();

        boolean strict = config.services().iam().enforcementEnabled()
                && config.services().iam().strictEnforcementEnabled();
        if (!hasAllSigFields) {
            if (strict) {
                ctx.abortWith(errorResponse(403, "AccessDenied",
                        "Missing required presigned POST policy fields."));
            }
            return;
        }

        if (key == null || key.isBlank()) {
            ctx.abortWith(errorResponse(400, "InvalidArgument",
                    "Bucket POST must contain a field named 'key'."));
            return;
        }

        if (isExpired(policy)) {
            ctx.abortWith(errorResponse(403, "AccessDenied", "Request has expired"));
            return;
        }

        String accessKeyId = SigV4RequestValidator.parseAccessKeyIdFromCredential(credential);
        if ("AWS4-ECDSA-P256-SHA256".equals(algorithm)) {
            var publicKey = sigV4aPublicKeyResolver.resolve(accessKeyId);
            if (publicKey.isEmpty()) {
                ctx.abortWith(signatureMismatch());
                return;
            }
            SigV4RequestValidator.Result sigv4aResult = SigV4RequestValidator.validatePresignedPostPolicySigV4a(
                    policy, algorithm, credential, amzDate, signature, publicKey.get());
            if (sigv4aResult != SigV4RequestValidator.Result.VALID) {
                ctx.abortWith(signatureMismatch());
                return;
            }
            markVerified(ctx, credential, key);
            return;
        }

        Optional<String> secret = resolveSecret(accessKeyId);
        if (secret.isEmpty()) {
            ctx.abortWith(signatureMismatch());
            return;
        }
        SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedPostPolicy(
                policy, algorithm, credential, amzDate, signature, secret.get());
        if (result != SigV4RequestValidator.Result.VALID) {
            ctx.abortWith(signatureMismatch());
            return;
        }
        markVerified(ctx, credential, key);
    }

    private void markVerified(ContainerRequestContext ctx, String credential, String key) {
        ctx.setProperty(PRESIGN_POST_VERIFIED_PROPERTY, Boolean.TRUE);
        ctx.setProperty(PRESIGN_POST_CREDENTIAL_PROPERTY, credential);
        ctx.setProperty(PRESIGN_POST_KEY_PROPERTY, key);
    }

    private Optional<String> resolveSecret(String accessKeyId) {
        if (accessKeyId == null) {
            return Optional.empty();
        }
        Optional<String> rootSecret = config.auth().rootAccessKeyId()
                .filter(accessKeyId::equals)
                .flatMap(ignored -> config.auth().resolveRootSecretAccessKey());
        if (rootSecret.isPresent()) {
            return rootSecret;
        }
        return iamService.findSecretKey(accessKeyId);
    }

    private static boolean isExpired(String policyBase64) {
        try {
            byte[] decoded = java.util.Base64.getDecoder().decode(policyBase64);
            JsonNode policyNode = OBJECT_MAPPER.readTree(decoded);
            JsonNode expiration = policyNode.get("expiration");
            if (expiration == null || !expiration.isTextual()) {
                return false;
            }
            return Instant.now().isAfter(Instant.parse(expiration.asText()));
        } catch (Exception e) {
            return true;
        }
    }

    private static Response signatureMismatch() {
        return errorResponse(403, "AccessDenied",
                "The request signature we calculated does not match the signature you provided.");
    }

    private static Response errorResponse(int status, String code, String message) {
        String xml = new XmlBuilder()
                .start("Error")
                .elem("Code", code)
                .elem("Message", message)
                .end("Error")
                .build();
        return Response.status(status)
                .type(MediaType.APPLICATION_XML_TYPE)
                .entity(xml)
                .build();
    }
}
