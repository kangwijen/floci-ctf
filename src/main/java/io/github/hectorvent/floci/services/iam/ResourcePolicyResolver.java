package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.sns.SnsService;
import io.github.hectorvent.floci.services.sqs.SqsService;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

/**
 * Loads resource-based policy documents (bucket policies, Lambda permissions, queue/topic/key policies)
 * for {@link IamPolicyEvaluator} Phase 2 evaluation in {@link io.github.hectorvent.floci.core.common.IamEnforcementFilter}.
 */
@ApplicationScoped
public class ResourcePolicyResolver {

    private final S3Service s3Service;
    private final LambdaService lambdaService;
    private final SqsService sqsService;
    private final SnsService snsService;
    private final KmsService kmsService;
    private final SecretsManagerService secretsManagerService;

    @Inject
    public ResourcePolicyResolver(S3Service s3Service,
                                  LambdaService lambdaService,
                                  SqsService sqsService,
                                  SnsService snsService,
                                  KmsService kmsService,
                                  SecretsManagerService secretsManagerService) {
        this.s3Service = s3Service;
        this.lambdaService = lambdaService;
        this.sqsService = sqsService;
        this.snsService = snsService;
        this.kmsService = kmsService;
        this.secretsManagerService = secretsManagerService;
    }

    /**
     * @param credentialScope SigV4 service name (e.g. {@code s3}, {@code lambda})
     * @param resourceArn     request target ARN from {@link ResourceArnBuilder}
     * @param region          request region
     * @return policy JSON documents attached to the resource (may be empty)
     */
    public List<String> resolve(String credentialScope, String resourceArn, String region) {
        if (resourceArn == null || "*".equals(resourceArn)) {
            return List.of();
        }
        List<String> docs = new ArrayList<>();
        switch (credentialScope) {
            case "s3" -> s3BucketFromArn(resourceArn)
                    .flatMap(s3Service::findBucketPolicyIfPresent)
                    .ifPresent(docs::add);
            case "lambda" -> lambdaFunctionFromArn(resourceArn, region)
                    .flatMap(name -> lambdaService.findFunctionPolicyDocument(region, name))
                    .ifPresent(docs::add);
            case "sqs" -> sqsService.findQueuePolicyByArn(resourceArn).ifPresent(docs::add);
            case "sns" -> snsService.findTopicPolicyDocument(resourceArn, region).ifPresent(docs::add);
            case "kms" -> kmsService.findKeyPolicyDocument(resourceArn, region).ifPresent(docs::add);
            case "secretsmanager" -> secretsManagerService.findSecretResourcePolicyDocument(resourceArn, region)
                    .ifPresent(docs::add);
            default -> { }
        }
        return List.copyOf(docs);
    }

    private static Optional<String> s3BucketFromArn(String arn) {
        if (!arn.startsWith("arn:aws:s3:::")) {
            return Optional.empty();
        }
        String rest = arn.substring("arn:aws:s3:::".length());
        if (rest.isEmpty() || "*".equals(rest)) {
            return Optional.empty();
        }
        int slash = rest.indexOf('/');
        String bucket = slash > 0 ? rest.substring(0, slash) : rest;
        return Optional.of(bucket);
    }

    private static Optional<String> lambdaFunctionFromArn(String arn, String region) {
        String prefix = "arn:aws:lambda:" + region + ":";
        if (!arn.startsWith(prefix) || !arn.contains(":function:")) {
            int fnIdx = arn.indexOf(":function:");
            if (fnIdx < 0) {
                return Optional.empty();
            }
            String after = arn.substring(fnIdx + ":function:".length());
            int colon = after.indexOf(':');
            return Optional.of(colon > 0 ? after.substring(0, colon) : after);
        }
        String after = arn.substring(arn.indexOf(":function:") + ":function:".length());
        int colon = after.indexOf(':');
        return Optional.of(colon > 0 ? after.substring(0, colon) : after);
    }
}
