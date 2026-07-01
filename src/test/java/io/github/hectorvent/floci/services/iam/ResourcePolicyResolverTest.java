package io.github.hectorvent.floci.services.iam;

import io.github.hectorvent.floci.services.ecr.EcrService;
import io.github.hectorvent.floci.services.kms.KmsService;
import io.github.hectorvent.floci.services.lambda.LambdaService;
import io.github.hectorvent.floci.services.s3.S3Service;
import io.github.hectorvent.floci.services.secretsmanager.SecretsManagerService;
import io.github.hectorvent.floci.services.sns.SnsService;
import io.github.hectorvent.floci.services.sqs.SqsService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

class ResourcePolicyResolverTest {

    private static final String REGION = "us-east-1";
    private static final String ACCOUNT = "000000000000";

    private S3Service s3Service;
    private LambdaService lambdaService;
    private SqsService sqsService;
    private SnsService snsService;
    private KmsService kmsService;
    private SecretsManagerService secretsManagerService;
    private EcrService ecrService;
    private ResourcePolicyResolver resolver;

    @BeforeEach
    void setUp() {
        s3Service = mock(S3Service.class);
        lambdaService = mock(LambdaService.class);
        sqsService = mock(SqsService.class);
        snsService = mock(SnsService.class);
        kmsService = mock(KmsService.class);
        secretsManagerService = mock(SecretsManagerService.class);
        ecrService = mock(EcrService.class);
        resolver = new ResourcePolicyResolver(
                s3Service, lambdaService, sqsService, snsService, kmsService, secretsManagerService, ecrService);
    }

    @Test
    void resolvesBucketPolicyFromObjectArn() {
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(s3Service.findBucketPolicyIfPresent("example-bucket"))
                .thenReturn(Optional.of(policy));

        List<String> docs = resolver.resolve(
                "s3",
                "arn:aws:s3:::example-bucket/data/object.txt",
                REGION);

        assertEquals(List.of(policy), docs);
    }

    @Test
    void resolvesBucketPolicyFromBucketArn() {
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(s3Service.findBucketPolicyIfPresent("version-bucket"))
                .thenReturn(Optional.of(policy));

        List<String> docs = resolver.resolve(
                "s3",
                "arn:aws:s3:::version-bucket",
                REGION);

        assertEquals(List.of(policy), docs);
    }

    @Test
    void returnsEmptyWhenBucketHasNoPolicy() {
        when(s3Service.findBucketPolicyIfPresent("empty-bucket"))
                .thenReturn(Optional.empty());

        assertTrue(resolver.resolve(
                "s3",
                "arn:aws:s3:::empty-bucket/key",
                REGION).isEmpty());
    }

    @Test
    void ignoresNonS3ArnsForS3Scope() {
        assertTrue(resolver.resolve("s3", "arn:aws:sqs:us-east-1:1:q", REGION).isEmpty());
        verifyNoInteractions(s3Service);
    }

    @Test
    void returnsEmptyForWildcardResource() {
        assertTrue(resolver.resolve("s3", "*", REGION).isEmpty());
        verifyNoInteractions(s3Service);
    }

    @Test
    void lambdaResolvesFunctionPolicyFromArn() {
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(lambdaService.findFunctionPolicyDocument(REGION, "my-fn"))
                .thenReturn(Optional.of(policy));

        List<String> docs = resolver.resolve(
                "lambda",
                "arn:aws:lambda:" + REGION + ":" + ACCOUNT + ":function:my-fn",
                REGION);

        assertEquals(List.of(policy), docs);
    }

    @Test
    void sqsResolvesQueuePolicyByArn() {
        String queueArn = "arn:aws:sqs:" + REGION + ":" + ACCOUNT + ":orders";
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(sqsService.findQueuePolicyByArn(queueArn)).thenReturn(Optional.of(policy));

        assertEquals(List.of(policy), resolver.resolve("sqs", queueArn, REGION));
    }

    @Test
    void snsResolvesTopicPolicyByArn() {
        String topicArn = "arn:aws:sns:" + REGION + ":" + ACCOUNT + ":alerts";
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(snsService.findTopicPolicyDocument(topicArn, REGION)).thenReturn(Optional.of(policy));

        assertEquals(List.of(policy), resolver.resolve("sns", topicArn, REGION));
    }

    @Test
    void secretsManagerResolvesResourcePolicyByArn() {
        String secretArn = "arn:aws:secretsmanager:" + REGION + ":" + ACCOUNT + ":secret:lab-abc";
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(secretsManagerService.findSecretResourcePolicyDocument(secretArn, REGION))
                .thenReturn(Optional.of(policy));

        assertEquals(List.of(policy), resolver.resolve("secretsmanager", secretArn, REGION));
    }

    @Test
    void kmsResolvesKeyPolicyByKeyArn() {
        String keyArn = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/policy-key-id";
        String customPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"*"},"Action":"kms:Decrypt","Resource":"*"}
            ]}""";
        when(kmsService.findKeyPolicyDocument(keyArn, REGION)).thenReturn(Optional.of(customPolicy));

        List<String> docs = resolver.resolve("kms", keyArn, REGION);

        assertEquals(1, docs.size());
        assertEquals(customPolicy, docs.getFirst());
    }

    @Test
    void kmsReturnsEmptyForWildcardKeyArn() {
        String wildcardArn = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":key/*";
        when(kmsService.findKeyPolicyDocument(wildcardArn, REGION)).thenReturn(Optional.empty());

        assertTrue(resolver.resolve("kms", wildcardArn, REGION).isEmpty());
    }

    @Test
    void kmsResolvesKeyPolicyByAliasArn() {
        String aliasArn = "arn:aws:kms:" + REGION + ":" + ACCOUNT + ":alias/lab-key";
        String customPolicy = """
            {"Version":"2012-10-17","Statement":[
              {"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::000000000000:user/reader"},
               "Action":"kms:Decrypt","Resource":"*"}
            ]}""";
        when(kmsService.findKeyPolicyDocument(aliasArn, REGION)).thenReturn(Optional.of(customPolicy));

        assertEquals(List.of(customPolicy), resolver.resolve("kms", aliasArn, REGION));
    }

    @Test
    void resolvesEcrRepositoryPolicy() {
        String repoArn = "arn:aws:ecr:" + REGION + ":" + ACCOUNT + ":repository/policy-repo";
        String policy = "{\"Version\":\"2012-10-17\",\"Statement\":[]}";
        when(ecrService.findRepositoryPolicyByArn(repoArn)).thenReturn(Optional.of(policy));

        assertEquals(List.of(policy), resolver.resolve("ecr", repoArn, REGION));
    }

    @Test
    void ecrReturnsEmptyWhenRepositoryHasNoPolicy() {
        String repoArn = "arn:aws:ecr:" + REGION + ":" + ACCOUNT + ":repository/no-policy";
        when(ecrService.findRepositoryPolicyByArn(repoArn)).thenReturn(Optional.empty());

        assertTrue(resolver.resolve("ecr", repoArn, REGION).isEmpty());
    }
}
