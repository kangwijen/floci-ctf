package io.github.hectorvent.floci.fuzz.operator;

import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzBodyGenerators;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Unsigned deny smoke across Query, JSON 1.1, and REST protocol surfaces.
 *
 * <p>Skipped unless {@code -Pfuzz-operator} and {@code AWS_ENDPOINT_URL} are set.
 */
class ServiceProtocolCampaignTest {

    private static Optional<DifferentialHttpOracle> live() {
        if (Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true"))) {
            return Optional.empty();
        }
        return DifferentialHttpOracle.fromEnv();
    }

    @Property(tries = 15)
    void unsignedHighValueQueryActionsStayDenied(@ForAll("queryActions") String action) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        String body = "Action=" + action + "&Version=2010-05-08";
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of("Content-Type", "application/x-www-form-urlencoded"),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "ServiceProtocol.unsigned.query",
                    body,
                    "unsigned query action succeeded",
                    Map.of("status", String.valueOf(result.status()), "action", action));
        }
    }

    @Property(tries = 15)
    void unsignedHighValueJson11TargetsStayDenied(@ForAll("jsonTargets") String target) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/",
                Map.of(
                        "Content-Type", "application/x-amz-json-1.1",
                        "X-Amz-Target", target),
                "{}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "ServiceProtocol.unsigned.json11",
                    target,
                    "unsigned JSON 1.1 call succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Property(tries = 10)
    void unsignedHighValueRestPathsStayDenied(@ForAll("restPaths") String path) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange("GET", path, Map.of(), null);
        if (result.success() && !"/health".equals(path)) {
            SecurityOracle.failSecurity(
                    "ServiceProtocol.unsigned.rest",
                    path,
                    "unsigned REST path succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedEcrRegistryV2Denied() throws Exception {
        assertUnsignedGetDenied("/v2/", "ServiceProtocol.ecr.v2");
    }

    @Test
    void participantS3GetDeniedWhenUnsignedDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        oracle.assertUnsignedDeniedAndParticipantNeverSucceeds(
                "ServiceProtocol.signed.s3Get",
                "GET",
                "/fuzz-bucket/object",
                Map.of(),
                null,
                "us-east-1",
                "s3");
    }

    @Test
    void unsignedIotThingsDenied() throws Exception {
        assertUnsignedGetDenied("/things", "ServiceProtocol.iot.things");
    }

    @Test
    void unsignedRdsDataExecuteDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/Execute",
                Map.of("Content-Type", "application/json"),
                "{\"resourceArn\":\"arn:aws:rds:us-east-1:000000000000:cluster/x\",\"sql\":\"SELECT 1\"}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "ServiceProtocol.rdsdata.execute",
                    "/Execute",
                    "unsigned RDS Data ExecuteStatement succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedAppConfigApplicationsDenied() throws Exception {
        assertUnsignedGetDenied("/applications", "ServiceProtocol.appconfig.applications");
    }

    @Test
    void unsignedSchedulerSchedulesDenied() throws Exception {
        assertUnsignedGetDenied("/schedules", "ServiceProtocol.scheduler.schedules");
    }

    @Test
    void unsignedPipesListDenied() throws Exception {
        assertUnsignedGetDenied("/v1/pipes", "ServiceProtocol.pipes.list");
    }

    @Test
    void unsignedBedrockInvokeDenied() throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                "/model/x/invoke",
                Map.of("Content-Type", "application/json"),
                "{}");
        if (result.success()) {
            SecurityOracle.failSecurity(
                    "ServiceProtocol.bedrock.invoke",
                    "/model/x/invoke",
                    "unsigned Bedrock invoke succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    @Test
    void unsignedBackupVaultDenied() throws Exception {
        assertUnsignedGetDenied("/backup-vaults/x", "ServiceProtocol.backup.vault");
    }

    @Test
    void unsignedRoute53HostedZoneDenied() throws Exception {
        assertUnsignedGetDenied("/hostedzone/Z1", "ServiceProtocol.route53.hostedzone");
    }

    @Test
    void unsignedCloudFrontDistributionDenied() throws Exception {
        assertUnsignedGetDenied(
                "/2020-05-31/distribution/D1", "ServiceProtocol.cloudfront.distribution");
    }

    @Test
    void unsignedBatchSubmitJobDenied() throws Exception {
        assertUnsignedPostDenied(
                "/v1/submitjob",
                "{}",
                "ServiceProtocol.batch.submitjob");
    }

    @Test
    void unsignedAmazonMqBrokersDenied() throws Exception {
        assertUnsignedGetDenied("/v1/brokers", "ServiceProtocol.amazonmq.brokers");
    }

    @Test
    void unsignedS3VectorsCreateBucketDenied() throws Exception {
        assertUnsignedPostDenied(
                "/CreateVectorBucket",
                "{\"vectorBucketName\":\"fuzz-bucket\"}",
                "ServiceProtocol.s3vectors.createVectorBucket");
    }

    private void assertUnsignedPostDenied(String path, String body, String target) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange(
                "POST",
                path,
                Map.of("Content-Type", "application/json"),
                body);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    target,
                    path,
                    "unsigned REST POST succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    private void assertUnsignedGetDenied(String path, String target) throws Exception {
        DifferentialHttpOracle oracle = requireOracle();
        DifferentialHttpOracle.ProbeResult result = oracle.exchange("GET", path, Map.of(), null);
        if (result.success()) {
            SecurityOracle.failSecurity(
                    target,
                    path,
                    "unsigned REST path succeeded",
                    Map.of("status", String.valueOf(result.status())));
        }
    }

    private static DifferentialHttpOracle requireOracle() {
        Assumptions.assumeFalse(
                Boolean.parseBoolean(System.getProperty("fuzz.operator.skip", "true")),
                "Enable with -Pfuzz-operator");
        Optional<DifferentialHttpOracle> maybe = live();
        Assumptions.assumeTrue(maybe.isPresent(),
                "Set AWS_ENDPOINT_URL for service protocol campaigns");
        return maybe.get();
    }

    @Provide
    Arbitrary<String> queryActions() {
        List<String> actions = CorpusLoader.orFallback(
                "query/actions.txt", FuzzBodyGenerators.highValueQueryActions());
        return Arbitraries.of(actions);
    }

    @Provide
    Arbitrary<String> jsonTargets() {
        List<String> targets = CorpusLoader.orFallback(
                "json11/targets.txt", FuzzBodyGenerators.highValueJson11Targets());
        return Arbitraries.of(targets);
    }

    @Provide
    Arbitrary<String> restPaths() {
        List<String> paths = CorpusLoader.orFallback(
                "paths/rest.txt", FuzzBodyGenerators.highValueRestPaths());
        return Arbitraries.of(paths);
    }
}
