package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.SecurityBypassPaths;
import io.github.hectorvent.floci.core.common.SigV4RequestValidator;
import io.github.hectorvent.floci.core.common.SigV4aPresignSupport;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.fuzz.support.CorpusLoader;
import io.github.hectorvent.floci.fuzz.support.FuzzRequestContexts;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.core.MediaType;
import jakarta.ws.rs.core.MultivaluedHashMap;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Presigned POST policy mutation: signature validation and multipart classification oracles.
 */
class PresignedPostConditionFuzzTest {

  private static final String WRONG_SECRET = "definitely-not-the-signing-secret";
  private static final String CREDENTIAL =
          "AKIATEST/20300101/us-east-1/s3/aws4_request";
  private static final String AMZ_DATE = "20300101T000000Z";

  @Property(tries = 60)
  void validatePresignedPostPolicyNeverThrowsError(
          @ForAll("policyBase64Values") String policyBase64,
          @ForAll("algorithms") String algorithm,
          @ForAll @StringLength(max = 128) String signature) throws Exception {
    String seed = policyBase64 + "|" + algorithm + "|" + signature;
    CrashWatchdog.run("PresignPost.validate", seed, 2000, () -> {
      SigV4RequestValidator.Result result = SecurityOracle.runCatching(
              "PresignPost.validate", seed, () ->
                      SigV4RequestValidator.validatePresignedPostPolicy(
                              policyBase64,
                              algorithm,
                              CREDENTIAL,
                              AMZ_DATE,
                              signature == null || signature.isBlank() ? "00" : signature,
                              WRONG_SECRET));
      if (result == SigV4RequestValidator.Result.VALID) {
        SecurityOracle.failSecurity(
                "PresignPost.validate",
                seed,
                "garbage presigned POST policy validated as VALID with wrong secret",
                Map.of());
      }
      return null;
    });
  }

  @Property(tries = 40)
  void validatePresignedPostPolicySigV4aNeverThrowsError(
          @ForAll("policyBase64Values") String policyBase64,
          @ForAll @StringLength(max = 200) String signature) throws Exception {
    String seed = policyBase64 + "|" + signature;
    CrashWatchdog.run("PresignPost.sigv4a", seed, 2000, () -> {
      SigV4RequestValidator.Result result = SecurityOracle.runCatching(
              "PresignPost.sigv4a", seed, () ->
                      SigV4RequestValidator.validatePresignedPostPolicySigV4a(
                              policyBase64,
                              SigV4aPresignSupport.ALGORITHM,
                              CREDENTIAL,
                              AMZ_DATE,
                              signature == null || signature.isBlank() ? "aa".repeat(64) : signature,
                              null));
      if (result == SigV4RequestValidator.Result.VALID) {
        SecurityOracle.failSecurity(
                "PresignPost.sigv4a",
                seed,
                "garbage SigV4a presigned POST policy validated as VALID",
                Map.of());
      }
      return null;
    });
  }

  @Property(tries = 40)
  void presignedPostClassificationConsistentWithPolicyMarkers(
          @ForAll("bucketPaths") String path,
          @ForAll("policyFieldNames") String fieldName,
          @ForAll @StringLength(max = 120) String fieldValue) {
    String boundary = "----fuzzboundary";
    String body = multipartField(boundary, fieldName, fieldValue);
    ContainerRequestContext ctx = FuzzRequestContexts.ctx(
            "POST", path, new MultivaluedHashMap<>(),
            MediaType.valueOf("multipart/form-data; boundary=" + boundary), body, null);

    boolean multipart = SecurityBypassPaths.isMultipartBucketPostRequest(ctx);
    boolean presigned = SecurityBypassPaths.isPresignedPostRequest(ctx);
    boolean markerPresent = isPolicyMarker(fieldName);

    if (markerPresent && multipart && !presigned) {
      SecurityOracle.failSecurity(
              "PresignPost.classify",
              path + "|" + fieldName,
              "policy marker present on bucket POST but isPresignedPostRequest false",
              Map.of("multipart", String.valueOf(multipart)));
    }
    if (presigned && !multipart) {
      SecurityOracle.failSecurity(
              "PresignPost.classify",
              path + "|" + fieldName,
              "isPresignedPostRequest true without multipart bucket POST",
              Map.of());
    }
    if (presigned && !markerPresent) {
      SecurityOracle.failSecurity(
              "PresignPost.classify",
              path + "|" + fieldName,
              "isPresignedPostRequest true without policy marker field",
              Map.of());
    }
  }

  @Property(tries = 30)
  void nonBucketMultipartNeverClassifiedAsPresignedPost(
          @ForAll("nonBucketPaths") String path,
          @ForAll("policyFieldNames") String fieldName) {
    String boundary = "----fuzzboundary";
    String body = multipartField(boundary, fieldName, "policy-value");
    ContainerRequestContext ctx = FuzzRequestContexts.ctx(
            "POST", path, new MultivaluedHashMap<>(),
            MediaType.valueOf("multipart/form-data; boundary=" + boundary), body, null);
    if (SecurityBypassPaths.isPresignedPostRequest(ctx)) {
      SecurityOracle.failSecurity(
              "PresignPost.nonBucket",
              path,
              "non-bucket path classified as presigned POST",
              Map.of("field", fieldName));
    }
  }

  @Property(tries = 30)
  void mutatedPolicyJsonNeverValidWithWrongSecret(
          @ForAll("policyJsonSamples") String policyJson,
          @ForAll @StringLength(min = 8, max = 64) String signatureNoise) throws Exception {
    String policyBase64 = Base64.getEncoder().encodeToString(
            policyJson.getBytes(StandardCharsets.UTF_8));
    String seed = policyJson + "|" + signatureNoise;
    CrashWatchdog.run("PresignPost.policyJson", seed, 2000, () -> {
      SigV4RequestValidator.Result result = SigV4RequestValidator.validatePresignedPostPolicy(
              policyBase64,
              "AWS4-HMAC-SHA256",
              CREDENTIAL,
              AMZ_DATE,
              signatureNoise,
              WRONG_SECRET);
      if (result == SigV4RequestValidator.Result.VALID) {
        SecurityOracle.failSecurity(
                "PresignPost.policyJson",
                seed,
                "mutated policy JSON validated with wrong secret",
                Map.of());
      }
      return null;
    });
  }

  private static boolean isPolicyMarker(String fieldName) {
    if (fieldName == null) {
      return false;
    }
    String lower = fieldName.toLowerCase(Locale.ROOT);
    return "policy".equals(lower) || "x-amz-algorithm".equals(lower);
  }

  private static String multipartField(String boundary, String name, String value) {
    String safeName = name == null ? "policy" : name;
    String safeValue = value == null ? "" : value;
    return "--" + boundary + "\r\n"
            + "Content-Disposition: form-data; name=\"" + safeName + "\"\r\n\r\n"
            + safeValue + "\r\n"
            + "--" + boundary + "--\r\n";
  }

  @Provide
  Arbitrary<String> algorithms() {
    return Arbitraries.of(
            "AWS4-HMAC-SHA256",
            SigV4aPresignSupport.ALGORITHM,
            "AWS4-HMAC-SHA1",
            "Bearer",
            "",
            "aws4-hmac-sha256");
  }

  @Provide
  Arbitrary<String> policyBase64Values() {
    List<String> samples = new ArrayList<>();
    for (String json : CorpusLoader.orFallback("presign/post-policies.txt", List.of())) {
      samples.add(Base64.getEncoder().encodeToString(json.getBytes(StandardCharsets.UTF_8)));
    }
    samples.add("");
    samples.add("not-valid-base64!!!");
    samples.add(Base64.getEncoder().encodeToString("{\"conditions\":[]}".getBytes(StandardCharsets.UTF_8)));
    return Arbitraries.oneOf(
            Arbitraries.of(samples),
            Arbitraries.strings().withCharRange('a', 'z').ofMaxLength(80)
                    .map(s -> Base64.getEncoder().encodeToString(s.getBytes(StandardCharsets.UTF_8))));
  }

  @Provide
  Arbitrary<String> policyJsonSamples() {
    List<String> base = CorpusLoader.orFallback("presign/post-policies.txt", List.of(
            "{\"expiration\":\"2030-01-01T00:00:00.000Z\",\"conditions\":[{\"bucket\":\"fuzz-bucket\"}]}"));
    return Arbitraries.oneOf(
            Arbitraries.of(base),
            Arbitraries.strings().withCharRange('a', 'z').ofMaxLength(40)
                    .map(noise -> "{\"expiration\":\"2030-01-01T00:00:00.000Z\",\"conditions\":["
                            + "[\"eq\",\"$key\",\"" + noise + "\"]]}"));
  }

  @Provide
  Arbitrary<String> bucketPaths() {
    return Arbitraries.of("/fuzz-bucket", "/my-bucket", "/upload-target");
  }

  @Provide
  Arbitrary<String> nonBucketPaths() {
    return Arbitraries.of(
            "/fuzz-bucket/key",
            "/health",
            "/_floci/health",
            "/v2/repo/manifests/latest");
  }

  @Provide
  Arbitrary<String> policyFieldNames() {
    return Arbitraries.of("policy", "Policy", "x-amz-algorithm", "key", "file", "noise");
  }
}
