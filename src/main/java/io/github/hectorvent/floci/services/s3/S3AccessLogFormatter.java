package io.github.hectorvent.floci.services.s3;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;
import java.util.StringJoiner;

/**
 * Formats S3 server access log lines per
 * <a href="https://docs.aws.amazon.com/AmazonS3/latest/userguide/LogFormat.html">AWS log record fields</a>.
 */
final class S3AccessLogFormatter {

    private static final DateTimeFormatter LOG_TIME = DateTimeFormatter
            .ofPattern("dd/MMM/yyyy:HH:mm:ss Z", Locale.ENGLISH)
            .withZone(ZoneOffset.UTC);

    private S3AccessLogFormatter() {
    }

    static String canonicalUserId(String accountId) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(("floci-canonical:" + accountId).getBytes(StandardCharsets.UTF_8));
            StringBuilder sb = new StringBuilder(64);
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (NoSuchAlgorithmException e) {
            return "0".repeat(64);
        }
    }

    static String formatLine(S3AccessLogContext ctx, String bucketOwnerId) {
        String time = "[" + LOG_TIME.format(ctx.timestamp()) + "]";
        String keyField = ctx.key() != null && !ctx.key().isEmpty() ? ctx.key() : "-";
        String errorCode = ctx.errorCode() != null ? ctx.errorCode() : "-";
        String bytesSent = ctx.bytesSent() >= 0 ? Long.toString(ctx.bytesSent()) : "-";
        String objectSize = ctx.objectSize() != null ? Long.toString(ctx.objectSize()) : "-";
        String totalTime = ctx.totalTimeMs() >= 0 ? Long.toString(ctx.totalTimeMs()) : "-";
        String turnAround = ctx.turnAroundTimeMs() >= 0 ? Long.toString(ctx.turnAroundTimeMs()) : "-";
        String referer = quoteOrDash(ctx.referer());
        String userAgent = quoteOrDash(ctx.userAgent());
        String versionId = ctx.versionId() != null ? ctx.versionId() : "-";
        String signatureVersion = ctx.signatureVersion() != null ? ctx.signatureVersion() : "-";
        String cipherSuite = ctx.cipherSuite() != null ? ctx.cipherSuite() : "-";
        String authenticationType = ctx.authenticationType() != null ? ctx.authenticationType() : "-";
        String hostHeader = ctx.hostHeader() != null ? ctx.hostHeader() : "-";
        String tlsVersion = ctx.tlsVersion() != null ? ctx.tlsVersion() : "-";
        String accessPointArn = ctx.accessPointArn() != null ? ctx.accessPointArn() : "-";
        String aclRequired = ctx.aclRequired() != null ? ctx.aclRequired() : "-";
        String sourceRegion = ctx.sourceRegion() != null ? ctx.sourceRegion() : "-";
        String remoteIp = ctx.remoteIp() != null ? ctx.remoteIp() : "-";
        String requester = ctx.requester() != null ? ctx.requester() : "-";

        StringJoiner joiner = new StringJoiner(" ");
        joiner.add(bucketOwnerId);
        joiner.add(ctx.sourceBucket());
        joiner.add(time);
        joiner.add(remoteIp);
        joiner.add(requester);
        joiner.add(ctx.requestId());
        joiner.add(ctx.operation());
        joiner.add(keyField);
        joiner.add("\"" + ctx.requestUri() + "\"");
        joiner.add(Integer.toString(ctx.httpStatus()));
        joiner.add(errorCode);
        joiner.add(bytesSent);
        joiner.add(objectSize);
        joiner.add(totalTime);
        joiner.add(turnAround);
        joiner.add(referer);
        joiner.add(userAgent);
        joiner.add(versionId);
        joiner.add(ctx.hostId());
        joiner.add(signatureVersion);
        joiner.add(cipherSuite);
        joiner.add(authenticationType);
        joiner.add(hostHeader);
        joiner.add(tlsVersion);
        joiner.add(accessPointArn);
        joiner.add(aclRequired);
        joiner.add(sourceRegion);
        return joiner.toString();
    }

    static int fieldCount(String line) {
        return line.split(" ", -1).length;
    }

    private static String quoteOrDash(String value) {
        if (value == null || value.isBlank()) {
            return "\"-\"";
        }
        return "\"" + value.replace("\"", "\\\"") + "\"";
    }
}
