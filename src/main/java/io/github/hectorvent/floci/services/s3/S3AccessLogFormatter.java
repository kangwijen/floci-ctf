package io.github.hectorvent.floci.services.s3;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.ZoneOffset;
import java.time.format.DateTimeFormatter;
import java.util.Locale;

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

    static String formatLine(S3AccessLogContext ctx, String bucketOwnerId, String sourceRegion) {
        String time = "[" + LOG_TIME.format(ctx.timestamp()) + "]";
        String keyField = ctx.key() != null && !ctx.key().isEmpty() ? ctx.key() : "-";
        String errorCode = ctx.errorCode() != null ? ctx.errorCode() : "-";
        String bytesSent = ctx.bytesSent() >= 0 ? Long.toString(ctx.bytesSent()) : "-";
        String objectSize = ctx.objectSize() != null ? Long.toString(ctx.objectSize()) : "-";
        String totalTime = ctx.totalTimeMs() >= 0 ? Long.toString(ctx.totalTimeMs()) : "-";
        String referer = quoteOrDash(ctx.referer());
        String userAgent = quoteOrDash(ctx.userAgent());
        String versionId = ctx.versionId() != null ? ctx.versionId() : "-";
        String signatureVersion = ctx.signatureVersion() != null ? ctx.signatureVersion() : "-";
        String authenticationType = ctx.authenticationType() != null ? ctx.authenticationType() : "-";
        String hostHeader = ctx.hostHeader() != null ? ctx.hostHeader() : "-";
        String requester = ctx.requester() != null ? ctx.requester() : "-";
        String remoteIp = ctx.remoteIp() != null ? ctx.remoteIp() : "-";

        return String.join(" ",
                bucketOwnerId,
                ctx.sourceBucket(),
                time,
                remoteIp,
                requester,
                ctx.requestId(),
                ctx.operation(),
                keyField,
                "\"" + ctx.requestUri() + "\"",
                Integer.toString(ctx.httpStatus()),
                errorCode,
                bytesSent,
                objectSize,
                totalTime,
                "-",
                referer,
                userAgent,
                versionId,
                ctx.hostId(),
                signatureVersion,
                "-",
                authenticationType,
                hostHeader,
                "-",
                "-",
                "-",
                sourceRegion != null ? sourceRegion : "-");
    }

    private static String quoteOrDash(String value) {
        if (value == null || value.isBlank()) {
            return "\"-\"";
        }
        return "\"" + value.replace("\"", "\\\"") + "\"";
    }
}
