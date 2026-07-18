package io.github.hectorvent.floci.services.s3;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Extracts text fields from an S3 browser-based (presigned) POST multipart body.
 */
final class PresignedPostFormParser {

    private PresignedPostFormParser() {
    }

    static Map<String, String> parseTextFields(String contentType, byte[] body) {
        Map<String, String> fields = new LinkedHashMap<>();
        if (contentType == null || body == null || body.length == 0) {
            return fields;
        }
        String boundary = extractBoundary(contentType);
        if (boundary == null) {
            return fields;
        }
        byte[] boundaryBytes = ("--" + boundary).getBytes(StandardCharsets.UTF_8);
        for (byte[] part : splitMultipartParts(body, boundaryBytes)) {
            int headerEnd = indexOfDoubleNewline(part);
            if (headerEnd < 0) {
                continue;
            }
            String headers = new String(part, 0, headerEnd, StandardCharsets.UTF_8);
            int bodyStart = headerEnd + 4;
            byte[] partBody = Arrays.copyOfRange(part, bodyStart, part.length);
            if (partBody.length >= 2
                    && partBody[partBody.length - 2] == '\r'
                    && partBody[partBody.length - 1] == '\n') {
                partBody = Arrays.copyOf(partBody, partBody.length - 2);
            }
            String disposition = extractHeaderValue(headers, "Content-Disposition");
            if (disposition == null) {
                continue;
            }
            String fieldName = extractDispositionParam(disposition, "name");
            if (fieldName == null) {
                continue;
            }
            if (extractDispositionParam(disposition, "filename") != null) {
                continue;
            }
            fields.put(fieldName, new String(partBody, StandardCharsets.UTF_8));
        }
        return fields;
    }

    static Map<String, String> lowerCaseKeys(Map<String, String> fields) {
        Map<String, String> lc = new LinkedHashMap<>(fields.size());
        for (Map.Entry<String, String> e : fields.entrySet()) {
            lc.put(e.getKey().toLowerCase(Locale.ROOT), e.getValue());
        }
        return lc;
    }

    private static String extractBoundary(String contentType) {
        for (String part : contentType.split(";")) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase(Locale.ROOT).startsWith("boundary=")) {
                String boundary = trimmed.substring("boundary=".length()).trim();
                if (boundary.startsWith("\"") && boundary.endsWith("\"") && boundary.length() >= 2) {
                    boundary = boundary.substring(1, boundary.length() - 1);
                }
                return boundary;
            }
        }
        return null;
    }

    private static List<byte[]> splitMultipartParts(byte[] body, byte[] boundary) {
        List<byte[]> parts = new ArrayList<>();
        int pos = indexOf(body, boundary, 0);
        if (pos < 0) {
            return parts;
        }
        pos += boundary.length;
        if (pos < body.length - 1 && body[pos] == '-' && body[pos + 1] == '-') {
            return parts;
        }
        if (pos < body.length - 1 && body[pos] == '\r' && body[pos + 1] == '\n') {
            pos += 2;
        }
        while (pos < body.length) {
            int nextBoundary = indexOf(body, boundary, pos);
            if (nextBoundary < 0) {
                break;
            }
            parts.add(Arrays.copyOfRange(body, pos, nextBoundary));
            pos = nextBoundary + boundary.length;
            if (pos < body.length - 1 && body[pos] == '-' && body[pos + 1] == '-') {
                break;
            }
            if (pos < body.length - 1 && body[pos] == '\r' && body[pos + 1] == '\n') {
                pos += 2;
            }
        }
        return parts;
    }

    private static int indexOf(byte[] data, byte[] pattern, int fromIndex) {
        outer:
        for (int i = fromIndex; i <= data.length - pattern.length; i++) {
            for (int j = 0; j < pattern.length; j++) {
                if (data[i + j] != pattern[j]) {
                    continue outer;
                }
            }
            return i;
        }
        return -1;
    }

    private static int indexOfDoubleNewline(byte[] data) {
        for (int i = 0; i < data.length - 3; i++) {
            if (data[i] == '\r' && data[i + 1] == '\n' && data[i + 2] == '\r' && data[i + 3] == '\n') {
                return i;
            }
        }
        return -1;
    }

    private static String extractHeaderValue(String headers, String headerName) {
        for (String line : headers.split("\r\n")) {
            int colon = line.indexOf(':');
            if (colon <= 0) {
                continue;
            }
            if (line.substring(0, colon).trim().equalsIgnoreCase(headerName)) {
                return line.substring(colon + 1).trim();
            }
        }
        return null;
    }

    private static String extractDispositionParam(String disposition, String paramName) {
        String needle = paramName + "=";
        int idx = disposition.toLowerCase(Locale.ROOT).indexOf(needle.toLowerCase(Locale.ROOT));
        if (idx < 0) {
            return null;
        }
        int valueStart = idx + needle.length();
        if (valueStart >= disposition.length()) {
            return null;
        }
        if (disposition.charAt(valueStart) == '"') {
            int end = disposition.indexOf('"', valueStart + 1);
            if (end < 0) {
                return null;
            }
            return disposition.substring(valueStart + 1, end);
        }
        int end = valueStart;
        while (end < disposition.length()
                && disposition.charAt(end) != ';'
                && disposition.charAt(end) != ' ') {
            end++;
        }
        return disposition.substring(valueStart, end);
    }
}
