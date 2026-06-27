package io.github.hectorvent.floci.services.s3;

import io.github.hectorvent.floci.core.common.XmlParser;
import io.github.hectorvent.floci.services.s3.model.LoggingConfiguration;
import io.github.hectorvent.floci.services.s3.model.PartitionedPrefix;
import io.github.hectorvent.floci.services.s3.model.TargetGrant;
import io.github.hectorvent.floci.services.s3.model.TargetObjectKeyFormat;

import java.util.ArrayList;
import java.util.List;
import java.util.Locale;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

final class S3LoggingConfigurationParser {

    private static final Pattern TARGET_GRANT_BLOCK = Pattern.compile(
            "<TargetGrant>(.*?)</TargetGrant>", Pattern.DOTALL | Pattern.CASE_INSENSITIVE);

    private S3LoggingConfigurationParser() {
    }

    static LoggingConfiguration parse(String loggingXml) {
        String targetBucket = XmlParser.extractFirst(loggingXml, "TargetBucket", null);
        if (targetBucket == null || targetBucket.isBlank()) {
            return null;
        }
        String targetPrefix = XmlParser.extractFirst(loggingXml, "TargetPrefix", "");
        if (targetPrefix == null) {
            targetPrefix = "";
        }
        LoggingConfiguration config = new LoggingConfiguration(targetBucket.trim(), targetPrefix);
        config.setTargetGrants(parseTargetGrants(loggingXml));
        config.setTargetObjectKeyFormat(parseTargetObjectKeyFormat(loggingXml));
        return config;
    }

    private static List<TargetGrant> parseTargetGrants(String loggingXml) {
        List<TargetGrant> grants = new ArrayList<>();
        Matcher matcher = TARGET_GRANT_BLOCK.matcher(loggingXml);
        while (matcher.find()) {
            String block = matcher.group(1);
            String wrapped = "<TargetGrant>" + block + "</TargetGrant>";
            TargetGrant grant = new TargetGrant();
            grant.setGranteeId(XmlParser.extractFirst(wrapped, "ID", null));
            grant.setGranteeDisplayName(XmlParser.extractFirst(wrapped, "DisplayName", null));
            grant.setGranteeType(XmlParser.extractFirst(wrapped, "Type", "CanonicalUser"));
            grant.setPermission(XmlParser.extractFirst(wrapped, "Permission", null));
            if (grant.getGranteeId() != null || grant.getPermission() != null) {
                grants.add(grant);
            }
        }
        return grants;
    }

    private static TargetObjectKeyFormat parseTargetObjectKeyFormat(String loggingXml) {
        String lower = loggingXml.toLowerCase(Locale.ROOT);
        if (lower.contains("<partitionedprefix")) {
            String source = XmlParser.extractFirst(loggingXml, "PartitionDateSource", "EventTime");
            return TargetObjectKeyFormat.partitionedPrefix(new PartitionedPrefix(source));
        }
        if (lower.contains("<simpleprefix")) {
            return TargetObjectKeyFormat.simplePrefix();
        }
        return TargetObjectKeyFormat.simplePrefix();
    }
}
