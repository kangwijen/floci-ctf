package io.github.hectorvent.floci.fuzz.unit;

import io.github.hectorvent.floci.core.common.CtfVelocityEngineFactory;
import io.github.hectorvent.floci.fuzz.oracle.CrashWatchdog;
import io.github.hectorvent.floci.fuzz.oracle.SecurityOracle;
import io.github.hectorvent.floci.services.lambda.zip.ZipExtractor;
import net.jqwik.api.Arbitraries;
import net.jqwik.api.Arbitrary;
import net.jqwik.api.ForAll;
import net.jqwik.api.Property;
import net.jqwik.api.Provide;
import net.jqwik.api.constraints.StringLength;
import org.apache.velocity.VelocityContext;
import org.apache.velocity.app.VelocityEngine;

import java.io.ByteArrayOutputStream;
import java.io.StringWriter;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.Map;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * ZIP path-traversal and VTL sandbox fuzz seeds.
 */
class ZipAndVtlFuzzTest {

    private final ZipExtractor zipExtractor = new ZipExtractor();

    @Property(tries = 40)
    void zipTraversalDoesNotEscapeTarget(
            @ForAll("safeLeaf") String leaf) throws Exception {
        Path target = Files.createTempDirectory("fuzz-zip-");
        try {
            byte[] zip = zipWithEntry("../" + leaf + ".txt", "pwned".getBytes(StandardCharsets.UTF_8));
            String seed = "../" + leaf;
            CrashWatchdog.run("ZipExtractor.traversal", seed, 2000, () -> {
                try {
                    zipExtractor.extractTo(zip, target);
                } catch (Exception ignored) {
                    // Rejection is fine.
                }
                Path escaped = target.getParent().resolve(leaf + ".txt");
                if (Files.exists(escaped) && !escaped.startsWith(target)) {
                    SecurityOracle.failSecurity(
                            "ZipExtractor.traversal",
                            seed,
                            "ZIP entry escaped target directory",
                            Map.of("escaped", escaped.toString()));
                }
                return null;
            });
        } finally {
            deleteRecursive(target);
        }
    }

    @Property(tries = 30)
    void vtlProcessBuilderChainDoesNotExecute(
            @ForAll @StringLength(max = 30) String noise) throws Exception {
        VelocityEngine engine = CtfVelocityEngineFactory.create("fuzz-vtl");
        String template = "#set($rt = $class.inspect(\"java.lang.Runtime\"))"
                + "#set($r = $rt.getRuntime())"
                + "$r.exec(\"echo " + noise.replace("\"", "") + "\")";
        CrashWatchdog.run("CtfVelocityEngineFactory.rce", template, 2000, () -> {
            StringWriter out = new StringWriter();
            VelocityContext ctx = new VelocityContext();
            try {
                engine.evaluate(ctx, out, "fuzz", template);
            } catch (Exception ignored) {
                // Sandbox may error; that is success.
            }
            String rendered = out.toString();
            if (rendered.contains("Process") && rendered.contains("pid=")) {
                SecurityOracle.failSecurity(
                        "CtfVelocityEngineFactory.rce",
                        template,
                        "VTL appeared to execute ProcessBuilder/Runtime",
                        Map.of("rendered", rendered.substring(0, Math.min(200, rendered.length()))));
            }
            return null;
        });
    }

    @Provide
    Arbitrary<String> safeLeaf() {
        return Arbitraries.strings().alpha().ofMinLength(1).ofMaxLength(24);
    }

    private static byte[] zipWithEntry(String name, byte[] content) throws Exception {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        try (ZipOutputStream zos = new ZipOutputStream(bos)) {
            zos.putNextEntry(new ZipEntry(name));
            zos.write(content);
            zos.closeEntry();
        }
        return bos.toByteArray();
    }

    private static void deleteRecursive(Path root) throws Exception {
        if (root == null || !Files.exists(root)) {
            return;
        }
        try (var walk = Files.walk(root)) {
            walk.sorted((a, b) -> b.compareTo(a)).forEach(p -> {
                try {
                    Files.deleteIfExists(p);
                } catch (Exception ignored) {
                    // best effort
                }
            });
        }
    }
}
