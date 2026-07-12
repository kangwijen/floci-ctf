package io.github.hectorvent.floci.fuzz.oracle;

import java.util.LinkedHashMap;
import java.util.Map;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/**
 * Secondary hang oracle: runs a callable with a wall-clock timeout.
 */
public final class CrashWatchdog {

    private CrashWatchdog() {
    }

    public static <T> T run(String target, String seed, long timeoutMs, Callable<T> action)
            throws Exception {
        ExecutorService exec = Executors.newSingleThreadExecutor(r -> {
            Thread t = new Thread(r, "fuzz-watchdog-" + target);
            t.setDaemon(true);
            return t;
        });
        Future<T> future = exec.submit(action);
        try {
            return future.get(timeoutMs, TimeUnit.MILLISECONDS);
        } catch (TimeoutException te) {
            future.cancel(true);
            Map<String, String> details = new LinkedHashMap<>();
            details.put("timeoutMs", String.valueOf(timeoutMs));
            Finding finding = new Finding(Finding.Kind.HANG, target, "watchdog timeout", seed, details);
            try {
                FindingSerializer.write(finding);
            } catch (Exception ignored) {
                // ignore
            }
            throw new AssertionError("[" + target + "] hang after " + timeoutMs + "ms");
        } catch (ExecutionException ee) {
            Throwable cause = ee.getCause() == null ? ee : ee.getCause();
            if (cause instanceof Error || cause instanceof RuntimeException) {
                SecurityOracle.recordCrash(target, seed, cause);
            }
            if (cause instanceof Exception ex) {
                throw ex;
            }
            if (cause instanceof Error err) {
                throw err;
            }
            throw new RuntimeException(cause);
        } finally {
            exec.shutdownNow();
        }
    }
}
