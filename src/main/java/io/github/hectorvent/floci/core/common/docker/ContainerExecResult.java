package io.github.hectorvent.floci.core.common.docker;

/**
 * Result of a one-shot {@code docker exec} inside a running container.
 */
public record ContainerExecResult(int exitCode, String output) {

    public String summary() {
        String text = output == null ? "" : output.stripTrailing();
        if (text.isBlank()) {
            return "exit=" + exitCode;
        }
        int start = Math.max(0, text.length() - 2048);
        return "exit=" + exitCode + " output=" + text.substring(start);
    }
}
