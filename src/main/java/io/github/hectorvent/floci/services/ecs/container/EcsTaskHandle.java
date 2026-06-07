package io.github.hectorvent.floci.services.ecs.container;

import java.io.Closeable;
import java.util.List;
import java.util.Map;

/**
 * Holds the runtime Docker container IDs for a running ECS task.
 * Maps container name → Docker container ID and log stream handle.
 */
public class EcsTaskHandle {

    private final String taskArn;
    private final Map<String, String> containerIds;   // containerName → dockerId
    private final List<Closeable> logStreams;
    private final String taskId;
    private final List<String> credentialTokens;

    public EcsTaskHandle(String taskArn, Map<String, String> containerIds, List<Closeable> logStreams) {
        this(taskArn, containerIds, logStreams, null, List.of());
    }

    public EcsTaskHandle(String taskArn, Map<String, String> containerIds, List<Closeable> logStreams,
                         String taskId, List<String> credentialTokens) {
        this.taskArn = taskArn;
        this.containerIds = containerIds;
        this.logStreams = logStreams;
        this.taskId = taskId;
        this.credentialTokens = credentialTokens != null ? credentialTokens : List.of();
    }

    public String getTaskArn() { return taskArn; }
    public Map<String, String> getContainerIds() { return containerIds; }
    public List<Closeable> getLogStreams() { return logStreams; }
    public String getTaskId() { return taskId; }
    public List<String> getCredentialTokens() { return credentialTokens; }
}
