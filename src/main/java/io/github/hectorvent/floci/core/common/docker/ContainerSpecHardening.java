package io.github.hectorvent.floci.core.common.docker;

import com.github.dockerjava.api.model.Bind;
import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;

import java.util.Locale;

/**
 * Rejects host-escalation container options for non-operator specs before Docker create.
 * Operator-managed launches (EC2 IMDS setup, EKS/k3s) may opt in via
 * {@link ContainerSpec#operatorManaged()}.
 */
public final class ContainerSpecHardening {

    private ContainerSpecHardening() {
    }

    public static void validate(ContainerSpec spec) {
        if (spec == null) {
            throw new IllegalArgumentException("ContainerSpec is required");
        }
        if (spec.operatorManaged()) {
            return;
        }
        if (spec.privileged()) {
            throw new IllegalArgumentException(
                    "Privileged containers are not allowed for non-operator specs");
        }
        rejectDockerSocketBinds(spec.binds());
        rejectDockerSocketMounts(spec.mounts());
    }

    private static void rejectDockerSocketBinds(java.util.List<Bind> binds) {
        if (binds == null || binds.isEmpty()) {
            return;
        }
        for (Bind bind : binds) {
            if (bind == null || bind.getPath() == null) {
                continue;
            }
            if (isDockerSocketHostPath(bind.getPath())) {
                throw new IllegalArgumentException(
                        "Docker socket binds are not allowed for non-operator specs");
            }
        }
    }

    private static void rejectDockerSocketMounts(java.util.List<Mount> mounts) {
        if (mounts == null || mounts.isEmpty()) {
            return;
        }
        for (Mount mount : mounts) {
            if (mount == null || mount.getType() != MountType.BIND) {
                continue;
            }
            String source = mount.getSource();
            if (source != null && isDockerSocketHostPath(source)) {
                throw new IllegalArgumentException(
                        "Docker socket bind mounts are not allowed for non-operator specs");
            }
        }
    }

    static boolean isDockerSocketHostPath(String hostPath) {
        if (hostPath == null || hostPath.isBlank()) {
            return false;
        }
        String normalized = hostPath.trim().toLowerCase(Locale.ROOT).replace('\\', '/');
        return normalized.contains("docker.sock") || normalized.contains("pipe/docker_engine");
    }
}
