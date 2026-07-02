package io.github.hectorvent.floci.core.common.container;

import io.github.hectorvent.floci.config.EmulatorConfig;
import io.github.hectorvent.floci.core.common.docker.ContainerDetector;

/**
 * In-container TCP proxy so workloads can fetch credentials at a boto3-allowed host.
 * AWS Lambda Python images ship {@code python3} and {@code curl}; installing {@code socat}
 * via package managers is too heavy for default function memory.
 */
public final class ContainerCredentialsLinkLocalProxy {

    private ContainerCredentialsLinkLocalProxy() {
    }

    public static boolean required(EmulatorConfig config, ContainerDetector containerDetector) {
        return config.ctf().containerCredentialsUseLinkLocalUri()
                && containerDetector.isRunningInContainer();
    }

    static String[] startLocalhostProxyCommand(int listenPort, String upstreamHost, int upstreamPort) {
        String probeUrl = "http://127.0.0.1:" + listenPort + "/v2/credentials/probe-reachability";
        String python = String.join("\n",
                "import select, socket, threading",
                "LISTEN = ('127.0.0.1', " + listenPort + ")",
                "REMOTE = ('" + upstreamHost + "', " + upstreamPort + ")",
                "def relay(client, remote):",
                "    sockets = [client, remote]",
                "    while True:",
                "        readable, _, _ = select.select(sockets, [], [], 60)",
                "        if not readable:",
                "            return",
                "        for sock in readable:",
                "            data = sock.recv(8192)",
                "            if not data:",
                "                return",
                "            (remote if sock is client else client).sendall(data)",
                "def handle(client):",
                "    try:",
                "        remote = socket.create_connection(REMOTE, timeout=10)",
                "        relay(client, remote)",
                "    finally:",
                "        client.close()",
                "server = socket.socket()",
                "server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)",
                "server.bind(LISTEN)",
                "server.listen(32)",
                "while True:",
                "    client, _ = server.accept()",
                "    threading.Thread(target=handle, args=(client,), daemon=True).start()");
        return new String[]{"sh", "-c", String.join("\n",
                "set -eu",
                "if [ -f /tmp/floci-creds-proxy.pid ] && kill -0 \"$(cat /tmp/floci-creds-proxy.pid)\" 2>/dev/null; then",
                "  exit 0",
                "fi",
                "nohup python3 - <<'PY' >/tmp/floci-creds-proxy.log 2>&1 &",
                python,
                "PY",
                "echo $! > /tmp/floci-creds-proxy.pid",
                "for i in 1 2 3 4 5 6 7 8 9 10 11 12; do",
                "  code=$(curl -o /dev/null -s -w '%{http_code}' --max-time 1 " + probeUrl + " || true)",
                "  if [ \"$code\" = \"404\" ]; then exit 0; fi",
                "  sleep 1",
                "done",
                "cat /tmp/floci-creds-proxy.log >&2 || true",
                "exit 1")};
    }
}
