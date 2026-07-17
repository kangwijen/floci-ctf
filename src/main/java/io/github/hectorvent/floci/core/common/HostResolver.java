package io.github.hectorvent.floci.core.common;

import java.net.InetAddress;
import java.net.UnknownHostException;

/**
 * Resolves a hostname to addresses once for pin-connect egress.
 * Tests inject a rebinding resolver to prove TOCTOU denial.
 */
@FunctionalInterface
public interface HostResolver {

    InetAddress[] resolve(String host) throws UnknownHostException;
}
