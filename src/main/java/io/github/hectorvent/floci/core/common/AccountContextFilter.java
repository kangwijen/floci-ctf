package io.github.hectorvent.floci.core.common;

import io.github.hectorvent.floci.core.common.auth.AuthPosture;
import jakarta.annotation.Priority;
import jakarta.enterprise.context.ApplicationScoped;
import jakarta.inject.Inject;
import jakarta.ws.rs.Priorities;
import jakarta.ws.rs.container.ContainerRequestContext;
import jakarta.ws.rs.container.ContainerRequestFilter;
import jakarta.ws.rs.ext.Provider;

import java.util.Optional;

/**
 * Populates {@link RequestContext} with the account ID and region derived from
 * the incoming AWS Authorization header or, for presigned URL requests, the
 * X-Amz-Credential query parameter. Runs at AUTHENTICATION priority so that
 * downstream filters (e.g. IAM enforcement) can rely on the context being set.
 *
 * <p>Account resolution precedence: a 12-digit access key ID is used directly as
 * the account; otherwise temporary credentials (e.g. assumed-role {@code ASIA...}
 * keys) are looked up in the session store via {@link SessionAccountLookup}; if
 * neither matches, the configured default account applies.
 *
 * <p>When {@link AuthPosture#deferCallerAccessKeyUntilVerified()} is true (SigV4
 * validation active), {@link RequestContext#setAccessKeyId(String)} is deferred to
 * {@link SigV4ValidationFilter} / {@code PreSignedUrlFilter} after verification (O23).
 */
@Provider
@ApplicationScoped
@Priority(Priorities.AUTHENTICATION - 100)
public class AccountContextFilter implements ContainerRequestFilter {

    private final AccountResolver accountResolver;
    private final RegionResolver regionResolver;
    private final RequestContext requestContext;
    private final SessionAccountLookup sessionAccountLookup;
    private final AuthPosture authPosture;

    @Inject
    public AccountContextFilter(AccountResolver accountResolver,
                                RegionResolver regionResolver,
                                RequestContext requestContext,
                                SessionAccountLookup sessionAccountLookup,
                                AuthPosture authPosture) {
        this.accountResolver = accountResolver;
        this.regionResolver = regionResolver;
        this.requestContext = requestContext;
        this.sessionAccountLookup = sessionAccountLookup;
        this.authPosture = authPosture;
    }

    @Override
    public void filter(ContainerRequestContext ctx) {
        String auth = ctx.getHeaderString("Authorization");
        if (auth != null && !auth.isEmpty()) {
            String akid = accountResolver.extractAccessKeyId(auth);
            requestContext.setAccountId(resolveAccount(akid, accountResolver.resolve(auth)));
            requestContext.setRegion(regionResolver.resolveRegionFromAuth(auth));
            publishAccessKeyId(akid);
        } else {
            String credential = ctx.getUriInfo().getQueryParameters().getFirst("X-Amz-Credential");
            if (credential != null && !credential.isEmpty()) {
                String akid = accountResolver.extractPresignedAccessKeyId(credential);
                requestContext.setAccountId(
                        resolveAccount(akid, accountResolver.resolveFromPresignedCredential(credential)));
                requestContext.setRegion(regionResolver.resolveRegionFromPresignedCredential(credential));
                publishAccessKeyId(akid);
            } else {
                requestContext.setAccountId(accountResolver.resolve(null));
                requestContext.setRegion(regionResolver.resolveRegionFromAuth(null));
                requestContext.setAccessKeyId(null);
            }
        }
    }

    private void publishAccessKeyId(String akid) {
        if (authPosture.deferCallerAccessKeyUntilVerified()) {
            requestContext.setAccessKeyId(null);
            return;
        }
        requestContext.setAccessKeyId(akid);
    }

    /**
     * Applies the account-resolution precedence. A 12-digit AKID is already reflected in
     * {@code resolvedDefault} (the account or default returned by {@link AccountResolver});
     * for any other key shape, a live session lookup takes precedence before falling back.
     */
    private String resolveAccount(String akid, String resolvedDefault) {
        if (akid != null && !akid.matches("\\d{12}")) {
            Optional<String> sessionAccount = sessionAccountLookup.resolveAccountId(akid);
            if (sessionAccount.isPresent()) {
                return sessionAccount.get();
            }
        }
        return resolvedDefault;
    }
}
