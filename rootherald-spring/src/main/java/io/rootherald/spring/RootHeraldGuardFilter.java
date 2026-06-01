package io.rootherald.spring;

import io.rootherald.AttestationClaims;
import io.rootherald.RootHeraldException;
import io.rootherald.TokenExpiredException;
import io.rootherald.TokenVerifier;
import io.rootherald.client.RootHeraldClient;
import io.rootherald.client.VerifyResult;

import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;

import java.io.IOException;
import java.util.Arrays;
import java.util.List;
import java.util.Objects;

/**
 * Servlet filter that enforces {@link RootHeraldGuard} on annotated handlers.
 * <p>
 * The filter consults Spring's {@link HandlerMapping} chain to discover whether
 * the current request maps to a guarded handler; if so it verifies the inbound
 * attestation token before forwarding. Non-guarded routes pass through untouched
 * so the same filter can sit at the front of every request without surprising
 * existing endpoints.
 */
public class RootHeraldGuardFilter extends OncePerRequestFilter {

    /** Request attribute populated with the decoded {@link AttestationClaims}. */
    public static final String CLAIMS_ATTRIBUTE = "rootherald.claims";
    /** Header used to convey the attestation token (alongside {@code Authorization}). */
    public static final String TOKEN_HEADER = "X-RootHerald-Token";

    private final TokenVerifier verifier;
    private final RootHeraldClient onlineClient;
    private final boolean onlineMode;
    private final List<HandlerMapping> handlerMappings;

    public RootHeraldGuardFilter(TokenVerifier verifier,
                                 RootHeraldClient onlineClient,
                                 boolean onlineMode,
                                 List<HandlerMapping> handlerMappings) {
        this.verifier = Objects.requireNonNull(verifier, "verifier");
        this.onlineClient = onlineClient;
        this.onlineMode = onlineMode;
        this.handlerMappings = handlerMappings != null ? handlerMappings : List.of();
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain chain) throws ServletException, IOException {
        RootHeraldGuard guard = resolveGuard(request);
        if (guard == null) {
            chain.doFilter(request, response);
            return;
        }
        String token = extractToken(request);
        if (token == null) {
            response.sendError(401, "Missing RootHerald attestation token");
            return;
        }
        try {
            AttestationClaims claims;
            String verdict;
            if (onlineMode && onlineClient != null) {
                VerifyResult vr = onlineClient.verifyOnline(token, guard.action());
                verdict = vr.verdict();
                claims = vr.claims();
            } else {
                claims = verifier.verify(token);
                verdict = "allow";
            }
            if (!Arrays.asList(guard.verdicts()).contains(verdict)) {
                response.sendError(403, "RootHerald verdict not permitted: " + verdict);
                return;
            }
            request.setAttribute(CLAIMS_ATTRIBUTE, claims);
            chain.doFilter(request, response);
        } catch (TokenExpiredException ex) {
            response.sendError(401, "Attestation token expired");
        } catch (RootHeraldException ex) {
            // Distinguish transient (network/JWKS) from terminal (signature, issuer) failures
            if (ex.getMessage() != null && (ex.getMessage().contains("unreachable")
                    || ex.getMessage().contains("Failed to fetch JWKS")
                    || ex.getMessage().contains("JWKS endpoint returned"))) {
                response.sendError(503, "RootHerald verifier unavailable");
            } else {
                response.sendError(401, "Attestation token rejected: " + ex.getMessage());
            }
        }
    }

    private RootHeraldGuard resolveGuard(HttpServletRequest request) {
        for (HandlerMapping mapping : handlerMappings) {
            try {
                HandlerExecutionChain chain = mapping.getHandler(request);
                if (chain == null) {
                    continue;
                }
                Object handler = chain.getHandler();
                if (handler instanceof HandlerMethod hm) {
                    RootHeraldGuard guard = hm.getMethodAnnotation(RootHeraldGuard.class);
                    if (guard == null) {
                        guard = hm.getBeanType().getAnnotation(RootHeraldGuard.class);
                    }
                    if (guard != null) {
                        return guard;
                    }
                }
            } catch (Exception ignored) {
                // Some mappings throw on misses — keep iterating.
            }
        }
        return null;
    }

    private static String extractToken(HttpServletRequest request) {
        String h = request.getHeader(TOKEN_HEADER);
        if (h != null && !h.isBlank()) {
            return h.trim();
        }
        String auth = request.getHeader("Authorization");
        if (auth != null) {
            if (auth.startsWith("RootHerald ")) {
                return auth.substring("RootHerald ".length()).trim();
            }
            if (auth.startsWith("Bearer ")) {
                return auth.substring("Bearer ".length()).trim();
            }
        }
        return null;
    }
}
