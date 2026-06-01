package io.rootherald.spring;

import io.rootherald.AttestationClaims;
import io.rootherald.RootHeraldException;
import io.rootherald.TokenExpiredException;
import io.rootherald.TokenVerifier;

import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.web.method.HandlerMethod;
import org.springframework.web.servlet.HandlerExecutionChain;
import org.springframework.web.servlet.HandlerMapping;

import java.lang.reflect.Method;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

class RootHeraldGuardFilterTest {

    static class GuardedHandler {
        @RootHeraldGuard(action = "signup")
        public void handle() {}

        public void unguarded() {}
    }

    private static HandlerMapping mappingFor(Method method) {
        return request -> {
            try {
                HandlerMethod hm = new HandlerMethod(new GuardedHandler(), method);
                return new HandlerExecutionChain(hm);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        };
    }

    private static final AttestationClaims OK = new AttestationClaims(
            "device-1", "iss", List.of("aud"), Instant.now().plusSeconds(60), null, null,
            "n", "p", null, java.util.Map.of());

    @Test
    void allowsValidToken() throws Exception {
        TokenVerifier verifier = t -> OK;
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("handle"))));
        var req = new MockHttpServletRequest("POST", "/signup");
        req.addHeader(RootHeraldGuardFilter.TOKEN_HEADER, "good.token.value");
        var resp = new MockHttpServletResponse();
        FilterChain chain = new MockFilterChain();
        filter.doFilter(req, resp, chain);
        assertEquals(200, resp.getStatus());
        assertSame(OK, req.getAttribute(RootHeraldGuardFilter.CLAIMS_ATTRIBUTE));
    }

    @Test
    void returns401WhenTokenMissing() throws Exception {
        TokenVerifier verifier = t -> OK;
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("handle"))));
        var req = new MockHttpServletRequest("POST", "/signup");
        var resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, new MockFilterChain());
        assertEquals(401, resp.getStatus());
    }

    @Test
    void returns401WhenExpired() throws Exception {
        TokenVerifier verifier = t -> { throw new TokenExpiredException("expired"); };
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("handle"))));
        var req = new MockHttpServletRequest("POST", "/signup");
        req.addHeader(RootHeraldGuardFilter.TOKEN_HEADER, "x");
        var resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, new MockFilterChain());
        assertEquals(401, resp.getStatus());
    }

    @Test
    void returns503WhenJwksUnreachable() throws Exception {
        TokenVerifier verifier = t -> { throw new RootHeraldException("Failed to fetch JWKS: down"); };
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("handle"))));
        var req = new MockHttpServletRequest("POST", "/signup");
        req.addHeader("Authorization", "Bearer abc");
        var resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, new MockFilterChain());
        assertEquals(503, resp.getStatus());
    }

    @Test
    void passesThroughUnguardedRoutes() throws Exception {
        TokenVerifier verifier = t -> { throw new AssertionError("should not be called"); };
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("unguarded"))));
        var req = new MockHttpServletRequest("GET", "/health");
        var resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, new MockFilterChain());
        assertEquals(200, resp.getStatus());
    }

    @Test
    void rootHeraldAuthHeaderAccepted() throws Exception {
        var seen = new String[]{null};
        TokenVerifier verifier = t -> { seen[0] = t; return OK; };
        var filter = new RootHeraldGuardFilter(verifier, null, false,
                List.of(mappingFor(GuardedHandler.class.getDeclaredMethod("handle"))));
        var req = new MockHttpServletRequest("POST", "/signup");
        req.addHeader("Authorization", "RootHerald my-token");
        var resp = new MockHttpServletResponse();
        filter.doFilter(req, resp, new MockFilterChain());
        assertEquals(200, resp.getStatus());
        assertEquals("my-token", seen[0]);
    }
}
