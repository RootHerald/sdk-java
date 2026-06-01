package io.rootherald.sample;

import io.rootherald.AttestationClaims;
import io.rootherald.spring.RootHeraldGuard;
import io.rootherald.spring.RootHeraldGuardFilter;

import jakarta.servlet.http.HttpServletRequest;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;

/**
 * Runnable Spring Boot sample. Configure with:
 * <pre>
 * rootherald.issuer=https://rootherald.io/myorg
 * rootherald.audience=demo-rp
 * </pre>
 * Then POST to {@code /signup} with the {@code X-RootHerald-Token} header set.
 */
@SpringBootApplication
public class SampleApp {
    public static void main(String[] args) {
        SpringApplication.run(SampleApp.class, args);
    }

    @RestController
    public static class SignupController {
        @PostMapping("/signup")
        @RootHeraldGuard(action = "signup")
        public ResponseEntity<Map<String, Object>> signup(HttpServletRequest req) {
            AttestationClaims claims = (AttestationClaims) req.getAttribute(RootHeraldGuardFilter.CLAIMS_ATTRIBUTE);
            return ResponseEntity.ok(Map.of(
                    "status", "ok",
                    "device", claims != null ? claims.subject() : "anonymous"
            ));
        }
    }
}
