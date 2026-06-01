package io.rootherald.spring;

import java.lang.annotation.ElementType;
import java.lang.annotation.Retention;
import java.lang.annotation.RetentionPolicy;
import java.lang.annotation.Target;

/**
 * Method-level marker for Spring MVC handlers that require a verified RootHerald
 * attestation. Intercepted by {@link RootHeraldGuardFilter}, which inspects the
 * inbound request for an {@code X-RootHerald-Token} header (or
 * {@code Authorization: RootHerald <token>}) and short-circuits with the
 * appropriate HTTP status when verification fails.
 *
 * <ul>
 *   <li>200 — verified; handler runs and may read {@code request.getAttribute("rootherald.claims")}</li>
 *   <li>401 — token missing or malformed</li>
 *   <li>403 — token verified but verdict is {@code deny}</li>
 *   <li>503 — JWKS / verifier transiently unavailable</li>
 * </ul>
 */
@Target(ElementType.METHOD)
@Retention(RetentionPolicy.RUNTIME)
public @interface RootHeraldGuard {
    /** Optional action label (forwarded to the verifier when online mode is used). */
    String action() default "verify";

    /** Optional comma-separated list of accepted verdicts (default: {@code allow}). */
    String[] verdicts() default { "allow" };
}
