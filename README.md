# Root Herald — Java SDK

Verify [Root Herald](https://rootherald.io) device-attestation JWTs from a Java backend. Plain Java + Spring Boot. Requires Java 17+.

## Install

```xml
<dependency>
  <groupId>io.rootherald</groupId>
  <artifactId>rootherald-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

For Spring Boot, depend on `io.rootherald:rootherald-spring` instead.

## Verify a token

```java
var client = RootHeraldClient.builder()
    .baseUri("https://rootherald.io")
    .issuer("https://rootherald.io/myorg")
    .audience("your-client-id")
    .build();

VerifyResult result = client.verifyOffline(token);
if (!result.isAllowed()) {
    response.setStatus(403);
    return;
}
String deviceId = result.claims().subject();
```

`verifyOffline` checks the JWT locally against the cached JWKS. Use `verifyOnline(token, action)` when you want server-side policy (revocation, risk score).

## Spring Boot

Set `rootherald.issuer` (and optionally `rootherald.audience`) in `application.yml`, then annotate guarded handlers:

```java
@PostMapping("/signup")
@RootHeraldGuard(action = "signup")
public ResponseEntity<?> signup(HttpServletRequest req) {
    var claims = (AttestationClaims) req.getAttribute(RootHeraldGuardFilter.CLAIMS_ATTRIBUTE);
    return ResponseEntity.ok(Map.of("device", claims.subject()));
}
```

The filter reads the token from `X-RootHerald-Token` (or `Authorization: RootHerald <token>`) and returns 401/403/503 on failure before the handler runs.

See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example.

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
