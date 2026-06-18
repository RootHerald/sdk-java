# Root Herald — Java SDK

[Root Herald](https://rootherald.io) device attestation from a Java backend. Plain Java + Spring Boot. Requires Java 17+. Two paths:

- **Background-Check (server → server)** — `BackgroundCheckClient`: your dumb client collects an opaque evidence blob and hands it to *your* server, which appraises it with Root Herald using your `rh_sk_` secret key. The client never holds a key or talks to Root Herald.
- **Badge tier (offline verify)** — `RootHeraldClient.verifyOffline` + the Spring guard: verify a Root Herald-issued EAT (JWT) against the cached JWKS.

## Install

```xml
<dependency>
  <groupId>io.rootherald</groupId>
  <artifactId>rootherald-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

For Spring Boot, depend on `io.rootherald:rootherald-spring` instead.

## Background-Check (server → server)

```java
// Construct with your SECRET key (rh_sk_…). A publishable key (rh_pk_…) is
// rejected — it must never be used server-side.
var rh = BackgroundCheckClient.builder()
    .secretKey(System.getenv("ROOTHERALD_SECRET_KEY"))
    .build();

// 1) Mint a relay-friendly nonce; send challenge.nonce() down to the client.
Challenge challenge = rh.createChallenge();

// 2) The client quotes over the nonce and returns an opaque evidence blob
//    (JSON); submit it for appraisal.
AttestResult result = rh.attest(evidence, AttestOptions.of(challenge.challengeId())
    .policy("rootherald:builtin:strict-hardware") // optional
    .returnToken(true));                          // optional signed EAT

if (!result.isAllowed()) {
    response.setStatus(403);
    return;
}
```

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an exception. Only protocol/auth/quota problems throw — `InvalidSecretKeyException` (401), `UnknownPolicyException` (422), `ChallengeException` (409), `InvalidEvidenceException` (400), `QuotaExceededException` (429).

## Verify a token (badge tier)

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

`verifyOffline` checks the JWT locally against the cached JWKS. (The legacy `verifyOnline(token, action)` is deprecated — it targets a self-hosted service absent on the stock Root Herald deployment; use `BackgroundCheckClient` instead.)

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
