# Root Herald — Java SDK

[Root Herald](https://rootherald.io) device attestation from a Java backend. Plain Java + Spring Boot. Requires Java 17+.

**Background-Check (server → server)** via `BackgroundCheckClient`: your dumb client collects an opaque evidence blob and hands it to *your* server, which appraises it with Root Herald using your `rh_sk_` secret key. The client never holds a key or talks to Root Herald.

## Install

```xml
<dependency>
  <groupId>io.rootherald</groupId>
  <artifactId>rootherald-client</artifactId>
  <version>0.1.0</version>
</dependency>
```

## Background-Check (server → server)

```java
// Construct with your SECRET key (rh_sk_…). Any key without the rh_sk_ prefix
// is rejected.
var rh = BackgroundCheckClient.builder()
    .secretKey(System.getenv("ROOTHERALD_SECRET_KEY"))
    .build();

// 1) Mint a relay-friendly nonce; send challenge.nonce() down to the client.
Challenge challenge = rh.issueChallenge();

// 2) The client quotes over the nonce and returns an opaque evidence blob
//    (JSON); submit it for appraisal.
AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.challengeId())
    .policy("rootherald:builtin:strict-hardware")); // optional

if (!result.isAllowed()) {
    response.setStatus(403);
    return;
}
```

`issueChallenge` / `verify` are the canonical ABI backend-relay names; the older `createChallenge` / `attest` remain as deprecated aliases.

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException` (401), `UnknownPolicyException` (422), `ChallengeException` (409), `InvalidEvidenceException` (400), `QuotaExceededException` (429).

### Enroll relay (one-time device-key bootstrap)

The keyless client also produces opaque enroll blobs; your backend relays the two legs with the same `rh_sk_` secret. `relayEnroll` resolves the asymmetric `201` (fresh) / `409` (already enrolled) outcomes into one result so you branch on `alreadyEnrolled()` instead of HTTP status.

```java
// Leg 1 — relay the client's EnrollBegin() blob.
RelayEnrollResult enroll = rh.relayEnroll(EnrollRequestBlob.builder()
    .ekPublicKey(blob.ekPublicKey())
    .akPublicArea(blob.akPublicArea())
    .platform("windows")
    .ekCertPem(blob.ekCertPem())                  // optional
    .build());

if (enroll.alreadyEnrolled()) {
    bindDeviceToUser(enroll.deviceId());          // device already bound; done
} else {
    // Hand enroll.challenge() to the client's EnrollComplete(), then relay leg 2.
    EnrollActivationChallenge challenge = enroll.challenge().get();
    // ... client returns the decrypted secret ...
    RelayActivateResponse activated = rh.relayActivate(
        new EnrollActivationResponse(enroll.deviceId(), decryptedSecret));
    bindDeviceToUser(activated.deviceId());
}
```

The client never holds the `rh_sk_` key and never talks to RootHerald; this backend helper is the only thing that does. The verdict is computed by RootHerald and returned to your backend; it never travels through the client.

## Spring Boot

`BackgroundCheckClient` is a plain object — register it as a `@Bean` and inject it into your controllers. See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example (`POST /attest`).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
