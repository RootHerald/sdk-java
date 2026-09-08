# Root Herald — Java SDK

[Root Herald](https://rootherald.io) device attestation from a Java backend. Plain Java + Spring Boot. Requires Java 17+.

**Background-Check (server → server)** via `RootHeraldClient`: your dumb client collects an opaque evidence blob and hands it to *your* server, which appraises it with Root Herald using your `rh_sk_` secret key. The client never holds a key or talks to Root Herald.

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
var rh = RootHeraldClient.builder()
    .secretKey(System.getenv("ROOTHERALD_SECRET_KEY"))
    .build();

// 1) Mint a challenge; relay challenge.challenge() to the client verbatim.
//    The challenge carries the ask: what the device must prove is fixed here.
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_POSTURE)   // the default when omitted
    .policy("rootherald:builtin:strict-hardware"));                     // optional, bound to the challenge

// 2) The client quotes over the challenge and returns an opaque evidence blob
//    (JSON); submit it for appraisal.
AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.challengeId()));

if (!result.isAllowed()) {
    response.setStatus(403);
    return;
}
```

A policy named at verify time may only tighten the challenge's; a looser one is
refused with `PolicyDowngradeException` (422 `policy_downgrade`).

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException` (401), `UnknownPolicyException` / `PolicyDowngradeException` / `AdmissionRefusedException` (422, told apart by `errorCode()`), `ChallengeException` (409), `InvalidEvidenceException` (400), `QuotaExceededException` (429).

### Certified device key

Ask for `key` and a passing verdict also certifies a fresh TPM-resident P-256
signing key. Store the `CertifiedKey` against the user; later signatures from
the device verify locally, with no Root Herald call.

```java
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_KEY)
    .keyPurpose(ChallengeOptions.KEY_PURPOSE_SIGN));

AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.challengeId()));
CertifiedKey key = result.key().orElseThrow();   // present only on a pass with a key ask
store(userId, key.keyId(), key.jwk());

// Later: the device signed `message` with that key (raw r||s or DER).
boolean ok = KeySignatures.verifyKeySignature(key.jwk(), message, signature);
```

### Enroll relay (one-time device-key bootstrap)

The keyless client also produces opaque enroll blobs; your backend relays the two legs with the same `rh_sk_` secret. Every enrollment returns a MakeCredential challenge, a device already known included — re-enrollment is how a device rotates its attestation key. `deviceId()` is your tenant's alias for the device, not a global identifier.

```java
// Leg 1 — relay the client's EnrollBegin() blob. Pass a live challenge id to
// run admission against that challenge's policy; a device that could never
// satisfy it is refused with AdmissionRefusedException (422 admission_refused).
RelayEnrollResult enroll = rh.relayEnroll(EnrollRequestBlob.builder()
    .ekPublicKey(blob.ekPublicKey())
    .akPublicArea(blob.akPublicArea())
    .platform("windows")
    .ekCertPem(blob.ekCertPem())                  // optional
    .build(), challenge.challengeId());           // challengeId optional

// Hand enroll.challenge() to the client's EnrollComplete(), then relay leg 2.
EnrollActivationChallenge challenge = enroll.challenge();
// ... client returns the decrypted secret ...
RelayActivateResponse activated = rh.relayActivate(
    new EnrollActivationResponse(enroll.deviceId(), decryptedSecret));
bindDeviceToUser(activated.deviceId());
```

The client never holds the `rh_sk_` key and never talks to RootHerald; this backend helper is the only thing that does. The verdict is computed by RootHerald and returned to your backend; it never travels through the client.

## Spring Boot

`RootHeraldClient` is a plain object — register it as a `@Bean` and inject it into your controllers. See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example (`POST /challenge`, `POST /attest`, `POST /verify-signature`).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
