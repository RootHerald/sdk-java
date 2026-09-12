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

// 1) Mint a challenge; relay challenge.challenge() to the client verbatim and
//    keep challenge.nonce(), your handle for it. The challenge carries the ask:
//    what the device must prove is fixed here.
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_POSTURE)); // the default when omitted

// 2) The client quotes over the challenge and returns an opaque evidence blob
//    (JSON); submit it for appraisal under the nonce it answered.
AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.nonce()));

if (!result.isAllowed()) {
    response.setStatus(403);
    return;
}
```

Policies bind to your API key, not to calls. The key carries an identity
policy and, on Pro, a posture policy; a posture ask runs under the posture
policy and everything else under the identity policy. The resolved policy is
pinned on the challenge when it is minted. Change what a key enforces from the
dashboard or `PUT /api/v1/admin/api-keys/{id}/policies`; a `policy` field in a
hand-built request body is refused with `400 policy_bound_to_key`.

An un-enrolled / failing device is a verdict (`"deny"`/`"review"`), **not** an exception. Only protocol/auth/quota problems throw: `InvalidSecretKeyException` (401), `UnknownPolicyException` / `AdmissionRefusedException` (422, told apart by `errorCode()`; `unknown_policy` means a policy bound to the key no longer exists), `ChallengeException` (409), `InvalidEvidenceException` (400), `QuotaExceededException` (429).

### Certified device key

Ask for `key` and a passing verdict also certifies a fresh TPM-resident P-256
signing key. Store the `CertifiedKey` against the user; later signatures from
the device verify locally, with no Root Herald call.

```java
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY, ChallengeOptions.ASK_KEY)
    .keyPurpose(ChallengeOptions.KEY_PURPOSE_SIGN));

AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.nonce()));
CertifiedKey key = result.key().orElseThrow();   // present only on a pass with a key ask
store(userId, key.keyId(), key.jwk());

// Later: the device signed `message` with that key (raw r||s or DER).
boolean ok = KeySignatures.verifyKeySignature(key.jwk(), message, signature);
```

### Enroll relay (one-time device-key bootstrap)

The keyless client also produces opaque enroll blobs; your backend relays the two legs with the same `rh_sk_` secret. Every enrollment returns a challenge, a device already known included — re-enrollment is how a device rotates its attestation key. Nothing in either leg names the device: the server finds the open enrollment by the `enrollmentId` it minted, and the `deviceId` your backend learns at activation is your tenant's alias for the device, not a global identifier. It is for your backend only; never relay it to the device.

```java
// Leg 1 — relay the client's EnrollBegin() blob, as the JSON it emitted.
// Admission runs under the key's identity policy; a device that could never
// satisfy it is refused with AdmissionRefusedException (422 admission_refused).
RelayEnrollResult enroll = rh.relayEnroll(enrollBeginJson);

// Hand enroll.challenge() to the client's EnrollComplete() verbatim, then relay
// leg 2. A TPM answers with the secret it released; a Secure Enclave with a
// signature over challengeNonce.
EnrollActivationChallenge challenge = enroll.challenge().orElseThrow();
// ... client returns { enrollmentId, decryptedSecret } ...
RelayActivateResponse activated = rh.relayActivate(
    EnrollActivationResponse.ofDecryptedSecret(challenge.enrollmentId(), decryptedSecret));
bindDeviceToUser(activated.deviceId());
```

`EnrollRequestBlob.builder()` types the TPM and Secure Enclave bodies for a backend that would rather not pass JSON through. An App Attest body (`platform: "ios"`) has no EK or AK and enrolls in one leg: relay it as JSON, the 201 is empty, `enroll.challenge()` is absent and there is no activate leg.

The client never holds the `rh_sk_` key and never talks to RootHerald; this backend helper is the only thing that does. The verdict is computed by RootHerald and returned to your backend; it never travels through the client.

## Spring Boot

`RootHeraldClient` is a plain object — register it as a `@Bean` and inject it into your controllers. See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example (`POST /challenge`, `POST /attest`, `POST /verify-signature`).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
