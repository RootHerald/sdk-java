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

if (!result.isPass()) {
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

`result.verdict()` is the server's own token, `Verdict.PASS` / `Verdict.WARN` / `Verdict.FAIL` (`"pass"` / `"warn"` / `"fail"`, the same vocabulary in every Root Herald SDK), with `isPass()` as a convenience. A response carrying any other token is refused with `RootHeraldApiException`, never a guessed verdict.

### Errors

An un-enrolled / failing device is a verdict (`"fail"`/`"warn"`), **not** an exception. Only protocol, auth and quota problems throw, each exposing `statusCode()` and the server's `errorCode()`:

| Status | Server `error` code                                 | Exception                    |
| ------ | --------------------------------------------------- | ---------------------------- |
| 401    | `activation_refused`                                | `ActivationRefusedException` |
| 401    | anything else                                       | `InvalidSecretKeyException`  |
| 400    |                                                     | `InvalidEvidenceException`   |
| 409    |                                                     | `ChallengeException`         |
| 422    | `unknown_policy`, or none                           | `UnknownPolicyException`     |
| 422    | `admission_refused`                                 | `AdmissionRefusedException`  |
| 429    | `quota_exceeded`, or an `X-RootHerald-Quota` header | `QuotaExceededException`     |
| 429    | anything else                                       | `RateLimitedException`       |

`ActivationRefusedException` is `relayActivate` being refused for an unknown, spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted. `RateLimitedException.retryAfterSeconds()` is the server's `Retry-After` (else the body's `retryAfterSeconds`, else `null`); `QuotaExceededException` is the metered billing ceiling. `UnknownPolicyException` means a policy bound to the key no longer exists. Any other status, and a 422 or 402 carrying a code no subclass covers (`posture_not_bound`, `plan_lapsed`), is a plain `RootHeraldApiException` with `errorCode()` preserved. Input the SDK refuses locally, such as an empty nonce, is `IllegalArgumentException` and makes no request.

Every request times out after 30 s (`RootHeraldClient.DEFAULT_TIMEOUT`), whichever `HttpClient` is in use. The default is the same in every Root Herald server SDK. A `baseUrl` with a path prefix is kept: requests go to `<baseUrl>/api/v1/...`.

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

`relayEnroll(String)` relays the client's JSON verbatim and is the path for a backend that already holds it. `EnrollRequestBlob.builder()` types every body for a backend that would rather not pass JSON through: `platform` is required; a TPM body carries `ekPublicKey`, `akPublicArea` and optionally `ekCertPem`, `ekCertificateChain` and `tpmSelfReport(manufacturer, vendorString)`; a macOS body the enclave key as both; an App Attest body (`platform("ios")`) `iosKeyId`, `iosAttestationObject` and `nonce`. Every field that is set is sent and nothing else is. An App Attest body enrolls in one leg: the 201 is empty, `enroll.challenge()` is absent and there is no activate leg.

The client never holds the `rh_sk_` key and never talks to RootHerald; this backend helper is the only thing that does. The verdict is computed by RootHerald and returned to your backend; it never travels through the client.

## Spring Boot

`RootHeraldClient` is a plain object — register it as a `@Bean` and inject it into your controllers. See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example (`POST /challenge`, `POST /attest`, `POST /verify-signature`).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
