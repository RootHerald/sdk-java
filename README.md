# Root Herald — Java SDK

[Root Herald](https://rootherald.io) device attestation from a Java backend. Plain Java + Spring Boot. Requires Java 17+.

Wire 8.0 from `0.2.0`. A 7.0 client cannot enroll against an 8.0 server; see the [CHANGELOG](./CHANGELOG.md) for the migration.

**Background-Check (server → server)** via `RootHeraldClient`: your client does local TPM work and hands *your* server opaque blobs. Your server relays them to Root Herald with your `rh_sk_` secret key. The verdict is computed by Root Herald and returned to your backend; it never travels through the client, which holds no Root Herald key.

**Three ceremonies, two calls each.**

- `relayEnroll(blob)` / `relayActivate(activation)`: enroll an installation (`POST /api/v1/attest/enroll`, `/activate`).
- `issueKeyChallenge(options)` / `certifyKey(nonce, certification)`: mint a device-bound key (`POST /api/v1/keys/challenge`, `/certify`).
- `issueChallenge(options)` / `verify(evidence, options)`: attest (`POST /api/v1/attest/challenge`, `/verify`).
- `KeySignatures.verifyKeySignature(jwk, message, signature)`: check a signature from a certified key locally, with `java.security` only.

## Install

```xml
<dependency>
  <groupId>io.rootherald</groupId>
  <artifactId>rootherald-client</artifactId>
  <version>0.2.0</version>
</dependency>
```

`secretKey` is required and must start with `rh_sk_`. `baseUrl` defaults to the production API and must be `https` (loopback excepted); a path prefix is kept. Every request times out after 30 s (`RootHeraldClient.DEFAULT_TIMEOUT`), the same in every Root Herald server SDK.

## Enroll an installation

Each installation of your client enrolls once. The client's `EnrollBegin` creates an attestation key (AK) inside the TPM and returns an opaque AK blob alongside the enroll body; the client keeps the blob and passes it to every later attest and mint. Windows needs one elevation per enrollment.

```java
var rh = RootHeraldClient.builder()
    .secretKey(System.getenv("ROOTHERALD_SECRET_KEY"))
    .build();

// Leg 1: relay the client's EnrollBegin() body verbatim. Admission runs under
// the key's identity policy, so a device that could never satisfy it is
// refused with AdmissionRefusedException (422 admission_refused).
RelayEnrollResult enroll = rh.relayEnroll(enrollBeginJson);

// Hand enroll.challenge() (the 201 body) to the client's EnrollComplete(),
// which returns { enrollmentId, decryptedSecret }; relay it to finish binding.
EnrollActivationChallenge challenge = enroll.challenge().orElseThrow();
RelayActivateResponse activated = rh.relayActivate(
    EnrollActivationResponse.ofDecryptedSecret(challenge.enrollmentId(), decryptedSecret));
bindDeviceToUser(activated.deviceId());
// deviceId is this tenant's alias for the device. Keep it here; never send it
// to the client.
```

The alias is the device's only identity: a new AK, a new key, a re-enrollment or a TPM clear never changes it. Bind accounts to it. An iOS enrollment has nothing to activate: its 201 is empty, `enroll.challenge()` is absent and there is no second leg.

`relayEnroll(String)` and `relayEnroll(JsonNode)` relay the client's JSON as it is. `EnrollRequestBlob.builder()` types every body for a backend that builds it itself: a Windows or Linux body carries `ekPublicKey` and `attestationKey(publicArea, parentPublicArea, qualifiedName)`, optionally `ekCertPem`, `ekCertificateChain` and `tpmSelfReport(manufacturer, vendorString)`; a macOS body `ekPublicKey` and `akPublicArea`, both the enclave key; an iOS body `iosKeyId`, `iosAttestationObject` and `nonce`. A flat TPM body (`akPublicArea` on `windows` or `linux`) is the 7.0 shape and every path refuses it with `IllegalArgumentException` before any request.

When to enroll: the client has no AK blob; the client's attest or mint reports the blob unloadable (TPM cleared, parent changed), in which case discard it, enroll, retry once; or `verify` answers `enrollmentRequired() == true`.

## Attest

```java
// 1. Mint a challenge. Relay challenge.challenge() to the client; keep the nonce.
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY));

// 2. The client's Attest answers with an opaque evidence blob (JSON). Appraise it.
AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.nonce()));

if (!result.isPass()) {
    response.setStatus(403);
    return;
}
String alias = result.deviceId().orElseThrow(); // bind the session to it
```

Omitting `ask` asks for identity and posture. A posture ask runs under the key's posture policy and checks the boot configuration; use it for step-up, with `result.assuranceClaimsMet()` listing the policy claims the device satisfied.

`result.verdict()` is the server's own token, `Verdict.PASS` / `Verdict.WARN` / `Verdict.FAIL`, with `isPass()` as a convenience; a response carrying any other token is refused with `RootHeraldApiException`. `result.verdictNode()` is the full verdict as the server sent it, every device field under `device`.

**Name the device that must answer.** `expectedDevices` takes aliases you enrolled, `expectedKey` a `keyId` you certified; any other device answers a failing verdict with reason `expected_device_mismatch`, and an unknown value is `422 expected_unknown`. Pass the same values to `AttestOptions`: the verdict echoes what the server enforced under `expected`, and `verify` refuses a verdict that does not echo it with `ExpectedNotEnforcedException`.

```java
Challenge challenge = rh.issueChallenge(ChallengeOptions.defaults()
    .ask(ChallengeOptions.ASK_IDENTITY)
    .expectedDevices(session.deviceId()));
AttestResult result = rh.verify(evidence, AttestOptions.of(challenge.nonce())
    .expectedDevices(session.deviceId()));
```

Policies bind to your API key, not to calls. Change what a key enforces from the dashboard; a `policy` field in a hand-built request body is refused with `400 policy_bound_to_key`.

## Device-bound signing keys

A key is created inside the chip and certified by the installation's AK; you get its public half, the device keeps the blob. A signature on a request then proves the request came from that device, and you check it with no Root Herald call.

```java
// 1. Mint a key challenge for the device that just passed an attest
//    challenge. Relay keyChallenge.keyChallenge() to the client; keep the nonce.
KeyChallenge keyChallenge = rh.issueKeyChallenge(
    KeyChallengeOptions.of(KeyChallengeOptions.PURPOSE_SIGN)
        .expectedDevices(result.deviceId().orElseThrow()));

// 2. The client's MintKey answers with a certification (JSON) and keeps its key blob.
CertifiedKey key = rh.certifyKey(keyChallenge.nonce(), certificationJson);
saveDeviceKey(key.deviceId(), key.keyId(), key.jwk());

// Later, without any Root Herald call: the client signed `message` with its key.
Jwk jwk = loadDeviceKey(session.deviceId());
if (!KeySignatures.verifyKeySignature(jwk, message, signature)) {
    response.setStatus(401);
    return;
}
```

`certifyKey` returns `CertifiedKey(deviceId, keyId, purpose, alg, format, jwk, hardwareBound, certifiedAt)`: `alg` is `ES256` or `RS256` for a sign key, `ECDH-ES` or `RSA-OAEP-256` for a decrypt key; `format` (`jwe` or `apple-ecies`) is set for decrypt keys only; `jwk` is `Jwk.ec(x, y)` (P-256) or `Jwk.rsa(n, e)` (RSA-2048), chosen by the device; `hardwareBound` is `false` on macOS, where only possession is proved. A malformed key in the response is refused with `RootHeraldApiException` rather than returned half-parsed.

A signature proves which chip signed, not how the machine booted; run an attest challenge for that.

Minting again for the same purpose rotates the key under the same `keyId`; a re-enrolled installation gets new key IDs. The key ID identifies an installation's credential, never a device: bind accounts to the alias.

`verifyKeySignature(jwk, message, signature)` hashes `message` itself. ES256: a 64-byte signature is read as raw `r||s`, any other length as DER. RS256: PKCS#1 v1.5 over SHA-256, a modulus of at least 2048 bits, a signature exactly the modulus length (256 bytes). It returns `false` for any malformed or non-matching signature and throws `IllegalArgumentException` only for a JWK that is not a usable key.

## Errors

An un-enrolled or failing device is a verdict (`fail` / `warn`), **not** an exception. Only protocol, auth and budget problems throw, each exposing `statusCode()` and the server's `errorCode()`:

| Status | Server `error` code                                   | Exception                    |
| ------ | ----------------------------------------------------- | ---------------------------- |
| 401    | `activation_refused`                                  | `ActivationRefusedException` |
| 401    | anything else                                         | `InvalidSecretKeyException`  |
| 400    | `invalid_ask`                                         | `InvalidAskException`        |
| 400    | anything else, including `wire_version_unsupported`, `invalid_enroll_shape` | `InvalidEvidenceException` |
| 409    | `key_rotation_conflict`                               | `RootHeraldApiException`     |
| 409    | anything else                                         | `ChallengeException`         |
| 422    | `unknown_policy`, or none                             | `UnknownPolicyException`     |
| 422    | `admission_refused`                                   | `AdmissionRefusedException`  |
| 422    | `expected_unknown`, `key_disclosure_too_low`          | `RootHeraldApiException`     |
| 429    | `budget_exhausted`, or an `X-RootHerald-Quota` header | `QuotaExceededException` (`budget()`) |
| 429    | anything else                                         | `RateLimitedException`       |

`InvalidAskException` is a programming error in your backend, not a device failure. `ActivationRefusedException` is `relayActivate` being refused for an unknown, spent or foreign `enrollmentId` or a wrong proof; the secret key was accepted. `RateLimitedException.retryAfterSeconds()` is the server's `Retry-After` (else the body's `retryAfterSeconds`, else `null`); `QuotaExceededException.budget()` names the budget that refused. `UnknownPolicyException` means a policy bound to the key no longer exists. Any other status, and a code no subclass covers (`posture_not_bound`, `plan_lapsed`), is a plain `RootHeraldApiException` with `errorCode()` preserved. A verdict that does not echo the `expectedKey` / `expectedDevices` you passed to `verify` is `ExpectedNotEnforcedException`. Input the SDK refuses locally, such as an empty nonce or a flat TPM enroll body, is `IllegalArgumentException` and makes no request.

## Spring Boot

`RootHeraldClient` is a plain object — register it as a `@Bean` and inject it into your controllers. See [`samples/spring-boot-demo`](./samples/spring-boot-demo) for a runnable example (`POST /challenge`, `/attest`, `/key-challenge`, `/certify`, `/verify-signature`).

## License

Apache-2.0. See [LICENSE](./LICENSE) and [NOTICE](./NOTICE).
