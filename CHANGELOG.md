# Changelog

## 0.2.0

Wire 8.0. Every installation of a client has its own attestation key, created
inside the TPM at enrollment and handed back as an opaque AK blob the client
keeps and passes to every attest and mint. Keys are minted in their own
ceremony. A backend on this version cannot drive a 7.0 client, and the
reverse; the server refuses a 7.0-shaped enroll body with
`400 wire_version_unsupported`.

### Breaking

- `EnrollRequestBlob` carries the nested `attestationKey` (`AttestationKey`
  record: `publicArea`, `parentPublicArea`, `qualifiedName`) on a Windows or
  Linux body and refuses `akPublicArea` there; a macOS body stays flat with
  `ekPublicKey` and `akPublicArea`, and an iOS body is unchanged. The record's
  canonical constructor changed and the five- and nine-argument constructors
  are gone; use the builder. `relayEnroll(String)` relays the client's JSON
  verbatim and `relayEnroll(JsonNode)` is new for a backend that already
  parsed it; both refuse a flat TPM body before any request
  (`IllegalArgumentException`).
- Keys are minted by `issueKeyChallenge(KeyChallengeOptions)` →
  `certifyKey(nonce, certificationJson)` → `CertifiedKey(deviceId, keyId,
  purpose, alg, format, jwk, hardwareBound, certifiedAt)`. The `key` ask,
  `ChallengeOptions.ASK_KEY`, `KEY_PURPOSE_SIGN`, `keyPurpose` and
  `AttestResult.key()` are removed; a challenge that still asks for `key` is
  `InvalidAskException` (400 `invalid_ask`), not `InvalidEvidenceException`.
  `CertifiedKey.authPolicy()` is gone.
- `ChallengeOptions` takes `expectedKey` and `expectedDevices` and no longer
  takes `deviceHint`; `issueChallenge(String)` is removed. Pass the same
  values to `AttestOptions`: a verdict that does not echo them under
  `expected` is refused with `ExpectedNotEnforcedException`.
  `AttestResult.expected()` returns the echoed `ExpectedBinding`.
- `Jwk` is `(kty, crv, x, y, n, e)`: EC P-256 or RSA. `Jwk.ec(x, y)` and
  `Jwk.rsa(n, e)` build each. `KeySignatures.verifyKeySignature` checks
  ES256 for an EC key and RS256 (PKCS#1 v1.5 over SHA-256, modulus of at
  least 2048 bits, signature exactly the modulus length) for an RSA key.
  P-384 is no longer accepted: no device certifies one.
- A 429 `budget_exhausted` is `QuotaExceededException` with `budget()`
  (`RefusingBudget(id, name)`); the `quota_exceeded` code is gone. A 409
  `key_rotation_conflict` is a plain `RootHeraldApiException`, not
  `ChallengeException`. A 400 `invalid_purpose` is `InvalidAskException`
  (`errorCode()` preserved); a 400 `invalid_certification` is
  `InvalidEvidenceException`; a 422 `purpose_unsupported` or
  `certification_rejected` is a plain `RootHeraldApiException`.

### Added

- `AttestResult.deviceId()`: the device's alias (`verdict.device.ueid`),
  empty when the disclosure class withholds it.

### Migration

1. Re-enroll every installation: the client's `EnrollBegin` now returns an
   AK blob, which the client keeps and passes to `Attest` and `MintKey`.
2. Replace `ask(ASK_IDENTITY, ASK_KEY).keyPurpose(KEY_PURPOSE_SIGN)` plus
   `result.key()` with `issueKeyChallenge(KeyChallengeOptions.of(PURPOSE_SIGN)
   .expectedDevices(alias))` and `certifyKey(nonce, certification)`.
3. Drop `deviceHint`; bind a challenge to a device with `expectedDevices`,
   and pass the same value to `AttestOptions.expectedDevices`.
4. Read the alias with `result.deviceId()`.
5. Build enroll bodies with `EnrollRequestBlob.builder()` and
   `attestationKey(publicArea, parentPublicArea, qualifiedName)`.

## 0.1.0

### Breaking

- `AttestResult.verdict()` is the server's own token, `Verdict.PASS` /
  `Verdict.WARN` / `Verdict.FAIL` (`"pass"` / `"warn"` / `"fail"`), the same
  vocabulary as every other RootHerald SDK; `"allow"` / `"deny"` / `"review"`
  are gone and `isAllowed()` is `isPass()`. A response carrying any other
  token throws `RootHeraldApiException` instead of reading as `"review"`.
- `EnrollRequestBlob` requires `platform` and carries `tpmSelfReport`,
  `iosKeyId`, `iosAttestationObject` and `nonce`; `relayEnroll(EnrollRequestBlob)`
  sends every field that is set and nothing else, so a swtpm's self-report
  and an App Attest body relay through the typed helper. The five-argument
  constructor remains for TPM and macOS bodies.
- A 401 carrying `activation_refused` is `ActivationRefusedException`, not
  `InvalidSecretKeyException`. A 429 without `quota_exceeded` or an
  `X-RootHerald-Quota` header is `RateLimitedException`, with
  `retryAfterSeconds()`, not `QuotaExceededException`. A 422 whose code is
  neither `unknown_policy` nor `admission_refused` (`posture_not_bound`) is
  a plain `RootHeraldApiException` with the code preserved.
- Requests resolve `api/v1/...` against the base URL with its path kept, so
  `baseUrl("https://host/prefix")` reaches `https://host/prefix/api/v1/...`
  instead of `https://host/api/v1/...`.
- The per-request timeout is 30 s (`RootHeraldClient.DEFAULT_TIMEOUT`), was
  10 s.
- `CertifiedKey.authPolicy()` is documented as hex, which is what the server
  sends.

- Wire 7.0: nothing a client sends locates a row. `Challenge` is
  `(nonce, challenge, expiresAt)`; there is no `challengeId`. The `nonce` is
  the backend's handle for the challenge and `AttestOptions.of(nonce)` carries
  it to `verify`, which sends `nonce` instead of `challengeId`. `issueChallenge`
  requires all three fields in the response.
- `relayEnroll(EnrollRequestBlob)` takes no challenge id and sends no query
  string. `relayEnroll(String)` relays the client's blob as the JSON it emitted,
  which is how an App Attest body (`platform: "ios"`) is relayed; its 201 is
  empty and `RelayEnrollResult.challenge()` is then absent. `RelayEnrollResult`
  has no `deviceId` and no `challengeId`; `challenge()` is an `Optional`.
- `EnrollActivationChallenge` is `(enrollmentId, credentialBlob,
  encryptedSecret, challengeNonce)` and rejects a body without `enrollmentId`
  or without either the TPM pair or `challengeNonce`; `relayEnroll` maps that
  to `RootHeraldApiException`. `deviceId` is gone from the 201.
- `EnrollActivationResponse` is `(enrollmentId, decryptedSecret, signature)`
  with exactly one of the two proofs; `ofDecryptedSecret` and `ofSignature`
  build each. `deviceId` and `akPublicKey` are gone from the activate body.
  `RelayActivateResponse` is unchanged; its `deviceId` is for the backend and
  must not be relayed to the device.
- Policies bind to API keys. The `policy` option is gone from
  `ChallengeOptions` and `AttestOptions`, so `issueChallenge` and `verify`
  never send the field. The server refuses it with `400 policy_bound_to_key`.
  Bind a policy to the key from the dashboard or
  `PUT /api/v1/admin/api-keys/{id}/policies`.
- `PolicyDowngradeException` is removed with the field that produced it.
  `UnknownPolicyException` (422 `unknown_policy`) now means a policy bound to
  the key no longer exists.

### Added

- The challenge carries the ask. `ChallengeOptions` (ask list of
  `identity` / `posture` / `key`, `keyPurpose`, `deviceHint`) and
  `RootHeraldClient.issueChallenge(ChallengeOptions)`. `Challenge` gains
  `challenge()`, the string to relay to the client verbatim. The existing
  `issueChallenge()` / `issueChallenge(String)` overloads keep the server
  default of identity + posture.
- `CertifiedKey` and `Jwk`; `AttestResult.key()` returns the key the appraisal
  certified, present only on a passing verdict for a challenge that asked for
  `key`.
- `KeySignatures.verifyKeySignature(Jwk, byte[], byte[])`: local ECDSA
  verification of device signatures over SHA-256 (P-256) or SHA-384 (P-384),
  accepting raw `r||s` and DER. Returns `false` for any malformed signature.
- `RootHeraldApiException.errorCode()` exposes the server's `error` code.
  New 422 type keyed on it: `AdmissionRefusedException`
  (`admission_refused`). Other 422s remain `UnknownPolicyException`.

### Fixed

- `samples/spring-boot-demo` imported a `BackgroundCheckClient` that does not
  exist; it now uses `RootHeraldClient` and shows the key flow, and is built
  by `mvn verify` from the root.
