# Changelog

## Unreleased

### Added

- The challenge carries the ask. `ChallengeOptions` (ask list of
  `identity` / `posture` / `key`, `policy`, `keyPurpose`, `deviceHint`) and
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
- `RootHeraldClient.relayEnroll(EnrollRequestBlob, String challengeId)` sends
  the `challengeId` query parameter so admission runs against that challenge's
  policy; `RelayEnrollResult.challengeId()` echoes it when the server does.
- `RootHeraldApiException.errorCode()` exposes the server's `error` code.
  New 422 types keyed on it: `PolicyDowngradeException` (`policy_downgrade`)
  and `AdmissionRefusedException` (`admission_refused`). Other 422s remain
  `UnknownPolicyException`.

### Fixed

- `samples/spring-boot-demo` imported a `BackgroundCheckClient` that does not
  exist; it now uses `RootHeraldClient` and shows the key flow, and is built
  by `mvn verify` from the root.
