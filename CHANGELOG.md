# Changelog

### @marktripoli/ucan v0.4.0

- Add `AsyncDidSigner` and `Ed25519AsyncSigner` for asynchronous Ed25519
  callbacks, including non-extractable Web Crypto keys.
- Add `InvocationBuilder.tryBuildAsync()`,
  `DelegationBuilder.tryBuildAsync()`, and `revokeAsync()`.
- Async-built tokens use the same canonical bytes, CIDs, and verification
  path as synchronously built tokens.

### @marktripoli/varsig v0.3.0

- Add asynchronous Ed25519 signing through `Varsig.trySignAsync()`.

### @marktripoli/ucan v0.3.0

Security-hardened authorization verification. **Ed25519-only** cryptosuite for
this release (the spec profile also lists P-256 and secp256k1; unimplemented).

Scope/known deviations (all fail-closed):
- `did:key` with a DID fragment (`did:key:z…#z…`) is rejected at parse. Spec
  §Principal Alignment says alignment MUST ignore fragments; that only matters
  for multi-key DID methods (did:web/did:plc), which are out of scope here — a
  `did:key` already carries its single key in the method-specific id.
- Policy leaf evaluation throws (→ reject) on an unresolved selector or a
  non-string/non-number/non-collection operand, where the spec says return
  `false` without throwing. This is deliberately fail-closed: the spec-literal
  behavior is fail-open for `!=`/`not` predicates over attacker-controlled
  invocation args (a delegatee could bypass a restriction by omitting a field).
  Matches rs-ucan.
- Negative wire timestamps (`nbf`/`exp` in `-(2^53-1)..-1`) are rejected at
  decode, where the spec's numeric bound would accept them. Fail-closed and
  degenerate in practice: a negative `exp` is always-expired and a negative
  `nbf` means valid-from before the Unix epoch (≈ valid now); rejecting both
  only ever denies. Non-negative timestamps up to `2^53-1` are enforced
  normally.

- Add `verifyInvocation(invocation, delegationStore, options)` — full
  cryptographic verification. `options` requires `executor` (the audience the
  invocation must be addressed to) and `replayStore`; `revocationStore`, `now`,
  and `leewaySeconds` are optional. Order: invocation signature → audience →
  fetch proofs once → count/CID/signature per proof → time/chain/command/
  predicate checks against the verified array (never re-fetched) → revocation →
  atomic replay claim. It **returns the authenticated, caller-detached
  `Invocation` snapshot**; consumers MUST read command/arguments from the
  returned value, not the object they passed in.
- Hardened `verifyInvocation` against mutable-state TOCTOU: it authenticates a
  private canonical snapshot (`decode(encode(...))`) before any await, captures
  the claim CID, requested-proof CID strings, and `now` (by value) all
  synchronously, binds every external store callable (`replayStore.claim`,
  `revocationStore.lookup`) to its original object before the first await, hands
  the store disposable CID clones (a CID's `multihash.bytes` is mutable), and
  detaches each fetched proof before its CID/signature checks — so neither the
  caller nor a hostile `DelegationStore` can alter what is verified, claimed, or
  executed across an await.
- `checkRevocations` captures proof-CID strings and binds `revocationStore.lookup`
  at function entry (before any await), hands both the delegation and revocation
  stores disposable CID clones, rebuilds a fresh trusted target CID, detaches
  each fetched proof and each returned revocation (`decode(encode(...))`) before
  use — closing revocation-CID digest mutation, lookup-swap, and store-owned
  getter-override attacks in both the verify path and the generic semantic path.
  Fetched proofs are copied via a captured-length indexed loop (never the
  store-owned array's `map`/iterator), so a hostile array cannot suppress or
  retain the detached snapshots. `MapRevocationStore.lookup` copies stored bytes
  before decoding.
- Documentation: `check` and `checkWithRevocations` are marked SEMANTIC-ONLY
  (verify no signatures, not an authorization gate) in their docstrings,
  examples 02/04/06 headers, and the README, which now shows the
  `verifyInvocation` authorization step.
- Add `Invocation.verifySignature()` / `Delegation.verifySignature()`, which
  re-derive a fresh Ed25519/DAG-CBOR verifier (do not trust the envelope header)
  and require the DAG-CBOR codec.
- `Invocation.decode` / `Delegation.decode` now reject non-canonically-encoded
  wire bytes and non-DAG-CBOR varsig headers.
- Ed25519 verification is now strict (`zip215:false`) in BOTH the `Ed25519`
  class and the `webCryptoVerify` path; `Ed25519Did` rejects small-order public
  keys. Together these close the identity-key universal signature forgery.
- `Timestamp.fromWireIpld` rejects values outside ±(2^53−1) per spec.
- Policy fixes: exact float/integer comparison (no precision-loss collisions),
  escaped-literal `\*` no longer treated as a trailing/leading wildcard, and
  optional selectors (`.a.b?`) resolve against the current selection. An
  optional only null-swallows when it itself misses: `.account?.owner` with a
  present `account` but missing `owner` fails the predicate (fail-closed)
  rather than resolving to null and passing an `== null` policy.
- `MapRevocationStore` stores canonical byte snapshots and decodes a fresh
  `Invocation` per `lookup`, so a caller cannot retract or mutate stored
  revocations through the returned array/objects (append-only invariant).
- Revocation authority is directional (spec §Scope): only the target proof's
  issuer or an ancestor delegator (a proof at/before the target in the
  root→leaf chain) may revoke it. A downstream delegate can no longer revoke an
  upstream/root proof (cross-principal DoS).
- IPLD map encoding uses a null-prototype object, so a map key like
  `__proto__` is not silently dropped via the prototype setter. Since
  `@ipld/dag-cbor` cannot round-trip such a key, a token carrying it is
  rejected at decode by the canonical check (fail-closed) instead of losing
  data; no prototype pollution occurs (args decode into a `Map`).
- `syntaticChecks` rejects a Powerline (`sub: null`) root proof and enforces
  per-hop command attenuation.
- Revocation store authenticates revocations on insert (signature, command,
  target CID), retains all revocations per target, and no longer swallows
  proof-resolution errors into "not revoked".
- Add `VerifyError` (`invalidInvocationSignature`, `invalidProofSignature`,
  `proofCidMismatch`, `proofCountMismatch`, `audienceMismatch`, `replay`),
  `ReplayStore`/`MapReplayStore`, `InvalidRevocationError`, `checkResolved`,
  `checkRevocations`, `assertValidRevocation`.

- Delegation decode preserves `meta` presence, so a spec-valid delegation with
  an explicit empty `meta: {}` decodes, verifies, and round-trips byte-exactly
  (builder output still omits empty `meta`, matching the 1.0.0 fixture).
- Depend on `@noble/curves` directly (was only transitive via varsig) and
  require `@marktripoli/varsig@^0.2.0` (the release carrying the strict
  verifier). **Publish `@marktripoli/varsig@0.2.0` before `@marktripoli/ucan@0.3.0`.**

**Breaking:**
- `RevocationStore.lookup` now returns `Invocation[]` (was a single optional
  invocation).
- `verifyInvocation` now resolves to the verified `Invocation` snapshot instead
  of `void`; execute from the returned value.

### v0.11.4

- Upload `README.md` to `@ucans/ucans` on npm.

### v0.11.2

- Add `.js` suffixes to imports for ESM builds

### v0.11.0

- Refactors `ucans` to use a plugin system for DIDs & keys. It is now 3 packages in a monorepo:
  - `@ucans/core` - core functionality & logic around UCANs
  - `@ucans/default-plugins` - support for ed25519, NIST P-256, & RSA
  - `@ucans/ucans` - `core` with `default-plugins` injected
- Locked `uint8arrays` to `v3.0.0`
- Removed `KeyType` in favor of `jwtAlg`
- Removed `BaseKey` class


### v0.10.0

- Added a new verify function for checking UCANs  
- Removed `hasCapability` and chained interface in favor of verify  
- Added public key compression for NIST P-256 keys  
- Added re-delegation to capability checking  

### v0.9.1

Fixed ESM build.

### v0.9.0

- Adjusted implementation to the 0.8.x [specification](https://github.com/ucan-wg/spec#readme).
- Added Builder API
- Renamed Indexer to Store
- Capability semantics and validating
- Compatibility layer for 0.3 UCANs
- Better validation