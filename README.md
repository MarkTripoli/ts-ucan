# ts-ucan

TypeScript implementation of [UCAN](https://github.com/ucan-wg/spec) (User-Controlled Authorization Networks) v1.0 — a trustless, secure, local-first, user-originated authorization and revocation scheme maintained by the [UCAN Working Group](https://github.com/ucan-wg).

UCANs are capability tokens: instead of asking a central server for permission, principals delegate authority directly to one another and invoke it offline-verifiably. Tokens are content-addressed, cryptographically signed, and chain together into verifiable proofs.

## Specifications

This library implements the UCAN 1.0 family of specifications:

- [UCAN core spec](https://github.com/ucan-wg/spec) — high-level semantics, principals, capabilities
- [Delegation](https://github.com/ucan-wg/delegation) — granting authority between principals, including the policy language
- [Invocation](https://github.com/ucan-wg/invocation) — exercising delegated authority, proof chains, promises/pipelining
- [Revocation](https://github.com/ucan-wg/revocation) — invalidating delegations after the fact (`/ucan/revoke` invocations + append-only revocation stores)
- [Container / Envelope](https://github.com/ucan-wg/container) — the signed DAG-CBOR token envelope
- [Varsig](https://github.com/ChainAgnostic/varsig) — self-describing signature headers (algorithm, hash, payload encoding)
- [did:key](https://w3c-ccg.github.io/did-method-key/) — principal identifiers

## Packages

| Package | Contents |
|---|---|
| `@marktripoli/varsig` | Varsig headers, payload codecs (DAG-CBOR, DAG-JSON), EdDSA sign/verify, ECDSA verify (P-256/P-384/P-521/secp256k1), WebCrypto integration |
| `@marktripoli/ucan` | Delegation and invocation tokens with builders, the policy language (predicates + selectors), envelopes, `did:key` principals, timestamps, nonces, proof-chain checking, revocation (`checkWithRevocations`), and the container transport format |

## Wire format

Tokens are DAG-CBOR envelopes: a varsig header describing the signature scheme plus a tagged payload (`ucan/dlg@1.0.0`, `ucan/inv@1.0.0`), with the signature computed over the complete envelope payload per the final 1.0 spec. Encoding and decoding round-trip byte-exactly and are covered by conformance fixtures.

Note: revocation commands use `/ucan/revoke` — the leading slash follows the final core-spec command grammar; the revocation spec document (v1.0.0-rc.1) predates it.

## Usage

```ts
import { DelegationBuilder, InvocationBuilder } from "@marktripoli/ucan";

// Delegate a capability
const delegation = new DelegationBuilder()
  .issuer(aliceSigner)
  .audience(bobDid)
  .subject({ kind: "specific", did: aliceDid })
  .commandFromStr("/crud/create")
  .tryBuild();

// Invoke it (proofs reference delegations by CID)
const invocation = new InvocationBuilder()
  .issuer(bobSigner)
  .audience(aliceDid)
  .subject(aliceDid)
  .commandFromStr("/crud/create")
  .proofs([delegationCid])
  .issueNow()
  .tryBuild();

// Authorize an invocation from untrusted input. verifyInvocation authenticates
// the invocation + every proof signature, recomputes proof CIDs, enforces the
// executor audience, runs the chain/predicate/time checks, applies revocations,
// and claims the CID for replay prevention. It returns the authenticated
// snapshot — act on the RETURNED value, not the decoded input.
const verified = await verifyInvocation(Invocation.decode(bytes), delegationStore, {
  executor: serviceDid,       // the invocation's `aud` must equal this
  replayStore,                // rejects a repeated invocation CID
  revocationStore,            // optional
});

// `check` / `checkWithRevocations` are SEMANTIC-ONLY (chain/predicate/time,
// plus revocation). They verify NO signatures and MUST NOT gate authorization
// on untrusted input — use verifyInvocation for that.
```

### Asynchronous signing

When the private key is only reachable through an async API (a non-extractable
Web Crypto `CryptoKey`, a hardware token, a remote KMS), pass an
`AsyncDidSigner` and call `tryBuildAsync()` / `revokeAsync()`. The `sign`
callback receives the exact canonical bytes to sign; the key never enters this
library. The result is byte-for-byte identical to the synchronous path, so
CIDs and verification are unchanged.

```ts
import type { AsyncDidSigner } from "@marktripoli/ucan";
import { DelegationBuilder, Ed25519Did, InvocationBuilder, revokeAsync } from "@marktripoli/ucan";

const { privateKey, publicKey } = await crypto.subtle.generateKey({ name: "Ed25519" }, false, ["sign", "verify"]);
const aliceDid = new Ed25519Did(new Uint8Array(await crypto.subtle.exportKey("raw", publicKey)));

const signer: AsyncDidSigner<Ed25519Did> = {
  did: aliceDid,
  sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, bytes as BufferSource)),
};

const delegation = await new DelegationBuilder()
  .issuer(signer)
  .audience(bobDid)
  .subject({ kind: "specific", did: aliceDid })
  .commandFromStr("/crud/create")
  .tryBuildAsync();

const invocation = await new InvocationBuilder()
  .issuer(signer)
  .audience(bobDid)
  .subject(bobDid)
  .commandFromStr("/crud/create")
  .proofs([delegation.toCid()])
  .tryBuildAsync();

const revocation = await revokeAsync(
  new InvocationBuilder()
    .issuer(signer)
    .audience(aliceDid)
    .subject(aliceDid)
    .proofs([delegation.toCid()]),
  delegation.toCid(),
);
```

A rejected `sign` surfaces as `SignerError` with `reason: "signingError"`.
Calling `tryBuild()` on an `AsyncDidSigner` (or `tryBuildAsync()` on a
`DidSigner`) is a type error and throws at runtime; it never signs garbage.

## Build

```sh
npm install
npm run build
```

## Test

```sh
npm test
```

Runs the unit suites for both packages plus the delegation and policy conformance fixtures.

## Examples
See `examples/` for runnable end-to-end scripts covering delegation, policy, revocation, HTTP, and container transport.
Prereq: `npm install && npm run build`.
Run them all with `npm run examples`.
Each file also runs directly with `node examples/<file>.ts`.

## License

[Apache-2.0](LICENSE)
