/**
 * UCAN revocation helpers.
 */

import { CID } from "multiformats/cid";
import type { AsyncDidSigner, Did, DidSigner } from "../did.js";
import { Command } from "../command.js";
import { Nonce } from "../crypto/nonce.js";
import type { Ipld } from "../ipld.js";
import { bytesEqual } from "../ipld.js";
import type { InvocationPayload } from "../invocation/index.js";
import { check, Invocation } from "../invocation/index.js";
import { InvocationBuilder } from "../invocation/builder.js";
import { Delegation } from "../delegation/index.js";
import type { DelegationStore } from "../delegation/store.js";


/*
 * Spec conflict, resolved deliberately:
 * - core command grammar requires a leading slash: .reference/spec/README.md:405
 * - revocation prose predates that grammar and still shows "ucan/revoke"
 * We keep the grammar form "/ucan/revoke" here so Command.parse accepts the final spec.
 */
export const REVOKE_COMMAND = Command.parse("/ucan/revoke");

export function revoke<DSigner extends DidSigner>(
  builder: InvocationBuilder<DSigner>,
  revoked: CID,
  path: CID[] = [],
): Invocation<DSigner["did"]> {
  const args = new Map<string, Ipld>([["revoke", revoked]]);

  if (path.length > 0) {
    args.set("path", path);
  }

  // Revocation/README.md §Invoking Revocation: nonce MUST be empty bytes because
  // revocation is idempotent.
  return builder
    .command(REVOKE_COMMAND)
    .arguments(args)
    .nonce(Nonce.fromBytes(new Uint8Array()))
    .tryBuild();
}

export async function revokeAsync<DSigner extends AsyncDidSigner>(
  builder: InvocationBuilder<DSigner>,
  revoked: CID,
  path: CID[] = [],
): Promise<Invocation<DSigner["did"]>> {
  const args = new Map<string, Ipld>([["revoke", revoked]]);

  if (path.length > 0) {
    args.set("path", path);
  }

  return builder
    .command(REVOKE_COMMAND)
    .arguments(args)
    .nonce(Nonce.fromBytes(new Uint8Array()))
    .tryBuildAsync();
}

export interface RevocationStore<D extends Did = Did> {
  insert(revoked: CID, revocation: Invocation<D>): Promise<void>;
  lookup(revoked: CID): Promise<Invocation<D>[]>;
}

export class InvalidRevocationError extends Error {
  constructor(readonly reason: "invalidSignature" | "notRevokeCommand" | "targetMismatch") {
    super(reason);
    this.name = "InvalidRevocationError";
  }
}

/**
 * Authenticate a revocation invocation before it is trusted/stored: the
 * envelope signature MUST verify, the command MUST be `/ucan/revoke`, and the
 * `revoke` argument MUST be the CID being revoked. Without this, anyone could
 * poison the store with an inapplicable first record that shadows genuine
 * revocations (Revocation/README.md §Invoking Revocation).
 */
export function assertValidRevocation<D extends Did>(revoked: CID, revocation: Invocation<D>): void {
  try {
    revocation.verifySignature();
  } catch {
    throw new InvalidRevocationError("invalidSignature");
  }
  if (!revocation.command.equals(REVOKE_COMMAND)) {
    throw new InvalidRevocationError("notRevokeCommand");
  }
  const target = CID.asCID(revocation.arguments.get("revoke") ?? null);
  if (!target || !target.equals(revoked)) {
    throw new InvalidRevocationError("targetMismatch");
  }
}

export class MapRevocationStore<D extends Did = Did> implements RevocationStore<D> {
  // Store canonical encoded-byte SNAPSHOTS, not caller-owned Invocation
  // references. Revocation/README.md §Semantics: revocations MUST be immutable
  // and the store monotonically-growing. Holding live references would let a
  // caller retract or mutate a stored record after the fact (mutating the
  // returned array, or the Invocation's arguments Map) and defeat validation.
  private readonly map = new Map<string, Uint8Array[]>();

  async insert(revoked: CID, revocation: Invocation<D>): Promise<void> {
    assertValidRevocation(revoked, revocation);
    const key = revoked.toString();
    const snapshot = revocation.encode();
    const existing = this.map.get(key);
    // Retain every applicable revocation so a poisoned/earlier record cannot
    // shadow a later genuine one; dedupe by canonical bytes.
    if (existing === undefined) {
      this.map.set(key, [snapshot]);
    } else if (!existing.some((bytes) => bytesEqual(bytes, snapshot))) {
      existing.push(snapshot);
    }
  }

  async lookup(revoked: CID): Promise<Invocation<D>[]> {
    const snapshots = this.map.get(revoked.toString()) ?? [];
    // Decode a FRESH Invocation per lookup from a COPY of the stored bytes, so a
    // caller cannot mutate stored state through the returned objects/array (and
    // cannot alias the stored Uint8Array even if a codec returns byte views).
    return snapshots.map((bytes) => Invocation.decode(new Uint8Array(bytes)) as unknown as Invocation<D>);
  }
}

export class RevokedError extends Error {
  constructor(readonly revoked: CID, readonly revoker: Did) {
    super(`delegation ${revoked.toString()} revoked by ${revoker.toString()}`);
    this.name = "RevokedError";
  }
}

/**
 * SEMANTIC-ONLY: `check` (chain/predicate/time) plus revocation lookup. This
 * does NOT verify envelope signatures, proof CIDs, the executor audience, or
 * replay, and MUST NOT be used as an authorization gate on untrusted input. Use
 * `verifyInvocation` with a `revocationStore` for authorization.
 */
export async function checkWithRevocations<D extends Did>(
  payload: InvocationPayload<D>,
  delegationStore: DelegationStore<D>,
  revocationStore: RevocationStore<D>,
): Promise<void> {
  await check(payload, delegationStore);
  await checkRevocations(payload, delegationStore, revocationStore);
}

/**
 * Revocation checks only (no time/chain/predicate validation).
 *
 * `resolvedProofs`, when supplied, is the already-authenticated proof array
 * (verifyInvocation passes it so the delegator check never re-reads the store).
 */
export async function checkRevocations<D extends Did>(
  payload: InvocationPayload<D>,
  delegationStore: DelegationStore<D>,
  revocationStore: RevocationStore<D>,
  resolvedProofs?: Delegation<D>[],
): Promise<void> {
  // Capture proof-CID strings and bind lookup BEFORE any await, so a hostile
  // delegationStore cannot mutate a handed CID's digest or swap
  // revocationStore.lookup across the getAll await. When resolvedProofs is
  // omitted we fetch with disposable CID clones and detach each fetched proof
  // into a private snapshot (verifyInvocation already supplies detached,
  // authenticated proofs, so that path is unaffected).
  const proofCidStrings = payload.proofs.map((cid) => cid.toString());
  const revocationLookup = revocationStore.lookup.bind(revocationStore);

  let proofs: Delegation<D>[];
  if (resolvedProofs !== undefined) {
    proofs = resolvedProofs;
  } else {
    const fetched = await delegationStore.getAll(proofCidStrings.map((s) => CID.parse(s)));
    // Copy into a fresh local array using the TRUSTED count
    // (`proofCidStrings.length`), never reading `fetched.length`/`.map`/its
    // iterator: a hostile Proxy-over-array could trap `length` (return 0 to
    // suppress every ancestor) or `map`, or retain snapshots. Indexing to the
    // trusted count with a per-element decode keeps the snapshots private; a
    // missing element throws at `.encode()` and fails closed.
    proofs = [];
    for (let j = 0; j < proofCidStrings.length; j++) {
      proofs.push(Delegation.decode(fetched[j].encode()) as unknown as Delegation<D>);
    }
  }

  // Revocation/README.md §Store (normative pseudocode): a delegation in the
  // chain is invalidated iff the revocation's issuer is one of the chain's
  // delegators, i.e. the revoker appears (transitively) as a proof `iss`.
  // Since `prf` is the full root→invoker chain, this is exactly §Scope's
  // transitive-issuer rule, evaluated against the already-verified `proofs`
  // array (never re-read from the store).
  //
  // We deliberately do NOT treat the OPTIONAL `path` witness as a second
  // invalidation vector. The witness is a revoker-supplied argument; §Path
  // Witness frames it only as an anti-DoS aid for deciding whether to accept a
  // *spurious* revocation, not as authority to invalidate. Using it for
  // invalidation is both forgeable (a crafted path revokes an unrelated
  // delegation) and prone to fail-open on partial resolution.
  //
  // DIRECTIONALITY (§Scope + diagram): revocation authority flows
  // ancestor→descendant. Only the target proof's issuer or an ANCESTOR
  // delegator (a proof at or before the target in the root→leaf chain) may
  // revoke it. `proofs` is ordered root(0)→leaf, parallel to payload.proofs, so
  // authority for the proof at index i is proofs[0..i]. Checking the whole
  // array would let a downstream delegate revoke an upstream/root proof
  // (cross-principal DoS).
  for (let i = 0; i < proofCidStrings.length; i++) {
    const ancestorsInclusive = proofs.slice(0, i + 1);
    // Hand the store a disposable clone via the bound lookup; rebuild a fresh
    // trusted target CID from the captured string after the await.
    const revocations = await revocationLookup(CID.parse(proofCidStrings[i]));
    const targetCid = CID.parse(proofCidStrings[i]);
    // Indexed loop with captured length (no store-owned Symbol.iterator).
    const revCount = revocations.length;
    for (let k = 0; k < revCount; k++) {
      const revocation = revocations[k];
      // Detach a private snapshot of the returned revocation so getter overrides
      // or later mutation on a store-owned object cannot make the signed issuer
      // differ from the issuer used for the authority check.
      let snap;
      try {
        snap = Invocation.decode(revocation.encode()) as unknown as Invocation<D>;
      } catch {
        continue;
      }
      // Defense in depth: re-authenticate even though insert already did, in
      // case a custom store returns unvalidated records.
      try {
        assertValidRevocation(targetCid, snap);
      } catch {
        continue;
      }

      if (ancestorsInclusive.some((proof) => proof.issuer.equals(snap.issuer))) {
        throw new RevokedError(targetCid, snap.issuer);
      }
    }
  }
}


