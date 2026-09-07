/**
 * tryBuildAsync / revokeAsync: an AsyncDidSigner must produce bytes identical
 * to the synchronous path, work with a non-extractable Web Crypto key end to
 * end through verifyInvocation, and fail loudly when the wrong build path is
 * used for the signer kind.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  Delegation,
  DelegationBuilder,
  Ed25519Did,
  Ed25519Signer,
  Invocation,
  InvocationBuilder,
  MapDelegationStore,
  MapReplayStore,
  Nonce,
  assertValidRevocation,
  revoke,
  revokeAsync,
  verifyInvocation,
} from "../src/index.js";
import type { AsyncDidSigner } from "../src/index.js";

function signerPair(seed: number): { sync: Ed25519Signer; async: AsyncDidSigner<Ed25519Did> } {
  const secretKey = new Uint8Array(32).fill(seed);
  const sync = new Ed25519Signer(secretKey);
  return {
    sync,
    async: { did: sync.did, sign: async (bytes) => ed25519.sign(bytes, secretKey) },
  };
}

describe("asynchronous signing", () => {
  it("builds byte-identical invocations and verifies them", async () => {
    const alice = signerPair(1);
    const bob = signerPair(2);
    const nonce = Nonce.fromBytes(Uint8Array.from([1, 2, 3, 4]));

    const syncInvocation = Invocation.builder()
      .issuer(alice.sync)
      .audience(bob.sync.did)
      .subject(bob.sync.did)
      .commandFromStr("/read")
      .proofs([])
      .nonce(nonce)
      .tryBuild();
    const asyncInvocation = await Invocation.builder()
      .issuer(alice.async)
      .audience(bob.async.did)
      .subject(bob.async.did)
      .commandFromStr("/read")
      .proofs([])
      .nonce(nonce)
      .tryBuildAsync();

    expect(asyncInvocation.encode()).toEqual(syncInvocation.encode());
    expect(asyncInvocation.toCid().toString()).toBe(syncInvocation.toCid().toString());
    expect(() => asyncInvocation.verifySignature()).not.toThrow();
  });

  it("builds byte-identical delegations and verifies them", async () => {
    const alice = signerPair(3);
    const bob = signerPair(4);
    const nonce = Nonce.fromBytes(Uint8Array.from([5, 6, 7, 8]));

    const syncDelegation = new DelegationBuilder()
      .issuer(alice.sync)
      .audience(bob.sync.did)
      .subject({ kind: "specific", did: alice.sync.did })
      .commandFromStr("/read")
      .nonce(nonce)
      .tryBuild();
    const asyncDelegation = await new DelegationBuilder()
      .issuer(alice.async)
      .audience(bob.async.did)
      .subject({ kind: "specific", did: alice.async.did })
      .commandFromStr("/read")
      .nonce(nonce)
      .tryBuildAsync();

    expect(asyncDelegation.encode()).toEqual(syncDelegation.encode());
    expect(asyncDelegation.toCid().toString()).toBe(syncDelegation.toCid().toString());
    expect(() => asyncDelegation.verifySignature()).not.toThrow();
  });

  it("builds byte-identical revocations and verifies them", async () => {
    const alice = signerPair(5);
    const bob = signerPair(6);
    const target = new DelegationBuilder()
      .issuer(alice.sync)
      .audience(bob.sync.did)
      .subject({ kind: "specific", did: alice.sync.did })
      .commandFromStr("/read")
      .nonce(Nonce.fromBytes(Uint8Array.from([9, 10, 11])))
      .tryBuild();
    const targetCid = target.toCid();

    const syncRevocation = revoke(
      new InvocationBuilder().issuer(bob.sync).audience(alice.sync.did).subject(alice.sync.did).proofs([targetCid]),
      targetCid,
    );
    const asyncRevocation = await revokeAsync(
      new InvocationBuilder().issuer(bob.async).audience(alice.async.did).subject(alice.async.did).proofs([targetCid]),
      targetCid,
    );

    expect(asyncRevocation.encode()).toEqual(syncRevocation.encode());
    expect(asyncRevocation.toCid().toString()).toBe(syncRevocation.toCid().toString());
    expect(() => assertValidRevocation(targetCid, asyncRevocation)).not.toThrow();
  });

  it("signs with a non-extractable WebCrypto key and passes verifyInvocation", async () => {
    // Only the private key honours `extractable: false`; the public key is always exportable.
    const { privateKey, publicKey } = (await crypto.subtle.generateKey({ name: "Ed25519" }, false, [
      "sign",
      "verify",
    ])) as CryptoKeyPair;
    expect(privateKey.extractable).toBe(false);

    const web: AsyncDidSigner<Ed25519Did> = {
      did: new Ed25519Did(new Uint8Array(await crypto.subtle.exportKey("raw", publicKey))),
      sign: async (bytes) => new Uint8Array(await crypto.subtle.sign("Ed25519", privateKey, bytes as BufferSource)),
    };
    const executor = signerPair(7).sync.did;

    // Root invocation: issuer is the subject, so no proofs are needed.
    const invocation = await new InvocationBuilder()
      .issuer(web)
      .audience(executor)
      .subject(web.did)
      .commandFromStr("/read")
      .proofs([])
      .tryBuildAsync();

    const verified = await verifyInvocation(Invocation.decode(invocation.encode()), new MapDelegationStore(), {
      executor,
      replayStore: new MapReplayStore(),
    });
    expect(verified.toCid().toString()).toBe(invocation.toCid().toString());

    const delegation = await new DelegationBuilder()
      .issuer(web)
      .audience(executor)
      .subject({ kind: "specific", did: web.did })
      .commandFromStr("/read")
      .tryBuildAsync();
    expect(() => Delegation.decode(delegation.encode()).verifySignature()).not.toThrow();
  });

  it("surfaces a rejecting callback as SignerError(signingError)", async () => {
    const { did } = signerPair(8).sync;
    const refusing: AsyncDidSigner<Ed25519Did> = {
      did,
      sign: () => Promise.reject(new Error("user declined")),
    };

    await expect(
      new InvocationBuilder().issuer(refusing).audience(did).subject(did).commandFromStr("/read").proofs([]).tryBuildAsync(),
    ).rejects.toMatchObject({ name: "SignerError", reason: "signingError", message: /user declined/ });

    await expect(
      new DelegationBuilder().issuer(refusing).audience(did).subject(did).commandFromStr("/read").tryBuildAsync(),
    ).rejects.toMatchObject({ name: "SignerError", reason: "signingError" });
  });

  it("rejects the wrong build path for the signer kind, at compile time and at runtime", async () => {
    const { sync, async } = signerPair(9);
    const asyncBuilder = new InvocationBuilder().issuer(async).audience(sync.did).subject(sync.did).commandFromStr("/read").proofs([]);
    const syncBuilder = new InvocationBuilder().issuer(sync).audience(sync.did).subject(sync.did).commandFromStr("/read").proofs([]);

    // @ts-expect-error tryBuild requires a DidSigner
    expect(() => asyncBuilder.tryBuild()).toThrow(/use tryBuildAsync\(\)/);
    // @ts-expect-error tryBuildAsync requires an AsyncDidSigner
    await expect(syncBuilder.tryBuildAsync()).rejects.toThrow(/use tryBuild\(\)/);

    const asyncDelegation = new DelegationBuilder().issuer(async).audience(sync.did).subject(sync.did).commandFromStr("/read");
    // @ts-expect-error tryBuild requires a DidSigner
    expect(() => asyncDelegation.tryBuild()).toThrow(/use tryBuildAsync\(\)/);
  });
});
