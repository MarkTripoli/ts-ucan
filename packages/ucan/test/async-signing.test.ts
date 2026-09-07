import { webcrypto } from "node:crypto";
import { ed25519 } from "@noble/curves/ed25519";
import { describe, expect, it } from "vitest";
import {
  Delegation,
  DelegationBuilder,
  Ed25519AsyncSigner,
  Ed25519Did,
  Ed25519Signer,
  InvocationBuilder,
  Nonce,
  assertValidRevocation,
  revoke,
  revokeAsync,
} from "../src/index.js";

function signerPair(seed: number): {
  sync: Ed25519Signer;
  async: Ed25519AsyncSigner;
} {
  const secretKey = new Uint8Array(32).fill(seed);
  const sync = new Ed25519Signer(secretKey);
  const asyncSigner = new Ed25519AsyncSigner(
    sync.did,
    (bytes) => Promise.resolve(ed25519.sign(bytes, secretKey)),
  );
  return { sync, async: asyncSigner };
}

describe("asynchronous signing", () => {
  it("builds byte-identical invocations and verifies them", async () => {
    const alice = signerPair(1);
    const bob = signerPair(2);
    const nonce = Nonce.fromBytes(Uint8Array.from([1, 2, 3, 4]));

    const syncInvocation = new InvocationBuilder()
      .issuer(alice.sync)
      .audience(bob.sync.did)
      .subject(bob.sync.did)
      .commandFromStr("/read")
      .proofs([])
      .nonce(nonce)
      .tryBuild();
    const asyncInvocation = await new InvocationBuilder()
      .issuer(alice.async)
      .audience(bob.async.did)
      .subject(bob.async.did)
      .commandFromStr("/read")
      .proofs([])
      .nonce(nonce)
      .tryBuildAsync();

    expect(asyncInvocation.encode()).toEqual(syncInvocation.encode());
    expect(asyncInvocation.toCid()).toEqual(syncInvocation.toCid());
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
    expect(asyncDelegation.toCid()).toEqual(syncDelegation.toCid());
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
      new InvocationBuilder()
        .issuer(bob.sync)
        .audience(alice.sync.did)
        .subject(alice.sync.did)
        .proofs([targetCid]),
      targetCid,
    );
    const asyncRevocation = await revokeAsync(
      new InvocationBuilder()
        .issuer(bob.async)
        .audience(alice.async.did)
        .subject(alice.async.did)
        .proofs([targetCid]),
      targetCid,
    );

    expect(asyncRevocation.encode()).toEqual(syncRevocation.encode());
    expect(asyncRevocation.toCid()).toEqual(syncRevocation.toCid());
    expect(() => asyncRevocation.verifySignature()).not.toThrow();
    expect(() => assertValidRevocation(targetCid, asyncRevocation)).not.toThrow();
  });

  it("round-trips a non-extractable WebCrypto Ed25519 private key", async () => {
    const generated = await webcrypto.subtle.generateKey(
      { name: "Ed25519" },
      true,
      ["sign", "verify"],
    );
    if (!("privateKey" in generated) || !("publicKey" in generated)) {
      throw new Error("expected an Ed25519 key pair");
    }

    const publicKey = new Uint8Array(
      await webcrypto.subtle.exportKey("raw", generated.publicKey),
    );
    const privateKeyBytes = await webcrypto.subtle.exportKey(
      "pkcs8",
      generated.privateKey,
    );
    const privateKey = await webcrypto.subtle.importKey(
      "pkcs8",
      privateKeyBytes,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    expect(privateKey.extractable).toBe(false);

    const signer = new Ed25519AsyncSigner(
      new Ed25519Did(publicKey),
      async (bytes) =>
        new Uint8Array(
          await webcrypto.subtle.sign("Ed25519", privateKey, bytes),
        ),
    );
    const delegation = await new DelegationBuilder()
      .issuer(signer)
      .audience(signer.did)
      .subject({ kind: "specific", did: signer.did })
      .commandFromStr("/read")
      .tryBuildAsync();

    expect(() => delegation.verifySignature()).not.toThrow();
    expect(delegation.encode()).toEqual(
      Delegation.decode(delegation.encode()).encode(),
    );
  });
});
