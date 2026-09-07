import { describe, it, expect } from "vitest";
import { encode as dagCborEncode, decode as dagCborDecode } from "@ipld/dag-cbor";
import { ed25519 } from "@noble/curves/ed25519";
import { Varsig } from "../src/header.js";
import { DagCborCodec } from "../src/codec.js";
import { Ed25519, ed25519TryFromTags } from "../src/signature/eddsa.js";
import type { Ipld } from "../src/ipld.js";

// ---------------------------------------------------------------------------
// Helpers: encode/decode Varsig through DAG-CBOR byte string wrapping
// ---------------------------------------------------------------------------

/** Encode a Varsig as DAG-CBOR bytes (wraps the LEB128 bytes in a CBOR byte string). */
function dagCborEncodeVarsig(v: Varsig<any>): Uint8Array {
  const raw = v.encode();
  return dagCborEncode(raw);
}

/** Decode a Varsig from DAG-CBOR bytes. */
function dagCborDecodeVarsig<V extends { prefix(): number; configTags(): number[] }>(
  bytes: Uint8Array,
  tryFromTags: (tags: number[]) => { config: V; rest: number[] } | null,
): Varsig<V> {
  const raw = dagCborDecode(bytes);
  if (!(raw instanceof Uint8Array)) {
    throw new Error("expected CBOR byte string");
  }
  return Varsig.decode(raw, tryFromTags as any);
}

// ---------------------------------------------------------------------------
// test_ed25519_varsig_header_round_trip
// ---------------------------------------------------------------------------

describe("test_ed25519_varsig_header_round_trip", () => {
  it("round-trips through encode/decode", () => {
    const fixture = new Varsig(new Ed25519(), DagCborCodec);
    const dagCbor = dagCborEncodeVarsig(fixture);
    const decoded = dagCborDecodeVarsig(dagCbor, ed25519TryFromTags);

    expect(decoded.verifierCfg.prefix()).toBe(fixture.verifierCfg.prefix());
    expect(decoded.verifierCfg.configTags()).toEqual(
      fixture.verifierCfg.configTags(),
    );
    expect(decoded.codec.multicodecCode).toBe(
      fixture.codec.multicodecCode,
    );
  });
});

// ---------------------------------------------------------------------------
// test_ed25519_varsig_header_fixture
// ---------------------------------------------------------------------------

describe("test_ed25519_varsig_header_fixture", () => {
  it("decodes the exact byte fixture", () => {
    // DAG-CBOR byte string wrapping: 0x48 = byte string of length 8,
    // followed by 8 LEB128-encoded bytes.
    const dagCborBytes = new Uint8Array([
      0x48, 0x34, 0x01, 0xed, 0x01, 0xed, 0x01, 0x13, 0x71,
    ]);

    const decoded = dagCborDecodeVarsig(dagCborBytes, ed25519TryFromTags);

    expect(decoded.verifierCfg.prefix()).toBe(0xed);
    expect(decoded.verifierCfg.configTags()).toEqual([0xed, 0x13]);
    expect(decoded.codec.multicodecCode).toBe(0x71);
  });
});

// ---------------------------------------------------------------------------
// test_verifier_reader
// ---------------------------------------------------------------------------

describe("test_verifier_reader", () => {
  it("returns the correct verifier config", () => {
    const varsig = new Varsig(new Ed25519(), DagCborCodec);
    expect(varsig.verifierCfg.prefix()).toBe(0xed);
    expect(varsig.verifierCfg.configTags()).toEqual([0xed, 0x13]);
  });
});

// ---------------------------------------------------------------------------
// test_codec_reader
// ---------------------------------------------------------------------------

describe("test_codec_reader", () => {
  it("returns the correct codec", () => {
    const varsig = new Varsig(new Ed25519(), DagCborCodec);
    expect(varsig.codec.multicodecCode).toBe(0x71);
  });
});

// ---------------------------------------------------------------------------
// test_try_verify
// ---------------------------------------------------------------------------

describe("test_try_verify", () => {
  it("signs and verifies a payload round-trip", () => {
    const payload: Ipld = new Map<string, Ipld>([
      ["message", "Hello, Varsig!"],
      ["count", 42],
    ]);

    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);

    const varsig = new Varsig(new Ed25519(), DagCborCodec);

    const { signature } = varsig.trySign(sk, payload);
    varsig.tryVerify(pk, payload, signature);
    // If we got here without throwing, verification passed
  });

  it("docExampleRoundtrip", () => {
    const payload: Ipld = new Map<string, Ipld>([
      ["message", "Hello, Varsig!"],
      ["count", 42],
    ]);

    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);

    const varsig = new Varsig(new Ed25519(), DagCborCodec);
    const { signature } = varsig.trySign(sk, payload);
    expect(() => varsig.tryVerify(pk, payload, signature)).not.toThrow();
  });

  it("fails verification with wrong signature", () => {
    const payload: Ipld = new Map<string, Ipld>([
      ["message", "Hello, Varsig!"],
      ["count", 42],
    ]);

    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);

    const varsig = new Varsig(new Ed25519(), DagCborCodec);

    const { signature } = varsig.trySign(sk, payload);

    // Tamper with the signature
    const badSig = new Uint8Array(signature);
    badSig[0] = (badSig[0] + 1) % 256;

    expect(() => varsig.tryVerify(pk, payload, badSig)).toThrow();
  });

  it("signs and verifies asynchronously", async () => {
    const payload: Ipld = new Map<string, Ipld>([
      ["message", "Hello, async Varsig!"],
      ["count", 42],
    ]);
    const sk = ed25519.utils.randomPrivateKey();
    const pk = ed25519.getPublicKey(sk);
    const varsig = new Varsig(new Ed25519(), DagCborCodec);

    const { signature } = await varsig.trySignAsync(
      (message) => Promise.resolve(ed25519.sign(message, sk)),
      payload,
    );

    expect(() => varsig.tryVerify(pk, payload, signature)).not.toThrow();
  });
});
