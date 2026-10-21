import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { secp256k1 } from "@noble/curves/secp256k1";
import { sha256 } from "@noble/hashes/sha256";
import { sha384 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha512";
import type { Verify } from "../verify.js";
import { defaultTryVerify } from "../verify.js";
import type { TryFromTags } from "../header.js";
import type { Codec } from "../codec.js";
import type { Ipld } from "../ipld.js";

// ---------------------------------------------------------------------------
// ECDSA verify helper
// ---------------------------------------------------------------------------

/**
 * Common ECDSA verification: hash the message, then verify.
 *
 * Rust's `p256::ecdsa::VerifyingKey::verify` hashes internally (SHA-256);
 * noble's `verify` expects a pre-hashed message, so we hash manually here.
 */
function ecdsaVerify(
  curve: { verify(sig: Uint8Array, hash: Uint8Array, key: Uint8Array): boolean },
  hashFn: (msg: Uint8Array) => Uint8Array,
  msg: Uint8Array,
  sig: Uint8Array,
  pubkey: Uint8Array,
): void {
  const msgHash = hashFn(msg);
  if (!curve.verify(sig, msgHash, pubkey)) {
    throw new Error("signature verification failed");
  }
}

// ---------------------------------------------------------------------------
// Es256 — secp256r1 (P-256) + SHA-256 — VERIFY-ONLY
// ---------------------------------------------------------------------------

/** ES256: ECDSA with P-256 curve and SHA-256 hashing. VERIFY-ONLY. */
export class Es256 implements Verify<Uint8Array> {
  prefix(): 0xec {
    return 0xec;
  }

  configTags(): [0x1200, 0x12] {
    return [0x1200, 0x12];
  }

  tryDecodeSignature(signature: Uint8Array): void {
    p256.Signature.fromBytes(signature, "compact");
  }

  tryVerify(
    codec: Codec,
    verifier: Uint8Array,
    signature: Uint8Array,
    payload: Ipld,
  ): void {
    defaultTryVerify(codec, verifier, signature, payload, (vk, msg, sig) => {
      ecdsaVerify(p256, sha256, msg, sig, vk as Uint8Array);
    });
  }
}

export const es256TryFromTags: TryFromTags<Es256> = (
  tags: number[],
) => {
  if (
    tags.length >= 3 &&
    tags[0] === 0xec &&
    tags[1] === 0x1200 &&
    tags[2] === 0x12
  ) {
    return { config: new Es256(), rest: tags.slice(3) };
  }
  return null;
};

// ---------------------------------------------------------------------------
// Es384 — secp384r1 (P-384) + SHA-384 — VERIFY-ONLY
// ---------------------------------------------------------------------------

/** ES384: ECDSA with P-384 curve and SHA-384 hashing. VERIFY-ONLY. */
export class Es384 implements Verify<Uint8Array> {
  prefix(): 0xec {
    return 0xec;
  }

  configTags(): [0x1201, 0x20] {
    return [0x1201, 0x20];
  }

  tryDecodeSignature(signature: Uint8Array): void {
    p384.Signature.fromBytes(signature, "compact");
  }

  tryVerify(
    codec: Codec,
    verifier: Uint8Array,
    signature: Uint8Array,
    payload: Ipld,
  ): void {
    defaultTryVerify(codec, verifier, signature, payload, (vk, msg, sig) => {
      ecdsaVerify(p384, sha384, msg, sig, vk as Uint8Array);
    });
  }
}

export const es384TryFromTags: TryFromTags<Es384> = (
  tags: number[],
) => {
  if (
    tags.length >= 3 &&
    tags[0] === 0xec &&
    tags[1] === 0x1201 &&
    tags[2] === 0x20
  ) {
    return { config: new Es384(), rest: tags.slice(3) };
  }
  return null;
};

// ---------------------------------------------------------------------------
// Es512 — secp521r1 (P-521) + SHA-512 — VERIFY-ONLY
// ---------------------------------------------------------------------------

/** ES512: ECDSA with P-521 curve and SHA-512 hashing. VERIFY-ONLY. */
export class Es512 implements Verify<Uint8Array> {
  prefix(): 0xec {
    return 0xec;
  }

  configTags(): [0x1202, 0x13] {
    return [0x1202, 0x13];
  }

  tryDecodeSignature(signature: Uint8Array): void {
    p521.Signature.fromBytes(signature, "compact");
  }

  tryVerify(
    codec: Codec,
    verifier: Uint8Array,
    signature: Uint8Array,
    payload: Ipld,
  ): void {
    defaultTryVerify(codec, verifier, signature, payload, (vk, msg, sig) => {
      ecdsaVerify(p521, sha512, msg, sig, vk as Uint8Array);
    });
  }
}

export const es512TryFromTags: TryFromTags<Es512> = (
  tags: number[],
) => {
  if (
    tags.length >= 3 &&
    tags[0] === 0xec &&
    tags[1] === 0x1202 &&
    tags[2] === 0x13
  ) {
    return { config: new Es512(), rest: tags.slice(3) };
  }
  return null;
};

// ---------------------------------------------------------------------------
// Es256k — secp256k1 + SHA-256 — VERIFY-ONLY
// ---------------------------------------------------------------------------

/** ES256K: ECDSA with secp256k1 curve and SHA-256 hashing. VERIFY-ONLY. */
export class Es256k implements Verify<Uint8Array> {
  prefix(): 0xec {
    return 0xec;
  }

  configTags(): [0xe7, 0x12] {
    return [0xe7, 0x12];
  }

  tryDecodeSignature(signature: Uint8Array): void {
    secp256k1.Signature.fromBytes(signature, "compact");
  }

  tryVerify(
    codec: Codec,
    verifier: Uint8Array,
    signature: Uint8Array,
    payload: Ipld,
  ): void {
    defaultTryVerify(codec, verifier, signature, payload, (vk, msg, sig) => {
      ecdsaVerify(secp256k1, sha256, msg, sig, vk as Uint8Array);
    });
  }
}

export const es256kTryFromTags: TryFromTags<Es256k> = (
  tags: number[],
) => {
  if (
    tags.length >= 3 &&
    tags[0] === 0xec &&
    tags[1] === 0xe7 &&
    tags[2] === 0x12
  ) {
    return { config: new Es256k(), rest: tags.slice(3) };
  }
  return null;
};