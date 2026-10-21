import type { TryFromTags } from "../header.js";
import { ed25519 } from "@noble/curves/ed25519";
import { p256 } from "@noble/curves/p256";
import { p384 } from "@noble/curves/p384";
import { p521 } from "@noble/curves/p521";
import { sha256 } from "@noble/hashes/sha256";
import { sha384 } from "@noble/hashes/sha2";
import { sha512 } from "@noble/hashes/sha512";
import { Ed25519 } from "./eddsa.js";
import { Es256, Es384, Es512 } from "./ecdsa.js";

/**
 * WebCrypto-compatible signature algorithm configuration.
 *
 * In Rust this is a runtime enum whose variants implement `Verify`.
 * In TS we reuse the concrete algorithm classes directly.
 */
export type WebCrypto = Ed25519 | Es256 | Es384 | Es512;

/**
 * WebCrypto verifier — algorithm + raw key bytes.
 */
export type WebCryptoVerifier =
  | { alg: "es256"; key: Uint8Array }
  | { alg: "es384"; key: Uint8Array }
  | { alg: "es512"; key: Uint8Array }
  | { alg: "ed25519"; key: Uint8Array };

export type WebCryptoSignature =
  | { alg: "es256"; signature: Uint8Array }
  | { alg: "es384"; signature: Uint8Array }
  | { alg: "es512"; signature: Uint8Array }
  | { alg: "ed25519"; signature: Uint8Array };

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

/**
 * Verify a WebCrypto signature against a verifier key.
 *
 * Variant mismatches are rejected before cryptographic verification.
 */
export function webCryptoVerify(
  verifier: WebCryptoVerifier,
  msg: Uint8Array,
  sig: WebCryptoSignature,
): void {
  if (verifier.alg !== sig.alg) {
    throw new Error("variant mismatch");
  }

  switch (sig.alg) {
    case "es256":
      ecdsaVerify(p256, sha256, msg, sig.signature, verifier.key);
      return;
    case "es384":
      ecdsaVerify(p384, sha384, msg, sig.signature, verifier.key);
      return;
    case "es512":
      ecdsaVerify(p521, sha512, msg, sig.signature, verifier.key);
      return;
    case "ed25519":
      // zip215:false enforces strict RFC 8032 (rejects non-canonical /
      // small-order signatures), matching the Ed25519 class and closing the
      // identity-key universal forgery.
      if (!ed25519.verify(sig.signature, msg, verifier.key, { zip215: false })) {
        throw new Error("signature verification failed");
      }
      return;
  }
}

/**
 * Tag parser for WebCrypto.
 */
export const webCryptoTryFromTags: TryFromTags<WebCrypto> = (tags: number[]) => {
  if (tags.length < 3) return null;

  const [first, second, third] = tags;
  const rest = tags.slice(3);

  switch (first) {
    case 0xec:
      if (second === 0x1200 && third === 0x12) return { config: new Es256(), rest };
      if (second === 0x1201 && third === 0x20) return { config: new Es384(), rest };
      if (second === 0x1202 && third === 0x13) return { config: new Es512(), rest };
      return null;
    case 0xed:
      if (second === 0xed && third === 0x13) return { config: new Ed25519(), rest };
      return null;
    default:
      return null;
  }
};
