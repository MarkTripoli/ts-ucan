import { ed25519 } from "@noble/curves/ed25519";
import { defaultTryVerify, VerificationError } from "../verify.js";
import type { AsyncSign, Sign } from "../signer.js";
import { defaultTrySign, defaultTrySignAsync } from "../signer.js";
import type { TryFromTags } from "../header.js";
import type { Codec } from "../codec.js";
import type { Ipld } from "../ipld.js";

/**
 * Ed25519 signature algorithm.
 *
 * Uses the Edwards25519 curve with SHA2-512 hashing (EdDSA).
 * Verifier = 32-byte public key. Signer = 32-byte secret key.
 */
export class Ed25519
  implements
    Sign<Uint8Array, Uint8Array>,
    AsyncSign<Uint8Array, (msg: Uint8Array) => Promise<Uint8Array>>
{
  prefix(): 0xed {
    return 0xed;
  }

  configTags(): [0xed, 0x13] {
    return [0xed, 0x13];
  }

  tryDecodeSignature(signature: Uint8Array): void {
    if (signature.length !== 64) {
      throw new Error("invalid signature bytes");
    }
  }

  tryVerify(
    codec: Codec,
    verifier: Uint8Array,
    signature: Uint8Array,
    payload: Ipld,
  ): void {
    defaultTryVerify(codec, verifier, signature, payload, (vk, msg, sig) => {
      // zip215:false enforces strict RFC 8032: rejects non-canonical encodings
      // and the small-order/malleable signatures that enable universal forgery.
      if (!ed25519.verify(sig, msg, vk as Uint8Array, { zip215: false })) {
        throw new VerificationError("verificationError", "signature verification failed");
      }
    });
  }

  trySign(
    codec: Codec,
    signer: Uint8Array,
    payload: Ipld,
  ): { signature: Uint8Array; encoded: Uint8Array } {
    return defaultTrySign(
      codec,
      (msg) => ed25519.sign(msg, signer),
      payload,
    );
  }

  trySignAsync(
    codec: Codec,
    signer: (msg: Uint8Array) => Promise<Uint8Array>,
    payload: Ipld,
  ): Promise<{ signature: Uint8Array; encoded: Uint8Array }> {
    return defaultTrySignAsync(codec, signer, payload);
  }
}

/**
 * Tag parser for Ed25519.
 *
 * Matches `[0xed, 0xed, 0x13]` (the signature prefix, then the two config tags).
 */
export const ed25519TryFromTags: TryFromTags<Ed25519> = (
  tags: number[],
) => {
  if (
    tags.length >= 3 &&
    tags[0] === 0xed &&
    tags[1] === 0xed &&
    tags[2] === 0x13
  ) {
    return { config: new Ed25519(), rest: tags.slice(3) };
  }
  return null;
};