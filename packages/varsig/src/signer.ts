import type { Codec } from "./codec.js";
import type { Ipld } from "./ipld.js";
import type { Verify } from "./verify.js";

/**
 * Synchronous signing trait.
 *
 * Extends `Verify`. Provides `trySign` for signing a payload.
 */
export interface Sign<Verifier = unknown, Signer = unknown>
  extends Verify<Verifier> {
  /**
   * Synchronously sign a payload.
   *
   * Encodes the payload with the given codec, then signs the encoded bytes.
   * Returns the raw signature bytes and the encoded payload.
   */
  trySign(
    codec: Codec,
    signer: Signer,
    payload: Ipld,
  ): { signature: Uint8Array; encoded: Uint8Array };
}

/**
 * Asynchronous signing trait.
 *
 * Extends `Verify`. Provides `trySignAsync` for signing a payload
 * with an async signer (e.g. Web Crypto keys).
 */
export interface AsyncSign<Verifier = unknown, AsyncSigner = unknown>
  extends Verify<Verifier> {
  /**
   * Asynchronously sign a payload.
   *
   * Encodes the payload with the given codec, then signs the encoded bytes.
   * Returns the raw signature bytes and the encoded payload.
   */
  trySignAsync(
    codec: Codec,
    signer: AsyncSigner,
    payload: Ipld,
  ): Promise<{ signature: Uint8Array; encoded: Uint8Array }>;
}

/**
 * Signing error.
 *
 * Mirrors Rust `SignerError` enum.
 */
export class SignerError extends Error {
  reason: "encodingError" | "signingError" | "varsigError";

  constructor(
    reason: "encodingError" | "signingError" | "varsigError",
    msg?: string,
  ) {
    super(msg ?? reason);
    this.reason = reason;
    this.name = "SignerError";
  }
}

/**
 * Extract the Signer type from a Sign implementation.
 */
export type SignerOf<V> = V extends Sign<any, infer S> ? S : never;

/**
 * Extract the AsyncSigner type from an AsyncSign implementation.
 */
export type AsyncSignerOf<V> = V extends AsyncSign<any, infer S> ? S : never;

/**
 * Default trySign implementation (Rust's default `Sign::try_sign` body).
 *
 * Encodes the payload with the codec, then signs the encoded bytes with
 * the provided `signFn`. Used by all implementations as the standard
 * sign pipeline.
 */
export function defaultTrySign(
  codec: Codec,
  signFn: (msg: Uint8Array) => Uint8Array,
  payload: Ipld,
): { signature: Uint8Array; encoded: Uint8Array } {
  let buffer: Uint8Array;
  try {
    buffer = codec.encodePayload(payload);
  } catch (e) {
    throw new SignerError("encodingError", String(e));
  }
  let signature: Uint8Array;
  try {
    signature = signFn(buffer);
  } catch (e) {
    throw new SignerError("signingError", String(e));
  }
  return { signature, encoded: buffer };
}

/**
 * Default asynchronous trySign implementation.
 *
 * Encodes the payload with the codec, then signs the encoded bytes with
 * the provided async sign function.
 */
export async function defaultTrySignAsync(
  codec: Codec,
  signFn: (msg: Uint8Array) => Promise<Uint8Array>,
  payload: Ipld,
): Promise<{ signature: Uint8Array; encoded: Uint8Array }> {
  let buffer: Uint8Array;
  try {
    buffer = codec.encodePayload(payload);
  } catch (e) {
    throw new SignerError("encodingError", String(e));
  }
  let signature: Uint8Array;
  try {
    signature = await signFn(buffer);
  } catch (e) {
    throw new SignerError("signingError", String(e));
  }
  return { signature, encoded: buffer };
}