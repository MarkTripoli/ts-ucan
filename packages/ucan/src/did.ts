/**
 * Decentralized Identifier (DID) helpers.
 */

import { ed25519 } from "@noble/curves/ed25519";
import { base58btc } from "multiformats/bases/base58";
import type { Sign } from "@marktripoli/varsig";
import { Ed25519 } from "@marktripoli/varsig";
import type { Ipld } from "./ipld.js";

/**
 * A trait for DIDs.
 */
export interface Did<V extends Sign<any, any> = Sign<any, any>> {
  readonly didMethod: string;
  readonly varsigConfig: V;
  toString(): string;
  equals(other: Did): boolean;
}

/**
 * A trait for DID signers.
 */
export interface DidSigner<D extends Did = Did> {
  readonly did: D;
  readonly signer: unknown;
}

/**
 * A DID signer backed by an asynchronous signing operation.
 */
export interface AsyncDidSigner<D extends Did = Did> {
  readonly did: D;
  sign(bytes: Uint8Array): Promise<Uint8Array>;
}

/**
 * An Ed25519 did:key.
 *
 * Format: did:key:z + base58btc of [0xed, 0x01, ...32 pubkey bytes]
 */
export class Ed25519Did implements Did<Ed25519> {
  readonly didMethod = "key";
  readonly varsigConfig: Ed25519;
  readonly publicKey: Uint8Array;

  constructor(publicKey: Uint8Array) {
    if (publicKey.length !== 32) {
      throw new Error("Ed25519 public key must be 32 bytes");
    }
    // fromBytes rejects non-canonical / off-curve encodings; isSmallOrder
    // rejects the small-order points (incl. identity) that allow a universal
    // forgery accepted by any signature. A legitimate key is large-prime order.
    const point = ed25519.Point.fromBytes(publicKey, true);
    if (point.isSmallOrder()) {
      throw new Error("Ed25519 public key is a small-order point");
    }
    this.publicKey = publicKey;
    this.varsigConfig = new Ed25519();
  }

  /**
   * Create from a secret key (32 bytes).
   */
  static fromSecretKey(secretKey: Uint8Array): Ed25519Did {
    const publicKey = ed25519.getPublicKey(secretKey);
    return new Ed25519Did(publicKey);
  }

  /**
   * Convert to DID string (did:key:z...).
   */
  toString(): string {
    const bytes = new Uint8Array(34);
    bytes[0] = 0xed;
    bytes[1] = 0x01;
    bytes.set(this.publicKey, 2);
    const b58 = base58btc.baseEncode(bytes);
    return `did:key:z${b58}`;
  }

  /**
   * Parse from DID string.
   */
  static fromString(s: string): Ed25519Did {
    const parts = s.split(":");
    if (parts.length !== 3 || parts[0] !== "did" || parts[1] !== "key") {
      throw new Ed25519DidFromStrError("invalidDidHeader");
    }

    const key = parts[2];
    if (!key.startsWith("z")) {
      throw new Ed25519DidFromStrError("missingBase58Prefix");
    }

    let decoded: Uint8Array;
    try {
      decoded = base58btc.baseDecode(key.slice(1));
    } catch {
      throw new Ed25519DidFromStrError("invalidBase58");
    }

    if (decoded.length !== 34) {
      throw new Ed25519DidFromStrError("invalidKey");
    }

    if (decoded[0] !== 0xed || decoded[1] !== 0x01) {
      throw new Ed25519DidFromStrError("invalidKey");
    }

    const publicKey = decoded.slice(2, 34);
    try {
      ed25519.Point.fromBytes(publicKey, true);
    } catch {
      throw new Ed25519DidFromStrError("invalidKey");
    }

    return new Ed25519Did(publicKey);
  }

  /**
   * Check equality.
   */
  equals(other: Did): boolean {
    if (!(other instanceof Ed25519Did)) return false;
    if (this.publicKey.length !== other.publicKey.length) return false;
    for (let i = 0; i < this.publicKey.length; i++) {
      if (this.publicKey[i] !== other.publicKey[i]) return false;
    }
    return true;
  }

  /**
   * Convert to IPLD.
   */
  toIpld(): string {
    return this.toString();
  }

  /**
   * Create from IPLD (string).
   */
  static fromIpld(ipld: Ipld): Ed25519Did {
    if (typeof ipld !== "string") {
      throw new Error("Expected string for Did");
    }
    return Ed25519Did.fromString(ipld);
  }
}

export type Ed25519DidFromStrErrorReason =
  | "invalidDidHeader"
  | "missingBase58Prefix"
  | "invalidBase58"
  | "invalidKey";

/**
 * Error thrown when parsing Ed25519Did from string.
 */
export class Ed25519DidFromStrError extends Error {
  constructor(readonly reason: Ed25519DidFromStrErrorReason) {
    const messages: Record<Ed25519DidFromStrErrorReason, string> = {
      invalidDidHeader: "invalid did header",
      missingBase58Prefix: "missing base58 prefix 'z'",
      invalidBase58: "invalid base58 encoding",
      invalidKey: "invalid key bytes",
    };
    super(messages[reason]);
    this.name = "Ed25519DidFromStrError";
  }
}

/**
 * An Ed25519 did:key signer.
 */
export class Ed25519Signer implements DidSigner<Ed25519Did> {
  readonly did: Ed25519Did;
  readonly signer: Uint8Array; // 32-byte secret key

  constructor(secretKey: Uint8Array) {
    if (secretKey.length !== 32) {
      throw new Error("Ed25519 secret key must be 32 bytes");
    }
    this.did = Ed25519Did.fromSecretKey(secretKey);
    this.signer = secretKey;
  }

  /**
   * Convert to string (delegates to DID).
   */
  toString(): string {
    return this.did.toString();
  }

  /**
   * Convert to IPLD / serialization form.
   */
  toIpld(): Ipld {
    return this.did.toIpld();
  }
}

/**
 * An Ed25519 did:key signer backed by an asynchronous callback.
 */
export class Ed25519AsyncSigner implements AsyncDidSigner<Ed25519Did> {
  readonly did: Ed25519Did;
  readonly sign: (bytes: Uint8Array) => Promise<Uint8Array>;

  constructor(
    did: Ed25519Did,
    sign: (bytes: Uint8Array) => Promise<Uint8Array>,
  ) {
    this.did = did;
    this.sign = sign;
  }

  toString(): string {
    return this.did.toString();
  }

  toIpld(): Ipld {
    return this.did.toIpld();
  }
}

/**
 * Extract the varsig config type of a Did.
 *
 * Mirrors Rust's D::VarsigConfig associated type.
 */
export type VarsigConfigOf<D extends Did> = D["varsigConfig"];
