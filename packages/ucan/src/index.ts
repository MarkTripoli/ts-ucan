/**
 * UCAN — User-Controlled Authorization Networks
 *
 * This is the primary entry point for the ucan library.
 * It re-exports all public APIs from submodules.
 */

// Core types and utilities
export type { Ipld } from "./ipld.js";
export { ipldFromDagCbor, ipldToDagCbor, ipldEquals, bytesEqual, ipldEqualsWithFloatNansAndInfinities } from "./ipld.js";

// CID
export { toDagCborCid } from "./cid.js";

// Collections
export type { UcanMap, UcanSet } from "./collections.js";
export type { Collection } from "./collection.js";
export {
  collectionToVec,
  collectionIsEmpty,
  collectionToIpld,
  collectionToWireIpld,
  wireIpldToCollection,
  collectionFromIterable,
} from "./collection.js";

// Command
export { Command } from "./command.js";
export { CommandParseError } from "./command.js";
export type { CommandParseErrorReason } from "./command.js";

// Time
export { Timestamp } from "./time/index.js";
export {
  OutOfRangeError,
  NumberIsNotATimestampError,
  TimeBoundError,
  ExpiredError,
  TimestampFromIpldError,
} from "./time/index.js";

// Crypto
export { Nonce } from "./crypto/nonce.js";
export { NoncesMustBeBytesError } from "./crypto/nonce.js";

// Number
export type { UcanNumber } from "./number.js";
export { numberCompare, numberFromIpld, numberToIpld, NotANumberError } from "./number.js";

// Promise
export type { Promise_, Promised } from "./promise.js";
export {
  promisedToIpld,
  ipldToPromised,
  promisedToWireIpld,
  wireIpldToPromised,
  promiseToWireIpld,
  wireIpldToPromise,
  WaitingOnError,
} from "./promise.js";

// DID
export type { Did, DidSigner, AsyncDidSigner } from "./did.js";
export { Ed25519Did, Ed25519Signer, Ed25519DidFromStrError } from "./did.js";
export type { Ed25519DidFromStrErrorReason, VarsigConfigOf } from "./did.js";

// Unset & sealed (builder type markers)
export { Unset } from "./unset.js";
export type { DidOrUnset, DidSignerOrUnset, DelegatedSubjectOrUnset, CommandOrUnset, ProofsOrUnset } from "./sealed.js";

// Envelope
export type {
  EnvelopePayload,
  Envelope,
  PayloadTag,
} from "./envelope/index.js";
export { tagOf } from "./envelope/index.js";
export {
  envelopeToIpld,
  envelopeFromIpld,
} from "./envelope/index.js";

// Delegation
export type {
  DelegatedSubject,
  DelegationPayload,
} from "./delegation/index.js";
export {
  Delegation,
  delegationPayloadTag,
  subjectAllows,
  subjectCoherent,
  subjectToString,
  subjectToIpld,
  ipldToSubject,
  delegationPayloadToIpld,
  ipldToDelegationPayload,
} from "./delegation/index.js";
export { DelegationBuilder } from "./delegation/builder.js";
export type { DelegationStore } from "./delegation/store.js";
export { MapDelegationStore, insert, MissingError } from "./delegation/store.js";

// Policy
export type {
  Predicate,
  Filter,
  Selectable,
} from "./delegation/policy/index.js";
export { Selector, SelectorError, Select } from "./delegation/policy/index.js";
export {
  runPredicate,
  glob,
  predicateToIpld,
  ipldToPredicate,
  RunError,
  FromIpldError,
  filterToString,
  parseFilter,
  filterIsIn,
  filterIsDotField,
  filterToIpld,
  ipldToFilter,
  filterParseError,
} from "./delegation/policy/index.js";

// Invocation
export type { InvocationPayload } from "./invocation/index.js";
export { Invocation, invocationPayloadTag, invocationPayloadToIpld, ipldToInvocationPayload, invocationPayloadToCid, check, checkResolved, timeBoundChecks, syntaticChecks, CheckFailed, StoredCheckError } from "./invocation/index.js";
export { InvocationBuilder } from "./invocation/builder.js";
export { verifyInvocation, VerifyError, MapReplayStore } from "./invocation/verify.js";
export type { ReplayStore } from "./invocation/verify.js";

// Revocation
export {
  REVOKE_COMMAND,
  revoke,
  revokeAsync,
  MapRevocationStore,
  RevokedError,
  InvalidRevocationError,
  assertValidRevocation,
  checkWithRevocations,
  checkRevocations,
} from "./revocation/index.js";
export type { RevocationStore } from "./revocation/index.js";

// Container
export {
  ContainerHeader,
  containerToBytes,
  containerFromBytes,
  containerToBase64StdPadding,
  containerToBase64Url,
} from "./container/index.js";
export type { CompressionAlgorithm, BaseEncoding, ContainerOptions } from "./container/index.js";
