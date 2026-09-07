/**
 * Delegation builder.
 */

import { DagCborCodec, Varsig } from "@marktripoli/varsig";
import type { AsyncDidSigner, Did, DidSigner } from "../did.js";
import { Command } from "../command.js";
import { Nonce } from "../crypto/nonce.js";
import type { Ipld } from "../ipld.js";
import { Timestamp } from "../time/index.js";
import { Unset } from "../unset.js";
import type { DelegatedSubject } from "./subject.js";
import { Delegation, delegationPayloadToIpld, type DelegationPayload } from "./index.js";
import type { Predicate } from "./policy/index.js";

type SupportedDidSigner = DidSigner | AsyncDidSigner;

export class DelegationBuilder<D extends SupportedDidSigner = DidSigner> {
  constructor(
    private readonly issuerField: D | typeof Unset = Unset,
    private readonly audienceField: Did | typeof Unset = Unset,
    private readonly subjectField: DelegatedSubject<Did> | typeof Unset = Unset,
    private readonly commandField: Command | typeof Unset = Unset,
    private readonly policyField: Predicate[] = [],
    private readonly expirationField: Timestamp | null = null,
    private readonly notBeforeField: Timestamp | null = null,
    private readonly metaField: Map<string, Ipld> = new Map(),
    private readonly nonceField: Nonce | null = null,
  ) {}

  issuer<S extends SupportedDidSigner>(issuer: S): DelegationBuilder<S> {
    return new DelegationBuilder<S>(
      issuer,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  audience(audience: Did): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      audience,
      this.subjectField,
      this.commandField,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  subject(subject: Did | DelegatedSubject<Did>): DelegationBuilder<D> {
    const nextSubject: DelegatedSubject<Did> =
      typeof subject === "object" && subject !== null && "kind" in subject
        ? (subject as DelegatedSubject<Did>)
        : ({ kind: "specific", did: subject as Did } as DelegatedSubject<Did>);

    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      nextSubject,
      this.commandField,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  command(command: Command): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      command,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  commandFromStr(s: string): DelegationBuilder<D> {
    return this.command(Command.parse(s));
  }

  policy(policy: Predicate[]): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      [...policy],
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  expiration(expiration: Timestamp): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.policyField,
      expiration,
      this.notBeforeField,
      this.metaField,
      this.nonceField,
    );
  }

  notBefore(notBefore: Timestamp): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.policyField,
      this.expirationField,
      notBefore,
      this.metaField,
      this.nonceField,
    );
  }

  meta(meta: Map<string, Ipld>): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      new Map(meta),
      this.nonceField,
    );
  }

  nonce(nonce: Nonce): DelegationBuilder<D> {
    return new DelegationBuilder<D>(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.policyField,
      this.expirationField,
      this.notBeforeField,
      this.metaField,
      nonce,
    );
  }

  issueNow(): DelegationBuilder<D> {
    return this.notBefore(Timestamp.now());
  }

  intoPayload(): DelegationPayload<Did> {
    const issuer = this.requireIssuer();
    const audience = this.requireAudience();
    const subject = this.requireSubject();
    const command = this.requireCommand();

    return {
      issuer: issuer.did,
      audience,
      subject,
      command,
      policy: [...this.policyField],
      expiration: this.expirationField,
      notBefore: this.notBeforeField,
      meta: new Map(this.metaField),
      nonce: this.nonceField ?? Nonce.generate16(),
    };
  }

  /**
   * Sign with a synchronous `DidSigner` (secret key bytes in hand).
   * For an `AsyncDidSigner` use `tryBuildAsync()`.
   */
  tryBuild(this: DelegationBuilder<DidSigner>): Delegation<Did> {
    const issuer = this.requireIssuer();
    if (!("signer" in issuer)) {
      throw new Error("issuer has no synchronous signer; use tryBuildAsync()");
    }
    const { payload, header, sigPayload } = this.signingInput(issuer);
    const { signature } = header.trySign(issuer.signer, sigPayload);
    return new Delegation<Did>({ signature, payload: { header, payload } });
  }

  /**
   * Sign with an `AsyncDidSigner` (e.g. a non-extractable Web Crypto key).
   * Produces bytes identical to `tryBuild()` for the same fields and key.
   */
  async tryBuildAsync(this: DelegationBuilder<AsyncDidSigner>): Promise<Delegation<Did>> {
    const issuer = this.requireIssuer();
    if (!("sign" in issuer)) {
      throw new Error("issuer has no asynchronous sign(); use tryBuild()");
    }
    const { payload, header, sigPayload } = this.signingInput(issuer);
    // Ed25519 (the only cryptosuite) implements AsyncSign; the generic Did type
    // only promises Sign, so the header's async signer type is not statically known.
    const { signature } = await header.trySignAsync(issuer.sign as never, sigPayload);
    return new Delegation<Did>({ signature, payload: { header, payload } });
  }

  /** The exact bytes both build paths sign: shared so they cannot diverge. */
  private signingInput(issuer: D) {
    const payload = this.intoPayload();
    const header = new Varsig(issuer.did.varsigConfig, DagCborCodec);
    const sigPayload = new Map<string, Ipld>([
      ["h", header.encode()],
      ["ucan/dlg@1.0.0", delegationPayloadToIpld(payload)],
    ]);
    return { payload, header, sigPayload };
  }

  private requireIssuer(): D {
    if (this.issuerField === Unset) {
      throw new Error("missing required field: issuer");
    }
    return this.issuerField;
  }

  private requireAudience(): Did {
    if (this.audienceField === Unset) {
      throw new Error("missing required field: audience");
    }
    return this.audienceField;
  }

  private requireSubject(): DelegatedSubject<Did> {
    if (this.subjectField === Unset) {
      throw new Error("missing required field: subject");
    }
    return this.subjectField;
  }

  private requireCommand(): Command {
    if (this.commandField === Unset) {
      throw new Error("missing required field: command");
    }
    return this.commandField;
  }
}
