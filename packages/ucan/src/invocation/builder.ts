/**
 * Invocation builder.
 */

import type { CID } from "multiformats/cid";
import { DagCborCodec, Varsig } from "@marktripoli/varsig";
import type { AsyncSign } from "@marktripoli/varsig";
import type { AsyncDidSigner, DidSigner } from "../did.js";
import { Command } from "../command.js";
import { Nonce } from "../crypto/nonce.js";
import type { Ipld } from "../ipld.js";
import { Timestamp } from "../time/index.js";
import { Unset } from "../unset.js";
import { Invocation, invocationPayloadToIpld, type InvocationPayload } from "./index.js";

type SupportedDidSigner = DidSigner | AsyncDidSigner;
type AsyncSignCallback = (bytes: Uint8Array) => Promise<Uint8Array>;

export class InvocationBuilder<D extends SupportedDidSigner = DidSigner> {
  constructor(
    public issuerField: D | typeof Unset = Unset,
    public audienceField: D["did"] | typeof Unset = Unset,
    public subjectField: D["did"] | typeof Unset = Unset,
    public commandField: Command | typeof Unset = Unset,
    public argumentsField: Map<string, Ipld> = new Map(),
    public proofsField: CID[] | typeof Unset = Unset,
    public cause: CID | null = null,
    public expirationField: Timestamp | null = null,
    public issuedAtField: Timestamp | null = null,
    public metaField: Map<string, Ipld> = new Map(),
    public nonceField: Nonce | null = null,
  ) {}

  issuer<S extends SupportedDidSigner>(issuer: S): InvocationBuilder<S> {
    return new InvocationBuilder<S>(
      issuer,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  audience(audience: D["did"]): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      audience,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  subject(subject: D["did"]): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      subject,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  command(command: Command): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      command,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  commandFromStr(s: string): InvocationBuilder<D> {
    return this.command(Command.parse(s));
  }

  arguments(argumentsValue: Map<string, Ipld>): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      new Map(argumentsValue),
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  proofs(proofs: CID[]): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      [...proofs],
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  expiration(expiration: Timestamp): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      expiration,
      this.issuedAtField,
      this.metaField,
      this.nonceField,
    );
  }

  issuedAt(issuedAt: Timestamp): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      issuedAt,
      this.metaField,
      this.nonceField,
    );
  }

  issueNow(): InvocationBuilder<D> {
    return this.issuedAt(Timestamp.now());
  }

  meta(meta: Map<string, Ipld>): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      new Map(meta),
      this.nonceField,
    );
  }

  nonce(nonce: Nonce): InvocationBuilder<D> {
    return new InvocationBuilder(
      this.issuerField,
      this.audienceField,
      this.subjectField,
      this.commandField,
      this.argumentsField,
      this.proofsField,
      this.cause,
      this.expirationField,
      this.issuedAtField,
      this.metaField,
      nonce,
    );
  }

  build(): InvocationPayload<D["did"]> {
    return this.intoPayload();
  }

  tryBuild(): Invocation<D["did"]> {
    const issuer = this.requireIssuer();
    const payload = this.intoPayload();
    const header = new Varsig(issuer.did.varsigConfig, DagCborCodec);
    const sigPayload = new Map<string, Ipld>([
      ["h", header.encode()],
      ["ucan/inv@1.0.0", invocationPayloadToIpld(payload)],
    ]);
    const syncIssuer = issuer as DidSigner;
    const { signature } = syncIssuer.did.varsigConfig.trySign(
      DagCborCodec,
      syncIssuer.signer as never,
      sigPayload,
    );

    return new Invocation({
      signature,
      payload: {
        header,
        payload,
      },
    });
  }

  async tryBuildAsync(): Promise<Invocation<D["did"]>> {
    const issuer = this.requireIssuer();
    if (!("sign" in issuer)) {
      throw new Error("async signer required");
    }
    const payload = this.intoPayload();
    const header = new Varsig(issuer.did.varsigConfig, DagCborCodec);
    const sigPayload = new Map<string, Ipld>([
      ["h", header.encode()],
      ["ucan/inv@1.0.0", invocationPayloadToIpld(payload)],
    ]);
    const signCfg = issuer.did.varsigConfig as unknown as AsyncSign<
      unknown,
      AsyncSignCallback
    >;
    const { signature } = await signCfg.trySignAsync(
      DagCborCodec,
      issuer.sign,
      sigPayload,
    );

    return new Invocation({
      signature,
      payload: {
        header,
        payload,
      },
    });
  }

  private intoPayload(): InvocationPayload<D["did"]> {
    const issuer = this.requireIssuer();
    const audience = this.requireAudience();
    const subject = this.requireSubject();
    const command = this.requireCommand();
    const proofs = this.requireProofs();

    return {
      issuer: issuer.did,
      audience,
      subject,
      command,
      arguments: new Map(this.argumentsField),
      proofs: [...proofs],
      cause: this.cause,
      expiration: this.expirationField,
      issuedAt: this.issuedAtField,
      meta: new Map(this.metaField),
      nonce: this.nonceField ?? Nonce.generate16(),
    };
  }

  private requireIssuer(): D {
    if (this.issuerField === Unset) {
      throw new Error("missing required field: issuer");
    }
    return this.issuerField;
  }

  private requireAudience(): D["did"] {
    if (this.audienceField === Unset) {
      throw new Error("missing required field: audience");
    }
    return this.audienceField;
  }

  private requireSubject(): D["did"] {
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

  private requireProofs(): CID[] {
    if (this.proofsField === Unset) {
      throw new Error("missing required field: proofs");
    }
    return this.proofsField;
  }
}
