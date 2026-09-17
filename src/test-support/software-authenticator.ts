import { createHash, generateKeyPairSync, randomBytes, sign, type KeyObject } from "node:crypto";
import type { PasskeyResponseJSON } from "../passkeys/simplewebauthn";

/**
 * Spec-only WebAuthn authenticator built on `node:crypto`: an ES256 (P-256)
 * key pair, `none` attestation, and assertions signed exactly as the WebAuthn
 * Level 2 spec lays out (`authenticatorData || SHA-256(clientDataJSON)`). It
 * lets specs drive the REAL `@simplewebauthn/server` verifier end to end.
 */

type CborValue = number | string | Uint8Array | CborValue[] | Map<CborValue, CborValue>;

/** CBOR header: major type + argument (RFC 8949 §3). */
function cborHead(major: number, length: number): Buffer {
  if (length < 24) return Buffer.from([(major << 5) | length]);
  if (length < 0x100) return Buffer.from([(major << 5) | 24, length]);
  if (length < 0x10000) {
    const head = Buffer.alloc(3);
    head[0] = (major << 5) | 25;
    head.writeUInt16BE(length, 1);

    return head;
  }

  const head = Buffer.alloc(5);
  head[0] = (major << 5) | 26;
  head.writeUInt32BE(length, 1);

  return head;
}

/** Minimal canonical CBOR encoder — the subset attestation objects and COSE keys use. */
function cbor(value: CborValue): Buffer {
  if (typeof value === "number") {
    return value >= 0 ? cborHead(0, value) : cborHead(1, -1 - value);
  }

  if (typeof value === "string") {
    const bytes = Buffer.from(value, "utf8");

    return Buffer.concat([cborHead(3, bytes.length), bytes]);
  }

  if (value instanceof Uint8Array) {
    return Buffer.concat([cborHead(2, value.length), Buffer.from(value)]);
  }

  if (Array.isArray(value)) {
    return Buffer.concat([cborHead(4, value.length), ...value.map(cbor)]);
  }

  const parts: Buffer[] = [cborHead(5, value.size)];

  for (const [key, item] of value) {
    parts.push(cbor(key), cbor(item));
  }

  return Buffer.concat(parts);
}

const FLAG_USER_PRESENT = 0x01;
const FLAG_USER_VERIFIED = 0x04;
const FLAG_ATTESTED_DATA = 0x40;

const sha256 = (data: Buffer | string) => createHash("sha256").update(data).digest();

const b64url = (data: Buffer | Uint8Array) => Buffer.from(data).toString("base64url");

export type SoftwareAuthenticatorOptions = {
  rpID: string;
  origin: string;
};

/**
 * One software passkey. `counter` is the signature counter the NEXT assertion
 * reports; set it directly to simulate a cloned authenticator.
 */
export class SoftwareAuthenticator {
  public readonly credentialId: Buffer = randomBytes(16);

  public counter = 0;

  private readonly privateKey: KeyObject;

  private readonly publicJwk: { x: string; y: string };

  public constructor(private readonly options: SoftwareAuthenticatorOptions) {
    const { privateKey, publicKey } = generateKeyPairSync("ec", { namedCurve: "P-256" });

    this.privateKey = privateKey;
    this.publicJwk = publicKey.export({ format: "jwk" }) as { x: string; y: string };
  }

  /** base64url credential id, as the browser reports it. */
  public get id(): string {
    return b64url(this.credentialId);
  }

  private clientData(type: "webauthn.create" | "webauthn.get", challenge: string): Buffer {
    return Buffer.from(
      JSON.stringify({ type, challenge, origin: this.options.origin, crossOrigin: false }),
    );
  }

  private authenticatorData(flags: number, attested?: Buffer): Buffer {
    const counter = Buffer.alloc(4);
    counter.writeUInt32BE(this.counter, 0);

    return Buffer.concat([
      sha256(this.options.rpID),
      Buffer.from([flags]),
      counter,
      ...(attested ? [attested] : []),
    ]);
  }

  /** A `navigator.credentials.create()` response (`none` attestation) for `challenge`. */
  public register(challenge: string): PasskeyResponseJSON {
    const coseKey = cbor(
      new Map<CborValue, CborValue>([
        [1, 2], // kty: EC2
        [3, -7], // alg: ES256
        [-1, 1], // crv: P-256
        [-2, Buffer.from(this.publicJwk.x, "base64url")],
        [-3, Buffer.from(this.publicJwk.y, "base64url")],
      ]),
    );

    const idLength = Buffer.alloc(2);
    idLength.writeUInt16BE(this.credentialId.length, 0);

    const attested = Buffer.concat([Buffer.alloc(16), idLength, this.credentialId, coseKey]);
    const authData = this.authenticatorData(
      FLAG_USER_PRESENT | FLAG_USER_VERIFIED | FLAG_ATTESTED_DATA,
      attested,
    );

    const attestationObject = cbor(
      new Map<CborValue, CborValue>([
        ["fmt", "none"],
        ["attStmt", new Map()],
        ["authData", authData],
      ]),
    );

    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(this.clientData("webauthn.create", challenge)),
        attestationObject: b64url(attestationObject),
        transports: ["internal"],
      },
    };
  }

  /** A `navigator.credentials.get()` response signing `challenge` with the current counter. */
  public authenticate(challenge: string): PasskeyResponseJSON {
    const clientDataJSON = this.clientData("webauthn.get", challenge);
    const authData = this.authenticatorData(FLAG_USER_PRESENT | FLAG_USER_VERIFIED);
    const signature = sign("sha256", Buffer.concat([authData, sha256(clientDataJSON)]), {
      key: this.privateKey,
      dsaEncoding: "der",
    });

    return {
      id: this.id,
      rawId: this.id,
      type: "public-key",
      clientExtensionResults: {},
      response: {
        clientDataJSON: b64url(clientDataJSON),
        authenticatorData: b64url(authData),
        signature: b64url(signature),
      },
    };
  }
}
