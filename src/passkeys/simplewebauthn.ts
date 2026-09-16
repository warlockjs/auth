import { loadOptionalPeer } from "../services/optional-peer";

/** The `warlock add` feature that installs `@simplewebauthn/server`. */
export const PASSKEYS_FEATURE = "auth-passkeys";

/** The browser's JSON-serialized credential (`startRegistration` / `startAuthentication` result). */
export type PasskeyResponseJSON = {
  id: string;
  rawId: string;
  type: string;
  response: {
    clientDataJSON: string;
    transports?: string[];
    [key: string]: unknown;
  };
  [key: string]: unknown;
};

/** Options JSON handed to the browser; `challenge` is what auth stores. */
export type PasskeyOptionsJSON = {
  challenge: string;
  [key: string]: unknown;
};

/** A stored credential in the shape `@simplewebauthn/server` verifies against. */
export type WebAuthnCredential = {
  id: string;
  publicKey: Uint8Array;
  counter: number;
  transports?: string[];
};

/**
 * The slice of `@simplewebauthn/server` (v13) auth uses — declared locally
 * because the package is an optional peer.
 */
export type SimpleWebAuthnServer = {
  generateRegistrationOptions: (options: Record<string, unknown>) => Promise<PasskeyOptionsJSON>;
  verifyRegistrationResponse: (options: Record<string, unknown>) => Promise<{
    verified: boolean;
    registrationInfo?: { credential: WebAuthnCredential };
  }>;
  generateAuthenticationOptions: (options: Record<string, unknown>) => Promise<PasskeyOptionsJSON>;
  verifyAuthenticationResponse: (options: Record<string, unknown>) => Promise<{
    verified: boolean;
    authenticationInfo: { newCounter: number };
  }>;
};

/** Load `@simplewebauthn/server`, or throw `AuthProviderSdkMissingError` naming `warlock add auth-passkeys`. */
export function loadSimpleWebAuthn(): Promise<SimpleWebAuthnServer> {
  return loadOptionalPeer<SimpleWebAuthnServer>("@simplewebauthn/server", PASSKEYS_FEATURE);
}
