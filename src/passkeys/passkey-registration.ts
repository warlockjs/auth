import type { Request } from "@warlock.js/core";
import { InvalidPasskeyError } from "../errors/invalid-passkey.error";
import type { Auth } from "../models/auth.model";
import { PasskeyCredential } from "../models/passkey-credential";
import { authConfig } from "../services/auth-config";
import {
  assertPasskeyOrigin,
  storePasskeyChallenge,
  takePasskeyChallenge,
} from "./passkey-challenges";
import {
  loadSimpleWebAuthn,
  type PasskeyOptionsJSON,
  type PasskeyResponseJSON,
} from "./simplewebauthn";

/** Account name the authenticator shows: `auth.passkeys.userName`, else email, else id. */
function passkeyUserName(user: Auth): string {
  const configured = authConfig.passkeys.settings().userName;

  if (configured) return configured(user);

  const email = user.get("email");

  return typeof email === "string" && email ? email : String(user.id);
}

/**
 * Registration options for a LOGGED-IN user adding a passkey. The challenge is
 * stored single-use and bound to this user; the user's existing credentials
 * are excluded so the same authenticator is not registered twice.
 *
 * @example
 * // POST /auth/passkeys/register/options  (authMiddleware)
 * response.success(await generatePasskeyRegistrationOptions(request.locals.user));
 */
export async function generatePasskeyRegistrationOptions(user: Auth): Promise<PasskeyOptionsJSON> {
  const webauthn = await loadSimpleWebAuthn();
  const settings = authConfig.passkeys.settings();
  const existing = await PasskeyCredential.listFor(user);

  const options = await webauthn.generateRegistrationOptions({
    rpName: settings.rpName,
    rpID: settings.rpID,
    userName: passkeyUserName(user),
    userID: new TextEncoder().encode(`${user.userType}:${user.id}`),
    attestationType: "none",
    excludeCredentials: existing.map((credential) => ({
      id: credential.credentialId,
      transports: credential.get("transports") ?? undefined,
    })),
    authenticatorSelection: { residentKey: "preferred", userVerification: "preferred" },
  });

  await storePasskeyChallenge("passkey-registration", options.challenge, user);

  return options;
}

/**
 * Verify the browser's registration response and store the credential.
 * Checks, in order: the request `Origin` (CSRF), the single-use challenge
 * (consumed even if what follows fails) belongs to THIS user, then the
 * attestation via `@simplewebauthn/server` against the configured origins and
 * rpID.
 *
 * @throws InvalidPasskeyError (400, EC011) on any rejection.
 */
export async function verifyPasskeyRegistration(
  request: Request,
  user: Auth,
  credential: PasskeyResponseJSON,
): Promise<PasskeyCredential> {
  const webauthn = await loadSimpleWebAuthn();
  const origins = assertPasskeyOrigin(request);
  const { challenge, row } = await takePasskeyChallenge("passkey-registration", credential);

  if (String(row.userId) !== String(user.id) || row.userType !== user.userType) {
    throw new InvalidPasskeyError("challenge-issued-to-another-user");
  }

  let verification: Awaited<ReturnType<typeof webauthn.verifyRegistrationResponse>>;

  try {
    verification = await webauthn.verifyRegistrationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: origins,
      expectedRPID: authConfig.passkeys.settings().rpID,
      requireUserVerification: false,
    });
  } catch (error) {
    throw new InvalidPasskeyError("registration-verification-failed", error);
  }

  if (!verification.verified || !verification.registrationInfo) {
    throw new InvalidPasskeyError("registration-not-verified");
  }

  const { id, publicKey, counter, transports } = verification.registrationInfo.credential;

  if (await PasskeyCredential.findByCredentialId(id)) {
    throw new InvalidPasskeyError("credential-already-registered");
  }

  return PasskeyCredential.create({
    credential_id: id,
    public_key: Buffer.from(publicKey).toString("base64url"),
    counter,
    transports: transports ?? credential.response.transports ?? [],
    user_id: user.id,
    user_type: user.userType,
  });
}
