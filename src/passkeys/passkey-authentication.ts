import type { ChildModel } from "@warlock.js/cascade";
import { config, type Request } from "@warlock.js/core";
import type { DeviceInfo, LoginResult } from "../contracts/types";
import { InvalidPasskeyError } from "../errors/invalid-passkey.error";
import type { Auth } from "../models/auth.model";
import { PasskeyCredential } from "../models/passkey-credential";
import { authConfig } from "../services/auth-config";
import { authService } from "../services/auth.service";
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

/** A counter that did not advance past the stored one (when either is non-zero): a cloned authenticator. */
function counterRegressed(stored: number, presented: number | undefined): boolean {
  if (presented === undefined) return false;

  return (stored > 0 || presented > 0) && !(presented > stored);
}

/**
 * The signature counter an assertion CLAIMS (bytes 33–36 of authenticatorData).
 * Unverified — only used to label a rejection the SDK already made.
 */
function presentedCounter(credential: PasskeyResponseJSON): number | undefined {
  const encoded = credential.response.authenticatorData;

  if (typeof encoded !== "string") return undefined;

  const authData = Buffer.from(encoded, "base64url");

  return authData.length >= 37 ? authData.readUInt32BE(33) : undefined;
}

/**
 * Authentication options for a passkey login. No user is identified yet
 * (discoverable credentials), so the stored single-use challenge has no owner;
 * the credential the browser returns decides the user.
 *
 * @example
 * // POST /auth/passkeys/login/options
 * response.success(await generatePasskeyAuthenticationOptions());
 */
export async function generatePasskeyAuthenticationOptions(): Promise<PasskeyOptionsJSON> {
  const webauthn = await loadSimpleWebAuthn();

  const options = await webauthn.generateAuthenticationOptions({
    rpID: authConfig.passkeys.settings().rpID,
    userVerification: "preferred",
  });

  await storePasskeyChallenge("passkey-authentication", options.challenge);

  return options;
}

/**
 * Verify a passkey assertion and log its owner in through
 * `authService.completeLogin` — the same outcome as password login.
 *
 * Checks, in order: the request `Origin` (CSRF), the single-use challenge
 * (consumed even if what follows fails), the credential is registered, the
 * assertion via `@simplewebauthn/server`, then that the signature counter
 * ADVANCED — a counter that did not move past the stored one (when either is
 * non-zero) means a cloned authenticator and is rejected. The new counter is
 * written with a compare-and-set.
 *
 * @throws InvalidPasskeyError (400, EC011) on any rejection.
 */
export async function verifyPasskeyAuthentication(
  request: Request,
  credential: PasskeyResponseJSON,
  deviceInfo?: DeviceInfo,
): Promise<LoginResult<Auth>> {
  const webauthn = await loadSimpleWebAuthn();
  const origins = assertPasskeyOrigin(request);
  const { challenge } = await takePasskeyChallenge("passkey-authentication", credential);

  const stored =
    typeof credential.id === "string"
      ? await PasskeyCredential.findByCredentialId(credential.id)
      : null;

  if (!stored) {
    throw new InvalidPasskeyError("unknown-credential");
  }

  let verification: Awaited<ReturnType<typeof webauthn.verifyAuthenticationResponse>>;

  try {
    verification = await webauthn.verifyAuthenticationResponse({
      response: credential,
      expectedChallenge: challenge,
      expectedOrigin: origins,
      expectedRPID: authConfig.passkeys.settings().rpID,
      credential: {
        id: stored.credentialId,
        publicKey: new Uint8Array(Buffer.from(String(stored.get("public_key")), "base64url")),
        counter: stored.counter,
        transports: stored.get("transports") ?? undefined,
      },
      requireUserVerification: false,
    });
  } catch (error) {
    // The SDK enforces the counter rule itself and throws a generic Error for
    // it; keep clone detection visible as its own reason in the logs.
    const reason = counterRegressed(stored.counter, presentedCounter(credential))
      ? "counter-regression"
      : "authentication-verification-failed";

    throw new InvalidPasskeyError(reason, error);
  }

  if (!verification.verified) {
    throw new InvalidPasskeyError("authentication-not-verified");
  }

  const previous = stored.counter;
  const next = Number(verification.authenticationInfo.newCounter);

  if (counterRegressed(previous, next)) {
    throw new InvalidPasskeyError("counter-regression");
  }

  if (!(await stored.advanceCounter(previous, next))) {
    throw new InvalidPasskeyError("counter-changed-concurrently");
  }

  const UserModel = config.key<ChildModel<Auth> | undefined>(`auth.userType.${stored.userType}`);
  const user = UserModel ? ((await UserModel.find(stored.userId)) as Auth | null) : null;

  if (!user) {
    throw new InvalidPasskeyError("credential-owner-missing");
  }

  return authService.completeLogin(user, deviceInfo);
}
