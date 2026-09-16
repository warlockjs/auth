import type { Request } from "@warlock.js/core";
import { InvalidPasskeyError } from "../errors/invalid-passkey.error";
import type { Auth } from "../models/auth.model";
import type { OneTimeToken, OneTimeTokenPurpose } from "../models/one-time-token";
import { authConfig } from "../services/auth-config";
import { hashOneTimeToken, oneTimeTokenModel } from "../services/one-time-tokens";
import type { PasskeyResponseJSON } from "./simplewebauthn";

/** Which ceremony a challenge belongs to. */
export type PasskeyCeremony = Extract<
  OneTimeTokenPurpose,
  "passkey-registration" | "passkey-authentication"
>;

/**
 * Store a ceremony challenge server-side: SHA-256 hashed, purpose-bound,
 * expiring (`auth.passkeys.challengeExpiresIn`, default 5m). A registration
 * challenge is bound to its user; an authentication challenge has none.
 */
export async function storePasskeyChallenge(
  ceremony: PasskeyCeremony,
  challenge: string,
  user?: Auth,
): Promise<void> {
  const expiresAt = new Date(Date.now() + authConfig.passkeys.challengeExpiresInMs());

  await oneTimeTokenModel().issueChallenge(ceremony, hashOneTimeToken(challenge), expiresAt, user);
}

/** The challenge the browser signed, read from `clientDataJSON`. */
function signedChallenge(credential: PasskeyResponseJSON): string {
  try {
    const clientData = JSON.parse(
      Buffer.from(credential.response.clientDataJSON, "base64url").toString("utf8"),
    ) as { challenge?: unknown };

    if (typeof clientData.challenge === "string" && clientData.challenge.length > 0) {
      return clientData.challenge;
    }
  } catch {
    // fall through to the rejection
  }

  throw new InvalidPasskeyError("malformed-client-data");
}

/**
 * Consume the challenge a credential response signed. It is consumed BEFORE
 * the signature is verified, so a challenge is single-use even when that
 * verification fails. Unknown, other-ceremony, expired and already-used
 * challenges all throw {@link InvalidPasskeyError}.
 */
export async function takePasskeyChallenge(
  ceremony: PasskeyCeremony,
  credential: PasskeyResponseJSON,
): Promise<{ challenge: string; row: OneTimeToken }> {
  const challenge = signedChallenge(credential);
  const row = await oneTimeTokenModel().findByHash(hashOneTimeToken(challenge), ceremony);

  if (!row || row.isConsumed || row.isExpired) {
    throw new InvalidPasskeyError("unknown-or-expired-challenge");
  }

  if (!(await row.consumeIfActive())) {
    throw new InvalidPasskeyError("challenge-already-used");
  }

  return { challenge, row };
}

/**
 * CSRF rule for a passkey verify: the request's `Origin` header must be one
 * of `auth.passkeys.origin`. The same list is what the signed
 * `clientDataJSON.origin` is checked against.
 */
export function assertPasskeyOrigin(request: Request): string[] {
  const origins = authConfig.passkeys.origins();
  const origin = request.origin;

  if (typeof origin !== "string" || !origins.includes(origin)) {
    throw new InvalidPasskeyError("origin-mismatch");
  }

  return origins;
}
