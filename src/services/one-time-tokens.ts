import { config } from "@warlock.js/core";
import { createHash, randomBytes } from "node:crypto";
import { InvalidOneTimeTokenError } from "../errors/invalid-one-time-token.error";
import type { Auth } from "../models/auth.model";
import { OneTimeToken, type OneTimeTokenPurpose } from "../models/one-time-token";

/** The raw token handed to the notification, with its expiry. */
export type IssuedOneTimeToken = {
  token: string;
  expiresAt: Date;
};

/** Resolve the active one-time-token model — the default or `auth.oneTimeToken.model`. */
export function oneTimeTokenModel(): typeof OneTimeToken {
  return config.key("auth.oneTimeToken.model", OneTimeToken);
}

/** SHA-256 hex digest of a raw one-time token — the only form ever persisted. */
export function hashOneTimeToken(token: string): string {
  return createHash("sha256").update(token).digest("hex");
}

/**
 * Create and persist a one-time token for the user: 32 random bytes,
 * base64url-encoded. Only the hash reaches storage.
 *
 * @param invalidatePrevious - consume the user's still-unused tokens of the
 *   same purpose first (password reset: only the newest link works).
 */
export async function issueOneTimeToken(
  user: Auth,
  purpose: OneTimeTokenPurpose,
  expiresInMs: number,
  invalidatePrevious = false,
): Promise<IssuedOneTimeToken> {
  const Model = oneTimeTokenModel();

  if (invalidatePrevious) {
    await Model.invalidateActiveFor(user, purpose);
  }

  const token = randomBytes(32).toString("base64url");
  const expiresAt = new Date(Date.now() + expiresInMs);

  await Model.issue(user, purpose, hashOneTimeToken(token), expiresAt);

  return { token, expiresAt };
}

/**
 * Consume a raw one-time token of the given purpose and resolve its user.
 *
 * Unknown, other-purpose, expired, already-consumed, lost-the-race and
 * orphaned (user gone) tokens all throw the same {@link InvalidOneTimeTokenError}.
 * The consume is a conditional update, so of N concurrent callers exactly one
 * proceeds.
 */
export async function consumeOneTimeToken(
  rawToken: string,
  purpose: OneTimeTokenPurpose,
): Promise<Auth> {
  if (typeof rawToken !== "string" || rawToken.length === 0) {
    throw new InvalidOneTimeTokenError();
  }

  const row = await oneTimeTokenModel().findByHash(hashOneTimeToken(rawToken), purpose);

  if (!row || row.isConsumed || row.isExpired) {
    throw new InvalidOneTimeTokenError();
  }

  const UserModel = config.key(`auth.userType.${row.userType}`);

  if (!UserModel) {
    throw new Error(`User type ${row.userType} is unknown type.`);
  }

  const user = (await UserModel.find(row.userId)) as Auth | null;

  if (!user) {
    throw new InvalidOneTimeTokenError();
  }

  if (!(await row.consumeIfActive())) {
    throw new InvalidOneTimeTokenError();
  }

  return user;
}
