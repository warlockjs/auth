import type { Auth } from "../models/auth.model";
import { authConfig } from "./auth-config";
import { consumeOneTimeToken, issueOneTimeToken } from "./one-time-tokens";
import { resolveTokenNotification } from "./token-notifications";

/**
 * Whether the user has verified their email — the configured
 * `auth.verification.field` (default `emailVerifiedAt`) holds a value.
 */
export function isEmailVerified(user: Pick<Auth, "get">): boolean {
  return !!user.get(authConfig.verification.field());
}

/**
 * Issue an email-verification token for the user and send it through the
 * verification notification (`auth.verification.notification`, else auth's
 * default mail). Earlier verification links keep working until they expire or
 * one of them is used.
 *
 * @throws NotificationsUnavailableError before any token is issued when
 *   `@warlock.js/notifications` is not installed or not configured.
 *
 * @example
 * const user = await User.create(data);
 * await sendEmailVerification(user);
 */
export async function sendEmailVerification(user: Auth): Promise<void> {
  const notification = await resolveTokenNotification("email-verification");

  const { token, expiresAt } = await issueOneTimeToken(
    user,
    "email-verification",
    authConfig.verification.expiresInMs(),
  );

  const url = authConfig.verification.url()?.(token, user);

  await notification.send(user, { token, expiresAt, ...(url ? { url } : {}) });
}

/**
 * Consume a verification token and stamp the user's verified field with the
 * current date. Resolves to the verified user.
 *
 * @throws InvalidOneTimeTokenError for an unknown, reset-purpose, expired or
 *   already-used token.
 * @throws Error when the save did not keep the field — the user schema must
 *   declare it (e.g. `emailVerifiedAt: v.date().optional()`).
 */
export async function verifyEmail(token: string): Promise<Auth> {
  const user = await consumeOneTimeToken(token, "email-verification");
  const field = authConfig.verification.field();

  await user.merge({ [field]: new Date() } as never).save();

  if (!isEmailVerified(user)) {
    throw new Error(
      `@warlock.js/auth: verifyEmail could not persist "${field}" on the user — ` +
        `declare it in the user schema (e.g. \`${field}: v.date().optional()\`) ` +
        "or set `auth.verification.field` to an existing attribute.",
    );
  }

  return user;
}
