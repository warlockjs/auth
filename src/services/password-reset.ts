import type { ChildModel } from "@warlock.js/cascade";
import type { Auth } from "../models/auth.model";
import { authConfig } from "./auth-config";
import { authEvents } from "./auth-events";
import { authService } from "./auth.service";
import { consumeOneTimeToken, issueOneTimeToken } from "./one-time-tokens";
import { resolveTokenNotification } from "./token-notifications";

/**
 * Default password writer. Login verifies with `authService.verifyPassword`,
 * so that is the authority on what "stored correctly" means:
 *
 * 1. Save `hashPassword(plain)` — right for a model that stores what it's given.
 * 2. If that no longer verifies, the model hashed on save (core's
 *    `useHashedPassword()`), double-hashing it: save the plaintext so the
 *    model's own transformer hashes it once.
 * 3. Still not verifiable ⇒ throw. Never leave a reset that "succeeded" with a
 *    password nobody can log in with.
 *
 * The first write is always a hash, so a model without a transformer never
 * has plaintext written.
 */
async function writePassword(user: Auth, plainPassword: string): Promise<void> {
  await user.merge({ password: await authService.hashPassword(plainPassword) } as never).save();

  if (await authService.verifyPassword(plainPassword, user.string("password") ?? "")) return;

  await user.merge({ password: plainPassword } as never).save();

  const stored = user.string("password") ?? "";

  if (stored !== plainPassword && (await authService.verifyPassword(plainPassword, stored))) {
    return;
  }

  throw new Error(
    "@warlock.js/auth: resetPassword could not store a password that verifies — " +
      "set `auth.passwordReset.setPassword` to write it the way your user model expects.",
  );
}

/**
 * Start a password reset for the account whose `auth.passwordReset.identifierField`
 * (default `email`) equals `identifier`: invalidate the account's unused reset
 * tokens, issue a new one, and send it through the reset notification.
 *
 * **Anti-enumeration:** resolves `undefined` whether or not the account exists
 * — an unknown identifier simply sends nothing. Notification availability is
 * checked before the lookup, so a misconfigured app fails identically for both.
 *
 * @throws NotificationsUnavailableError when `@warlock.js/notifications` is not installed or not configured.
 *
 * @example
 * await requestPasswordReset(User, request.input("email"));
 * return response.success({ message: "If the account exists, we sent a reset link." });
 */
export async function requestPasswordReset<T extends Auth>(
  Model: ChildModel<T>,
  identifier: string,
): Promise<void> {
  const notification = await resolveTokenNotification("password-reset");

  if (typeof identifier !== "string" || identifier.length === 0) return;

  const user = (await Model.first({
    [authConfig.passwordReset.identifierField()]: identifier,
  })) as T | null;

  if (!user) return;

  const { token, expiresAt } = await issueOneTimeToken(
    user,
    "password-reset",
    authConfig.passwordReset.expiresInMs(),
    true,
  );

  authEvents.emit("password.resetRequested", user, token);

  const url = authConfig.passwordReset.url()?.(token, user);

  await notification.send(user, { token, expiresAt, ...(url ? { url } : {}) });
}

/**
 * Complete a password reset: consume the token, store the new password, then
 * revoke every access token, refresh token and cookie session the user holds
 * (`authService.revokeAllTokens`). Resolves to the user.
 *
 * Validate password strength BEFORE calling this — the token is consumed first.
 *
 * @throws InvalidOneTimeTokenError for an unknown, verification-purpose,
 *   expired, superseded or already-used token.
 */
export async function resetPassword(token: string, newPassword: string): Promise<Auth> {
  const user = await consumeOneTimeToken(token, "password-reset");

  const setPassword = authConfig.passwordReset.setPassword();

  if (setPassword) {
    await setPassword(user, newPassword);
  } else {
    await writePassword(user, newPassword);
  }

  await authService.revokeAllTokens(user);

  authEvents.emit("password.reset", user);

  return user;
}
