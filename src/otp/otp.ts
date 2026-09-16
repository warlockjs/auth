import type { ChildModel } from "@warlock.js/cascade";
import { createHmac, randomBytes, randomInt } from "node:crypto";
import type { OtpMessage, OtpSender } from "../contracts/providers";
import type { DeviceInfo, LoginResult } from "../contracts/types";
import { InvalidOneTimeTokenError } from "../errors/invalid-one-time-token.error";
import type { Auth } from "../models/auth.model";
import { authConfig } from "../services/auth-config";
import { authService } from "../services/auth.service";
import { oneTimeTokenModel } from "../services/one-time-tokens";
import { loadOptionalPeer } from "../services/optional-peer";
import { safeEqual } from "../utils/safe-equal";

/** The slice of `@warlock.js/notifications` OTP delivery uses (an optional peer). */
type NotifyModule = {
  notify: {
    channel: (name: string) => { send: (to: string, payload: unknown) => Promise<unknown> };
  };
};

const CODE_PATTERN = /^\d{6}$/;

/** One error for every rejection: unknown phone, no code, wrong, expired, used, over the cap. */
function invalidCode(): InvalidOneTimeTokenError {
  return new InvalidOneTimeTokenError("Invalid or expired code.");
}

/**
 * Keyed hash of a code. A plain SHA-256 of a 6-digit code is reversed by
 * trying all million values, so the MAC key (derived from the access-token
 * secret) is what keeps a leaked table useless. `salt` makes each stored
 * value unique.
 */
function macCode(user: Auth, salt: string, code: string): string {
  const key = createHmac("sha256", authConfig.accessToken.secret())
    .update("@warlock.js/auth:otp")
    .digest();

  return createHmac("sha256", key)
    .update(`${salt}:${user.userType}:${user.id}:${code}`)
    .digest("base64url");
}

/** Stored form: `<salt>.<mac>` — 16 + 1 + 43 chars, inside the 64-char `token_hash` column. */
function storedCodeHash(user: Auth, code: string): string {
  const salt = randomBytes(12).toString("base64url");

  return `${salt}.${macCode(user, salt, code)}`;
}

function codeMatches(user: Auth, stored: string, code: string): boolean {
  const [salt, mac] = stored.split(".");

  return !!salt && !!mac && safeEqual(mac, macCode(user, salt, code));
}

/**
 * Resolve how a code is sent: `auth.otp.send`, else the app's notifications
 * channel. Resolved BEFORE the user lookup, so a missing notifications package
 * fails identically for known and unknown phones.
 */
async function resolveDelivery(channel: string): Promise<OtpSender> {
  const custom = authConfig.otp.send();

  if (custom) return custom;

  const { notify } = await loadOptionalPeer<NotifyModule>(
    "@warlock.js/notifications",
    "notifications",
  );

  return (phone, message, channelName) => notify.channel(channelName).send(phone, message);
}

/**
 * Send a 6-digit login code to the account whose `auth.otp.phoneField`
 * (default `phone`) equals `phone`, through the notifications channel named by
 * `options.channel` / `auth.otp.channel` (default `"sms"`). Auth ships no
 * SMS/WhatsApp driver — the app registers that channel.
 *
 * The code is stored only as a keyed hash in `one_time_tokens` (purpose
 * `otp`), expires after `auth.otp.expiresIn` (default 5m), and replaces any
 * earlier unused code. **Anti-enumeration:** an unknown phone resolves the same
 * way and sends nothing. Throttle the route with `otpRequestThrottleMiddleware()`.
 *
 * @throws AuthProviderSdkMissingError when `@warlock.js/notifications` is not
 *   installed and no `auth.otp.send` is configured.
 */
export async function requestOtp<T extends Auth>(
  Model: ChildModel<T>,
  phone: string,
  options: { channel?: string } = {},
): Promise<void> {
  const channel = options.channel ?? authConfig.otp.channel();
  const deliver = await resolveDelivery(channel);

  if (typeof phone !== "string" || phone.length === 0) return;

  const user = (await Model.first({ [authConfig.otp.phoneField()]: phone })) as T | null;

  if (!user) return;

  const code = String(randomInt(0, 1_000_000)).padStart(6, "0");
  const expiresAt = new Date(Date.now() + authConfig.otp.expiresInMs());
  const TokenModel = oneTimeTokenModel();

  await TokenModel.invalidateActiveFor(user, "otp");
  await TokenModel.issue(user, "otp", storedCodeHash(user, code), expiresAt);

  const message: OtpMessage = { body: authConfig.otp.message(code), code, expiresAt };

  await deliver(phone, message, channel);
}

/**
 * Verify a phone login code and log the user in through
 * `authService.completeLogin` — the same outcome as password login.
 *
 * Each check first counts an attempt atomically; once `auth.otp.maxAttempts`
 * (default 5) have been counted the code is invalidated, so it is compared at
 * most that many times even under concurrent guesses. A correct code is
 * consumed single-use. Throttle the route with `otpVerifyThrottleMiddleware()`.
 *
 * @throws InvalidOneTimeTokenError (400, EC008) — the same for an unknown
 *   phone, a wrong, expired, used or exhausted code.
 */
export async function verifyOtp<T extends Auth>(
  Model: ChildModel<T>,
  phone: string,
  code: string,
  deviceInfo?: DeviceInfo,
): Promise<LoginResult<T>> {
  if (typeof phone !== "string" || phone.length === 0) throw invalidCode();
  if (typeof code !== "string" || !CODE_PATTERN.test(code)) throw invalidCode();

  const user = (await Model.first({ [authConfig.otp.phoneField()]: phone })) as T | null;

  if (!user) throw invalidCode();

  const row = await oneTimeTokenModel().findActiveFor(user, "otp");

  if (!row || row.isConsumed || row.isExpired) throw invalidCode();

  if (!(await row.recordAttempt(authConfig.otp.maxAttempts()))) {
    await row.consumeIfActive();

    throw invalidCode();
  }

  if (!codeMatches(user, String(row.get("token_hash") ?? ""), code)) throw invalidCode();

  if (!(await row.consumeIfActive())) throw invalidCode();

  return authService.completeLogin(user, deviceInfo);
}
