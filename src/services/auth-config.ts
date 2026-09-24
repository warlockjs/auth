import { config } from "@warlock.js/core";
import { log } from "@warlock.js/logger";
import { type Algorithm } from "fast-jwt";
import ms from "ms";
import type {
  AuthNotification,
  CanAuthenticate,
  LogoutWithoutTokenBehavior,
  OneTimeTokenUrlBuilder,
  PasswordSetter,
} from "../contracts/types";
import type {
  AppleProviderConfig,
  AuthProvider,
  DiscordProviderConfig,
  FacebookProviderConfig,
  GitHubProviderConfig,
  GoogleProviderConfig,
  LinkedInProviderConfig,
  OtpSender,
  PasskeysConfig,
  ProviderUserCreator,
  XProviderConfig,
} from "../contracts/providers";
import type { Auth } from "../models/auth.model";

const warnedLegacyKeys = new Set<string>();

const permitAuthentication: CanAuthenticate = (): boolean => true;

/**
 * `ms` accepts anything at runtime and answers `undefined` for a string it
 * cannot parse (`"30dayz"`), a *formatted string* for a number (`2592000` ⇒
 * `"43m"`), and throws for `""`. Its published types claim the far narrower
 * `(value: ms.StringValue) => number`, which is exactly what let an
 * `as ms.StringValue` cast smuggle arbitrary config text past the compiler and
 * hand `undefined` to the JWT signer. Declare the honest runtime signature once,
 * here, so every caller is forced to deal with the `undefined`.
 */
const parseMs = ms as unknown as (value: unknown) => number | string | undefined;

/**
 * Turn a configured lifetime into a positive number of milliseconds, or throw
 * naming the key.
 *
 * A token lifetime is a security boundary, so an unusable value is a hard error
 * rather than a silent fallback: substituting a default would trade one
 * unintended lifetime for another, just as quietly — and quiet is the whole
 * problem. Every non-positive, non-finite or non-numeric parse is rejected:
 *
 * - `"30dayz"` / `"thirty days"` ⇒ `undefined` ⇒ a JWT signed with **no `exp`
 *   claim** and an `Invalid Date` written to the token row.
 * - `"0d"` ⇒ parses cleanly to `0`, which `fast-jwt` treats as falsy and also
 *   emits with **no `exp` claim** — it survives any guard that only rejects
 *   `undefined`. `"-1h"` signs an already-expired token.
 * - `2592000` (a bare number) ⇒ `ms` *formats* it as `"43m"`, a string, which
 *   then turns `Date.now() + expiresIn` into an `Invalid Date`.
 */
function parseDuration(key: string, raw: unknown): number {
  let parsed: number | string | undefined;

  try {
    parsed = parseMs(raw);
  } catch {
    // ms throws (rather than returning undefined) for "" and non-strings
    parsed = undefined;
  }

  if (typeof parsed !== "number" || !Number.isFinite(parsed) || parsed <= 0) {
    throw new Error(
      `auth.${key}: ${JSON.stringify(raw)} is not a valid ms duration — ` +
        `use a positive duration string such as "1h", "7d", or NO_EXPIRATION.`,
    );
  }

  return parsed;
}

/** Email-verification token lifetime used when nothing is configured. */
const DEFAULT_VERIFICATION_EXPIRES_IN = "24h";

/** Password-reset token lifetime used when nothing is configured. */
const DEFAULT_PASSWORD_RESET_EXPIRES_IN = "60m";

/** Passkey challenge lifetime used when nothing is configured. */
const DEFAULT_PASSKEY_CHALLENGE_EXPIRES_IN = "5m";

/** OTP lifetime used when nothing is configured. */
const DEFAULT_OTP_EXPIRES_IN = "5m";

/** Access-token lifetime used when nothing is configured. */
const DEFAULT_ACCESS_TOKEN_EXPIRES_IN = "1h";

/**
 * Resolve an auth setting, preferring the new `auth.accessToken.*` /
 * `auth.refreshToken.*` key and falling back to the deprecated `auth.jwt.*`
 * shape — warning once per legacy key. Returns `fallback` when neither is set.
 *
 * This is the backward-compatible shim that lets existing `auth.jwt.*` configs
 * keep working after the config split.
 */
function resolve<T>(newKey: string, legacyKey: string, fallback?: T): T {
  const fromNew = config.key(`auth.${newKey}`);

  if (fromNew !== undefined && fromNew !== null) {
    return fromNew as T;
  }

  const fromLegacy = config.key(`auth.${legacyKey}`);

  if (fromLegacy !== undefined && fromLegacy !== null) {
    if (!warnedLegacyKeys.has(legacyKey)) {
      warnedLegacyKeys.add(legacyKey);
      log.warn(
        "auth",
        "config-deprecation",
        `auth.${legacyKey} is deprecated — use auth.${newKey}`,
      );
    }

    return fromLegacy as T;
  }

  return fallback as T;
}

/**
 * Typed, backward-compatible access to auth configuration. The service and the
 * jwt signer read configuration exclusively through here, so the new split
 * config and the legacy `auth.jwt.*` shape both resolve the same way.
 */
export const authConfig = {
  canAuthenticate: async (user: Auth): Promise<boolean> => {
    const canAuthenticate = config.key<CanAuthenticate>(
      "auth.canAuthenticate",
      permitAuthentication,
    );

    return canAuthenticate(user);
  },
  accessToken: {
    /** Signing secret (legacy: `auth.jwt.secret`). Throws if neither is set. */
    secret: (): string => {
      const secret = resolve<string | undefined>("accessToken.secret", "jwt.secret");

      if (!secret) {
        throw new Error("auth: no JWT secret configured — set `auth.accessToken.secret`.");
      }

      return secret;
    },
    /** Signing algorithm (legacy: `auth.jwt.algorithm`). */
    algorithm: (): Algorithm => resolve("accessToken.algorithm", "jwt.algorithm", "HS256"),
    /** Lifetime as an `ms`-string (legacy: `auth.jwt.expiresIn`). */
    expiresIn: (): string | undefined => resolve("accessToken.expiresIn", "jwt.expiresIn"),
    /**
     * Lifetime in milliseconds — the only form a token issuer may use. Defaults
     * to 1 hour when unset; throws naming the key when the configured value is
     * not a positive `ms` duration. See {@link parseDuration}.
     */
    expiresInMs: (): number =>
      parseDuration(
        "accessToken.expiresIn",
        authConfig.accessToken.expiresIn() ?? DEFAULT_ACCESS_TOKEN_EXPIRES_IN,
      ),
  },
  pageAuth: {
    /**
     * Login path a guarded PAGE route redirects a logged-out browser to.
     *
     * Unset (the default) ⇒ page-route auth failures keep the JSON 401 API
     * contract, so existing apps see NO behavior change. Set it (e.g. "/login")
     * to opt a browser-facing app into login-redirect UX: a logged-out human
     * navigating to a guarded page lands on the login screen instead of reading
     * a raw JSON error blob. Finding b9ab9804.
     */
    loginPath: (): string | undefined => config.key("auth.pageAuth.loginPath"),
    /**
     * Query parameter the redirect carries the originally-requested path in, so
     * the login flow can send the user back where they were headed. Defaults to
     * `"returnUrl"`.
     */
    returnUrlParam: (): string => config.key("auth.pageAuth.returnUrlParam", "returnUrl"),
  },
  cookie: {
    /** Cookie name `setAuthCookie`/`clearAuthCookie` use. @default "access_token" */
    name: (): string => config.key("auth.cookie.name", "access_token"),
    /** Refresh-token cookie name the session cookie helpers use. @default "refresh_token" */
    refreshName: (): string => config.key("auth.cookie.refreshName", "refresh_token"),
    /** Cookie `Path` attribute `setAuthCookie`/`clearAuthCookie` use. @default "/" */
    path: (): string => config.key("auth.cookie.path", "/"),
  },
  csrf: {
    /**
     * Extra origins allowed on a cookie-authenticated unsafe-method request,
     * beyond the request's own origin. @default []
     */
    allowedOrigins: (): string[] => config.key("auth.csrf.allowedOrigins", []),
  },
  verification: {
    /** Lifetime in ms of an email-verification token; throws naming the key when unusable. @default "24h" */
    expiresInMs: (): number =>
      parseDuration(
        "verification.expiresIn",
        config.key("auth.verification.expiresIn", DEFAULT_VERIFICATION_EXPIRES_IN),
      ),
    /** User attribute stamped with the verification date. @default "emailVerifiedAt" */
    field: (): string => config.key("auth.verification.field", "emailVerifiedAt"),
    /** App notification replacing the default verification email. */
    notification: (): AuthNotification | undefined => config.key("auth.verification.notification"),
    /** Link builder whose result is handed to the notification as `url`. */
    url: (): OneTimeTokenUrlBuilder | undefined => config.key("auth.verification.url"),
  },
  passwordReset: {
    /** Lifetime in ms of a password-reset token; throws naming the key when unusable. @default "60m" */
    expiresInMs: (): number =>
      parseDuration(
        "passwordReset.expiresIn",
        config.key("auth.passwordReset.expiresIn", DEFAULT_PASSWORD_RESET_EXPIRES_IN),
      ),
    /** User attribute `requestPasswordReset` looks the account up by. @default "email" */
    identifierField: (): string => config.key("auth.passwordReset.identifierField", "email"),
    /** App notification replacing the default reset email. */
    notification: (): AuthNotification | undefined => config.key("auth.passwordReset.notification"),
    /** Link builder whose result is handed to the notification as `url`. */
    url: (): OneTimeTokenUrlBuilder | undefined => config.key("auth.passwordReset.url"),
    /** App-owned password writer replacing the default. */
    setPassword: (): PasswordSetter | undefined => config.key("auth.passwordReset.setPassword"),
  },
  providers: {
    /** `auth.providers.google`, when configured. */
    google: (): GoogleProviderConfig | undefined => config.key("auth.providers.google"),
    /** `auth.providers.github`, when configured. */
    github: (): GitHubProviderConfig | undefined => config.key("auth.providers.github"),
    /** `auth.providers.discord`, when configured. */
    discord: (): DiscordProviderConfig | undefined => config.key("auth.providers.discord"),
    /** `auth.providers.linkedin`, when configured. */
    linkedin: (): LinkedInProviderConfig | undefined => config.key("auth.providers.linkedin"),
    /** `auth.providers.apple`, when configured. */
    apple: (): AppleProviderConfig | undefined => config.key("auth.providers.apple"),
    /** `auth.providers.facebook`, when configured. */
    facebook: (): FacebookProviderConfig | undefined => config.key("auth.providers.facebook"),
    /** `auth.providers.x`, when configured. */
    x: (): XProviderConfig | undefined => config.key("auth.providers.x"),
    /** An app-registered provider under `auth.providers.custom.<name>`. */
    custom: (name: string): AuthProvider | undefined => {
      const providers = config.key<Record<string, AuthProvider>>("auth.providers.custom", {});

      // Own keys only: `name` arrives from a URL, and "constructor" must not resolve to Object.
      return Object.hasOwn(providers, name) ? providers[name] : undefined;
    },
    /** User attribute a verified provider email is matched against. @default "email" */
    emailField: (): string => config.key("auth.providers.emailField", "email"),
    /** App-owned user creation for a first provider login. */
    createUser: (): ProviderUserCreator | undefined => config.key("auth.providers.createUser"),
  },
  passkeys: {
    /** `auth.passkeys`; throws naming the keys when `rpID`, `rpName` or `origin` is missing. */
    settings: (): PasskeysConfig => {
      const settings = config.key<PasskeysConfig | undefined>("auth.passkeys");

      if (!settings?.rpID || !settings.rpName || !settings.origin) {
        throw new Error(
          "@warlock.js/auth: passkeys need `auth.passkeys.rpID`, `auth.passkeys.rpName` and `auth.passkeys.origin`.",
        );
      }

      return settings;
    },
    /** Allowed ceremony origins, as a list. */
    origins: (): string[] => {
      const { origin } = authConfig.passkeys.settings();

      return Array.isArray(origin) ? origin : [origin];
    },
    /** Challenge lifetime in ms; throws naming the key when unusable. @default "5m" */
    challengeExpiresInMs: (): number =>
      parseDuration(
        "passkeys.challengeExpiresIn",
        config.key("auth.passkeys.challengeExpiresIn", DEFAULT_PASSKEY_CHALLENGE_EXPIRES_IN),
      ),
  },
  otp: {
    /** Notifications channel the code is sent through. @default "sms" */
    channel: (): string => config.key("auth.otp.channel", "sms"),
    /** User attribute holding the phone number. @default "phone" */
    phoneField: (): string => config.key("auth.otp.phoneField", "phone"),
    /** Code lifetime in ms; throws naming the key when unusable. @default "5m" */
    expiresInMs: (): number =>
      parseDuration("otp.expiresIn", config.key("auth.otp.expiresIn", DEFAULT_OTP_EXPIRES_IN)),
    /** Verify attempts before the code is invalidated. @default 5 */
    maxAttempts: (): number => config.key("auth.otp.maxAttempts", 5),
    /** The message text for a code. */
    message: (code: string): string => {
      const build = config.key<((code: string) => string) | undefined>("auth.otp.message");

      return build ? build(code) : `Your verification code is ${code}`;
    },
    /** App-owned delivery replacing the notifications channel send. */
    send: (): OtpSender | undefined => config.key("auth.otp.send"),
  },
  refreshToken: {
    /** Separate refresh secret (legacy: `auth.jwt.refresh.secret`); empty ⇒ fall back to the access secret. */
    secret: (): string | undefined => resolve("refreshToken.secret", "jwt.refresh.secret"),
    /** Whether refresh tokens are enabled (legacy: `auth.jwt.refresh.enabled`). */
    enabled: (): boolean => resolve("refreshToken.enabled", "jwt.refresh.enabled", true),
    /** Lifetime as an `ms`-string (legacy: `auth.jwt.refresh.expiresIn`). */
    expiresIn: (): string => resolve("refreshToken.expiresIn", "jwt.refresh.expiresIn", "7d"),
    /**
     * Lifetime in milliseconds — the only form a token issuer may use. Throws
     * naming the key when the configured value is not a positive `ms` duration.
     */
    expiresInMs: (): number =>
      parseDuration("refreshToken.expiresIn", authConfig.refreshToken.expiresIn()),
    /** Rotate-on-use (legacy: `auth.jwt.refresh.rotation`). */
    rotation: (): boolean => resolve("refreshToken.rotation", "jwt.refresh.rotation", true),
    /** Max active tokens per user (legacy: `auth.jwt.refresh.maxPerUser`). */
    maxPerUser: (): number => resolve("refreshToken.maxPerUser", "jwt.refresh.maxPerUser", 5),
    /** Logout-without-token behavior (legacy: `auth.jwt.refresh.logoutWithoutToken`). */
    logoutWithoutToken: (): LogoutWithoutTokenBehavior =>
      resolve("refreshToken.logoutWithoutToken", "jwt.refresh.logoutWithoutToken", "revoke-all"),
  },
};
