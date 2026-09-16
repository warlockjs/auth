import { type ChildModel } from "@warlock.js/cascade";
import { type Algorithm } from "fast-jwt";
import type { AccessToken } from "../models/access-token";
import type { Auth } from "../models/auth.model";
import type { OneTimeToken } from "../models/one-time-token";
import type { OtpConfig, PasskeysConfig, ProvidersConfig } from "./providers";
import type { RefreshToken } from "../models/refresh-token";

/**
 * Symbol to indicate no expiration for tokens
 * Use this when you explicitly want tokens to never expire
 *
 * @example
 * ```typescript
 * // src/config/auth.ts
 * import { NO_EXPIRATION, type AuthConfigurations } from "@warlock.js/auth";
 *
 * const authConfigurations: AuthConfigurations = {
 *   accessToken: {
 *     secret: env("JWT_SECRET"),
 *     expiresIn: NO_EXPIRATION,  // Token expires within 100 years
 *   },
 * };
 *
 * export default authConfigurations;
 * ```
 */
export const NO_EXPIRATION = "100y";

/**
 * Behavior when logout is called without a refresh token
 * - "revoke-all": Revoke all refresh tokens for the user (secure default)
 * - "error": Return an error requiring the refresh token
 */
export type LogoutWithoutTokenBehavior = "revoke-all" | "error";

/** The single request credential source an auth middleware instance accepts. */
export type TokenFrom = "header" | `cookie:${string}`;

/** Application policy that decides whether a resolved user may authenticate. */
export type CanAuthenticate = (user: Auth) => boolean | Promise<boolean>;

/** Password credentials plus the application-defined identity fields. */
export type AuthCredentials = Record<string, unknown> & {
  password: string;
};

/**
 * Access-token configuration.
 *
 * `secret` may also be supplied via the deprecated `jwt.secret` (resolved by a
 * backward-compatible shim); one of the two is required at runtime.
 */
export type AccessTokenConfig = {
  /**
   * Override the persisted access-token model — extend {@link AccessToken} to
   * add columns (e.g. a tenant key) or rename them, then register the subclass
   * here. Defaults to the package's `AccessToken`.
   */
  model?: typeof AccessToken;
  /**
   * Secret used to sign access tokens.
   */
  secret?: string;
  /**
   * JWT algorithm.
   * @default "HS256"
   */
  algorithm?: Algorithm;
  /**
   * Access-token lifetime — a duration string `ms` parses to a **positive**
   * number of milliseconds. A value `ms` cannot parse (`"30dayz"`), a
   * non-positive one (`"0d"`), or a bare number throws naming this key on the
   * first token issue: each of them would otherwise sign a token with no `exp`
   * claim at all.
   * @example "1h" or NO_EXPIRATION
   * @default "1h"
   */
  expiresIn?: string;
};

/**
 * Refresh-token configuration.
 */
export type RefreshTokenConfig = {
  /**
   * Override the persisted refresh-token model — extend {@link RefreshToken}.
   * Defaults to the package's `RefreshToken`.
   */
  model?: typeof RefreshToken;
  /**
   * Enable refresh tokens.
   * @default true
   */
  enabled?: boolean;
  /**
   * Separate secret for refresh tokens (recommended for security). Falls back
   * to the access-token secret when omitted.
   */
  secret?: string;
  /**
   * Refresh-token lifetime — a duration string `ms` parses to a **positive**
   * number of milliseconds; an unusable value throws naming this key on issue
   * (see {@link AccessTokenConfig.expiresIn}).
   * @example "7d" or "1w"
   * @default "7d"
   */
  expiresIn?: string;
  /**
   * Rotate the refresh token on each use (old token revoked, replay detected).
   * @default true
   */
  rotation?: boolean;
  /**
   * Maximum active refresh tokens per user; the oldest are revoked past it.
   * @default 5
   */
  maxPerUser?: number;
  /**
   * Behavior when logout is called without a refresh token.
   * @default "revoke-all"
   */
  logoutWithoutToken?: LogoutWithoutTokenBehavior;
};

/**
 * Legacy JWT configuration shape. Still honored by the resolver shim with a
 * deprecation warning.
 *
 * @deprecated Use the top-level `accessToken` / `refreshToken` blocks.
 */
export type LegacyJwtConfig = {
  secret?: string;
  algorithm?: Algorithm;
  expiresIn?: string;
  refresh?: {
    secret?: string;
    enabled?: boolean;
    expiresIn?: string;
    rotation?: boolean;
    maxPerUser?: number;
    logoutWithoutToken?: LogoutWithoutTokenBehavior;
  };
};

/**
 * Page-route auth-failure behavior. When a guarded PAGE route (a React-SSR page,
 * `route.isPage`) rejects a logged-out browser, this decides whether it redirects
 * to a login page instead of returning the API-style JSON 401.
 *
 * Read at runtime through `authConfig.pageAuth` (`auth.pageAuth.*`). API routes
 * always keep the JSON 401 contract regardless of this setting.
 */
export type PageAuthConfig = {
  /**
   * Login path a guarded page route redirects a logged-out browser to (e.g.
   * `"/login"`). Unset ⇒ page-route auth failures keep the JSON 401, so the
   * behavior is opt-in and backward-compatible.
   */
  loginPath?: string;
  /**
   * Query parameter the redirect carries the originally-requested path in, so
   * the login flow can send the user back where they were headed.
   * @default "returnUrl"
   */
  returnUrlParam?: string;
};

/**
 * Data every email-verification / password-reset notification receives.
 */
export type OneTimeTokenNotificationData = {
  /** The raw token — the only place it exists; only its SHA-256 hash is stored. */
  token: string;
  /** When the token stops working. */
  expiresAt: Date;
  /** The link built by `auth.verification.url` / `auth.passwordReset.url`, when configured. */
  url?: string;
};

/**
 * Anything auth can deliver a token through — a `defineNotification(...)`
 * result satisfies it, as does any object with a compatible `send`.
 */
export type AuthNotification = {
  send: (to: Auth, data: OneTimeTokenNotificationData) => unknown;
};

/** Builds the link a token notification points at. */
export type OneTimeTokenUrlBuilder = (token: string, user: Auth) => string;

/** Persists a new plaintext password for a user during a password reset. */
export type PasswordSetter = (user: Auth, plainPassword: string) => void | Promise<void>;

/**
 * Email-verification configuration (`auth.verification`).
 */
export type EmailVerificationConfig = {
  /**
   * Token lifetime — a positive `ms` duration string.
   * @default "24h"
   */
  expiresIn?: string;
  /**
   * User attribute stamped with the verification `Date`. Declare it in the
   * user schema (e.g. `emailVerifiedAt: v.date().optional()`).
   * @default "emailVerifiedAt"
   */
  field?: string;
  /** Replace the default verification email. */
  notification?: AuthNotification;
  /** Build the verification link passed to the notification as `url`. */
  url?: OneTimeTokenUrlBuilder;
};

/**
 * Password-reset configuration (`auth.passwordReset`).
 */
export type PasswordResetConfig = {
  /**
   * Token lifetime — a positive `ms` duration string.
   * @default "60m"
   */
  expiresIn?: string;
  /**
   * User attribute `requestPasswordReset` looks the account up by.
   * @default "email"
   */
  identifierField?: string;
  /** Replace the default reset email. */
  notification?: AuthNotification;
  /** Build the reset link passed to the notification as `url`. */
  url?: OneTimeTokenUrlBuilder;
  /**
   * Persist the new password yourself. By default auth saves a hash made by
   * the same `hashPassword` login verifies against, and falls back to the
   * plaintext when the model hashes on save (`useHashedPassword()`), checking
   * the stored value with `verifyPassword` either way.
   */
  setPassword?: PasswordSetter;
};

/**
 * One-time token storage configuration (`auth.oneTimeToken`).
 */
export type OneTimeTokenConfig = {
  /** Override the persisted model — extend {@link OneTimeToken}. */
  model?: typeof OneTimeToken;
};

export type AuthConfigurations = {
  /**
   * Define all user types — maps a user-type slug to its `Auth` model class so
   * tokens and the middleware can resolve the right model.
   */
  userType: {
    [userType: string]: ChildModel<Auth>;
  };
  /**
   * Decide whether a resolved user may authenticate or receive new tokens.
   * @default () => true
   */
  canAuthenticate?: CanAuthenticate;
  /**
   * Access-token configuration (secret, expiry, algorithm, model override).
   */
  accessToken?: AccessTokenConfig;
  /**
   * Refresh-token configuration (rotation, lifetime, cap, model override).
   */
  refreshToken?: RefreshTokenConfig;
  /**
   * Page-route auth-failure behavior — set `loginPath` to redirect a logged-out
   * browser on a guarded PAGE route to a login page instead of the JSON 401.
   * Opt-in; API routes are unaffected. Read via `authConfig.pageAuth`.
   */
  pageAuth?: PageAuthConfig;
  /**
   * Cookie auth session config — read by `authService.setAuthCookie` /
   * `clearAuthCookie`. Opt-in: unset ⇒ the helpers fall back to their own
   * defaults (`name: "access_token"`, `path: "/"`).
   */
  cookie?: CookieAuthConfig;
  /**
   * CSRF Origin-check config for cookie-authenticated unsafe-method requests.
   */
  csrf?: CsrfConfig;
  /**
   * Email verification — token lifetime, verified field, notification override.
   */
  verification?: EmailVerificationConfig;
  /**
   * Password reset — token lifetime, lookup field, notification and password-writer overrides.
   */
  passwordReset?: PasswordResetConfig;
  /**
   * One-time token (verification / reset) storage — model override.
   */
  oneTimeToken?: OneTimeTokenConfig;
  /**
   * Redirect login providers (`google`, `custom`) and account-linking policy.
   */
  providers?: ProvidersConfig;
  /**
   * Passkey (WebAuthn) relying-party settings. Requires `@simplewebauthn/server`.
   */
  passkeys?: PasskeysConfig;
  /**
   * Phone one-time-code login — channel, lifetime, attempts, delivery.
   */
  otp?: OtpConfig;
  /**
   * @deprecated Use `accessToken` / `refreshToken`. Read via a backward-compatible shim.
   */
  jwt?: LegacyJwtConfig;
};

export type AccessTokenOutput = {
  /**
   * JWT Token
   */
  token: string;
  /**
   * Exprie time in ISO format UTC time
   */
  expiresAt: string;
};

/**
 * Token pair returned after login or token refresh
 */
export type TokenPair = {
  /**
   * JWT access token (short-lived)
   */
  accessToken: AccessTokenOutput;
  /**
   * JWT refresh token (long-lived)
   */
  refreshToken?: AccessTokenOutput;
};

/**
 * Device information for session tracking
 */
export type DeviceInfo = {
  /**
   * User agent string from request
   */
  userAgent?: string;
  /**
   * Client IP address
   */
  ip?: string;
  /**
   * Optional device identifier
   */
  deviceId?: string;
  /**
   * Token family ID (for rotation tracking)
   * @internal
   */
  familyId?: string;
  /**
   * Access token payload
   */
  payload?: Record<string, unknown>;
};

export type LoginResult<UserType extends Auth> = {
  user: UserType;
  tokens: TokenPair;
};

/**
 * Configuration for the cookie an app opts into via `authService.setAuthCookie`
 * / `clearAuthCookie` and reads back with `authMiddleware([], "cookie:<name>")`.
 * Attribute flags (`httpOnly` / `sameSite` / `secure`) are deliberately NOT
 * configurable here — they come from core's `secureCookieDefaults()`, the
 * same floor every `response.cookie()` call gets, so a cookie auth session can
 * never be weakened to a laxer policy than the framework default.
 */
export type CookieAuthConfig = {
  /**
   * Cookie name `setAuthCookie`/`clearAuthCookie` write and clear, and that a
   * `cookie:<name>` token source must match to read it back.
   * @default "access_token"
   */
  name?: string;
  /**
   * Cookie `Path` attribute.
   * @default "/"
   */
  path?: string;
};

/**
 * CSRF Origin-check configuration. Read via
 * `authConfig.csrf.allowedOrigins()`.
 */
export type CsrfConfig = {
  /**
   * Extra origins allowed on a cookie-authenticated unsafe-method request,
   * in addition to the request's own origin.
   * @default []
   */
  allowedOrigins?: string[];
};

/**
 * Per-call overrides for {@link AuthService.setAuthCookie}. Anything omitted
 * falls back to `auth.cookie.*` config, then the package default. Cookie
 * *attribute* flags (`httpOnly`/`sameSite`/`secure`) are never settable here —
 * see {@link CookieAuthConfig}.
 */
export type SetAuthCookieOptions = {
  /** Cookie name; defaults to `auth.cookie.name` (package default `"access_token"`). */
  name?: string;
  /** Cookie `Path`; defaults to `auth.cookie.path` (package default `"/"`). */
  path?: string;
  /**
   * `Max-Age`, in seconds. Overrides the expiry `setAuthCookie` would
   * otherwise derive from an `AccessTokenOutput`'s `expiresAt`. Passing a
   * bare token string with no `maxAge` produces a session cookie (cleared
   * when the browser closes).
   */
  maxAge?: number;
};

/** Per-call overrides for {@link AuthService.clearAuthCookie}. */
export type ClearAuthCookieOptions = {
  /** Cookie name; defaults to `auth.cookie.name` (package default `"access_token"`). */
  name?: string;
  /** Cookie `Path`; defaults to `auth.cookie.path` (package default `"/"`). Must match the `Path` the cookie was set with. */
  path?: string;
};
