import type { ChildModel } from "@warlock.js/cascade";
import type { Auth } from "../models/auth.model";

/**
 * The per-login secrets a redirect provider round-trips: `state` (CSRF),
 * `nonce` (id_token replay binding) and the PKCE `codeVerifier`.
 */
export type ProviderAuthorizationState = {
  state: string;
  nonce: string;
  codeVerifier: string;
};

/**
 * What a provider's callback hands {@link AuthProvider.handleCallback}: the
 * callback query and the state that was stored when the login started. The
 * caller has already checked `query.state` against `expected.state`.
 */
export type ProviderCallbackParams = {
  query: Record<string, unknown>;
  expected: ProviderAuthorizationState;
};

/** The identity a provider asserts, normalized across providers. */
export type ProviderProfile = {
  /** Provider name, e.g. `"google"`. */
  provider: string;
  /** The provider's stable user id (`sub`). The link key — never the email. */
  providerUserId: string;
  email?: string;
  /** Whether the PROVIDER verified `email`. Accounts are never linked on `false`. */
  emailVerified: boolean;
  name?: string;
  avatar?: string;
  /** The verified claims the profile was built from. */
  raw: Record<string, unknown>;
};

/**
 * A redirect-style login provider (OAuth 2 / OIDC authorization code).
 * Register an instance under `auth.providers.custom.<name>` to add one auth does
 * not ship.
 */
export interface AuthProvider {
  readonly name: string;
  /**
   * How the provider's callback arrives. `"query"` (default) is a top-level
   * GET redirect, safe for a `SameSite=Lax` state cookie. `"form_post"` is a
   * cross-site POST (Apple, when `name`/`email` scopes are requested) — the
   * state cookie needs `SameSite=None; Secure` to survive it.
   * @default "query"
   */
  readonly callbackMode?: "query" | "form_post";
  /** The URL to send the browser to. */
  authorizationUrl(state: ProviderAuthorizationState): string | Promise<string>;
  /** Exchange the callback for a verified profile, or throw. */
  handleCallback(params: ProviderCallbackParams): Promise<ProviderProfile>;
}

/** `auth.providers.google`. */
export type GoogleProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match a redirect URI registered in the Google console. */
  redirectUri: string;
  /** @default ["openid", "email", "profile"] */
  scopes?: string[];
};

/** `auth.providers.github`. */
export type GitHubProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match the "Authorization callback URL" registered on the GitHub OAuth App. */
  redirectUri: string;
  /** @default ["read:user", "user:email"] */
  scopes?: string[];
};

/** `auth.providers.discord`. */
export type DiscordProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match a redirect registered on the Discord application. */
  redirectUri: string;
  /** @default ["identify", "email"] */
  scopes?: string[];
};

/** `auth.providers.linkedin`. */
export type LinkedInProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match a redirect URL registered on the LinkedIn app. */
  redirectUri: string;
  /** @default ["openid", "profile", "email"] */
  scopes?: string[];
};

/** `auth.providers.apple`. */
export type AppleProviderConfig = {
  /** The Services ID (or app id) registered with Sign in with Apple. */
  clientId: string;
  /** The Apple Developer team id — signed into the client-secret JWT as `iss`. */
  teamId: string;
  /** The id of the private key created for Sign in with Apple — signed into the client-secret JWT header as `kid`. */
  keyId: string;
  /** The PKCS8 PEM contents of that private key (`.p8` file), used to sign the client-secret JWT. */
  privateKey: string;
  /** Must exactly match a return URL registered on the Services ID. */
  redirectUri: string;
  /** @default ["name", "email"] */
  scopes?: string[];
};

/** `auth.providers.facebook`. */
export type FacebookProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match a valid OAuth redirect URI registered on the Facebook app. */
  redirectUri: string;
  /** @default ["email", "public_profile"] */
  scopes?: string[];
};

/** `auth.providers.x`. */
export type XProviderConfig = {
  clientId: string;
  clientSecret: string;
  /** Must exactly match a callback URI registered on the X app (confidential client). */
  redirectUri: string;
  /** @default ["tweet.read", "users.read"] */
  scopes?: string[];
};

/** Creates the app user for a verified provider profile with no matching account. */
export type ProviderUserCreator = (
  profile: ProviderProfile,
  Model: ChildModel<Auth>,
) => Auth | Promise<Auth>;

/** `auth.providers`. */
export type ProvidersConfig = {
  google?: GoogleProviderConfig;
  github?: GitHubProviderConfig;
  discord?: DiscordProviderConfig;
  linkedin?: LinkedInProviderConfig;
  apple?: AppleProviderConfig;
  facebook?: FacebookProviderConfig;
  x?: XProviderConfig;
  /**
   * User attribute a verified provider email is matched against.
   * @default "email"
   */
  emailField?: string;
  /** Replace the default user creation (`{ email, name, <verification.field>: now }`). */
  createUser?: ProviderUserCreator;
  /** Providers auth does not ship, by name. */
  custom?: Record<string, AuthProvider>;
};

/** `auth.passkeys`. */
export type PasskeysConfig = {
  /** Relying-party id — the site's registrable domain, e.g. `"example.com"`. */
  rpID: string;
  /** Name shown by the authenticator. */
  rpName: string;
  /** Exact origin(s) the browser ceremony runs on, e.g. `"https://example.com"`. */
  origin: string | string[];
  /**
   * Challenge lifetime — a positive `ms` duration string.
   * @default "5m"
   */
  challengeExpiresIn?: string;
  /** Account name shown by the authenticator. @default user email, else id */
  userName?: (user: Auth) => string;
};

/** Data an OTP delivery receives. */
export type OtpMessage = {
  /** Ready-to-send text containing the code. */
  body: string;
  code: string;
  expiresAt: Date;
};

/** Delivers an OTP. Replaces the default `notify.channel(channel).send(phone, message)`. */
export type OtpSender = (phone: string, message: OtpMessage, channel: string) => unknown;

/** `auth.otp`. */
export type OtpConfig = {
  /**
   * Notifications channel the code is sent through. The app registers it
   * (auth ships no SMS/WhatsApp driver).
   * @default "sms"
   */
  channel?: string;
  /** User attribute holding the phone number. @default "phone" */
  phoneField?: string;
  /** Code lifetime. @default "5m" */
  expiresIn?: string;
  /** Verify attempts before the code is invalidated. @default 5 */
  maxAttempts?: number;
  /** Build the message text. @default "Your verification code is <code>" */
  message?: (code: string) => string;
  /** Replace delivery entirely. */
  send?: OtpSender;
};
