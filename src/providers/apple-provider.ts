import type {
  AppleProviderConfig,
  AuthProvider,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { loadOptionalPeer } from "../services/optional-peer";
import type { JoseModule } from "./google-provider";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://appleid.apple.com/auth/authorize";
const TOKEN_ENDPOINT = "https://appleid.apple.com/auth/token";
const JWKS_URI = "https://appleid.apple.com/auth/keys";
const ISSUER = "https://appleid.apple.com";
const DEFAULT_SCOPES = ["name", "email"];
/** Apple's own recommendation for a per-request client secret: minutes, not the 6-month maximum it allows. */
const CLIENT_SECRET_TTL_SECONDS = 5 * 60;

/** The `warlock add` feature that installs `jose`. */
export const APPLE_AUTH_FEATURE = "auth-apple";

type AppleSignJwtBuilder = {
  setIssuer: (issuer: string) => AppleSignJwtBuilder;
  setIssuedAt: () => AppleSignJwtBuilder;
  setExpirationTime: (time: number) => AppleSignJwtBuilder;
  setAudience: (audience: string) => AppleSignJwtBuilder;
  setSubject: (subject: string) => AppleSignJwtBuilder;
  sign: (key: unknown) => Promise<string>;
};

/**
 * The slice of `jose` the Apple provider uses on top of {@link JoseModule} —
 * `importPKCS8` and `SignJWT` sign the ES256 client-secret JWT Apple requires
 * instead of a static client secret.
 */
export type AppleJoseModule = JoseModule & {
  importPKCS8: (pkcs8: string, alg: string) => Promise<unknown>;
  SignJWT: new (payload: Record<string, unknown>) => {
    setProtectedHeader: (header: Record<string, unknown>) => AppleSignJwtBuilder;
  };
};

/** Apple's key set, created once per process; `jose` caches the fetched JWKS inside it. */
let appleKeySet: unknown;

/**
 * Apple ("Sign in with Apple") is OpenID Connect over the authorization code
 * flow with PKCE (S256), `state` and `nonce`, the same shape as
 * {@link GoogleProvider} — with two differences that come straight from
 * Apple's own docs (this package has no Apple developer account, so nothing
 * here is proven against a live exchange):
 *
 * 1. Apple has no static client secret. The "secret" the token endpoint wants
 *    is a fresh ES256 JWT (`iss` = team id, `sub` = client id, `aud` =
 *    `https://appleid.apple.com`, signed with the app's private key and the
 *    key id as `kid`) — signed once per callback here rather than cached, to
 *    avoid ever presenting a stale one.
 * 2. Requesting `name`/`email` (the default scopes) forces
 *    `response_mode=form_post`: Apple POSTs `code`, `state` and, on the
 *    user's FIRST authorization only, a `user` field — a JSON string with
 *    `{ name: { firstName, lastName }, email } ` that never comes back again
 *    on a later login. The callback route must therefore accept a POST body,
 *    not just a query string, and `request.input` must read that body the
 *    same way it already reads a GET query for the other providers.
 *
 * The id_token is verified with `jose` against Apple's JWKS (signature,
 * `iss`, `aud` = the client id, `exp`), then its `nonce` is compared. Apple is
 * also documented to send `email_verified` (and `is_private_email`) as the
 * STRING `"true"`/`"false"` rather than a JSON boolean on some responses, so
 * both forms are accepted here — treating only the unambiguous `"false"` (or
 * `false`) as unverified. A private-relay address (`@privaterelay.appleid.com`)
 * is still a real, working forwarding address and is accepted as any other.
 */
export class AppleProvider implements AuthProvider {
  public readonly name = "apple";
  /** Apple's default scopes (`name`, `email`) force `response_mode=form_post`. */
  public readonly callbackMode = "form_post";

  public constructor(private readonly settings: AppleProviderConfig) {}

  public authorizationUrl(state: ProviderAuthorizationState): string {
    const scopes = this.settings.scopes ?? DEFAULT_SCOPES;
    const url = new URL(AUTHORIZATION_ENDPOINT);

    url.searchParams.set("client_id", this.settings.clientId);
    url.searchParams.set("redirect_uri", this.settings.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", scopes.join(" "));
    url.searchParams.set("state", state.state);
    url.searchParams.set("nonce", state.nonce);
    url.searchParams.set("code_challenge", pkceChallenge(state.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");

    // Apple requires form_post whenever name/email scopes are requested.
    if (scopes.includes("name") || scopes.includes("email")) {
      url.searchParams.set("response_mode", "form_post");
    }

    return url.toString();
  }

  public async handleCallback({
    query,
    expected,
  }: ProviderCallbackParams): Promise<ProviderProfile> {
    // Load the peer first: a missing SDK fails loudly before any network call.
    const jose = await loadOptionalPeer<AppleJoseModule>("jose", APPLE_AUTH_FEATURE);

    const code = query.code;

    if (typeof code !== "string" || code.length === 0) {
      throw new InvalidProviderCallbackError("missing-code");
    }

    const idToken = await this.exchangeCode(jose, code, expected.codeVerifier);
    const claims = await this.verifyIdToken(jose, idToken);

    if (typeof claims.nonce !== "string" || claims.nonce !== expected.nonce) {
      throw new InvalidProviderCallbackError("nonce-mismatch");
    }

    if (typeof claims.sub !== "string" || claims.sub.length === 0) {
      throw new InvalidProviderCallbackError("missing-subject");
    }

    return {
      provider: this.name,
      providerUserId: claims.sub,
      email: typeof claims.email === "string" ? claims.email : undefined,
      emailVerified: isVerifiedFlag(claims.email_verified),
      name: nameFromUserField(query.user),
      raw: claims,
    };
  }

  /** Sign a fresh ES256 client-secret JWT — Apple has no static one. */
  private async clientSecret(jose: AppleJoseModule): Promise<string> {
    const key = await jose.importPKCS8(this.settings.privateKey, "ES256");
    const now = Math.floor(Date.now() / 1000);

    try {
      return await new jose.SignJWT({})
        .setProtectedHeader({ alg: "ES256", kid: this.settings.keyId })
        .setIssuer(this.settings.teamId)
        .setIssuedAt()
        .setExpirationTime(now + CLIENT_SECRET_TTL_SECONDS)
        .setAudience(ISSUER)
        .setSubject(this.settings.clientId)
        .sign(key);
    } catch (error) {
      throw new InvalidProviderCallbackError("client-secret-signing-failed", error);
    }
  }

  /** Redeem the authorization code (with the PKCE verifier) for an id_token. */
  private async exchangeCode(
    jose: AppleJoseModule,
    code: string,
    codeVerifier: string,
  ): Promise<string> {
    const clientSecret = await this.clientSecret(jose);
    let body: { id_token?: unknown };

    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: this.settings.clientId,
          client_secret: clientSecret,
          redirect_uri: this.settings.redirectUri,
          grant_type: "authorization_code",
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        throw new Error(`Apple token endpoint answered ${response.status}`);
      }

      body = (await response.json()) as { id_token?: unknown };
    } catch (error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", error);
    }

    if (typeof body.id_token !== "string") {
      throw new InvalidProviderCallbackError("missing-id-token");
    }

    return body.id_token;
  }

  /** Verify signature, issuer, audience and expiry; resolve the claims. */
  private async verifyIdToken(
    jose: AppleJoseModule,
    idToken: string,
  ): Promise<Record<string, unknown>> {
    appleKeySet ??= jose.createRemoteJWKSet(new URL(JWKS_URI));

    try {
      const { payload } = await jose.jwtVerify(idToken, appleKeySet, {
        issuer: [ISSUER],
        audience: this.settings.clientId,
      });

      return payload;
    } catch (error) {
      throw new InvalidProviderCallbackError("invalid-id-token", error);
    }
  }
}

/** Apple's `email_verified` arrives as a JSON boolean on some responses, a `"true"`/`"false"` string on others. */
function isVerifiedFlag(value: unknown): boolean {
  return value === true || value === "true";
}

/**
 * Apple sends the account name only once, on the FIRST authorization, as a
 * `user` form field holding a JSON string: `{"name":{"firstName","lastName"}}`.
 * Every later login omits it entirely — callers that need the name must save
 * it themselves the first time.
 */
function nameFromUserField(user: unknown): string | undefined {
  if (typeof user !== "string" || user.length === 0) return undefined;

  try {
    const parsed = JSON.parse(user) as { name?: { firstName?: string; lastName?: string } };
    const first = parsed.name?.firstName;
    const last = parsed.name?.lastName;
    const name = [first, last].filter((part): part is string => Boolean(part)).join(" ");

    return name.length > 0 ? name : undefined;
  } catch {
    return undefined;
  }
}
