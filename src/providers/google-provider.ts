import { createHash } from "node:crypto";
import type {
  AuthProvider,
  GoogleProviderConfig,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { loadOptionalPeer } from "../services/optional-peer";

const AUTHORIZATION_ENDPOINT = "https://accounts.google.com/o/oauth2/v2/auth";
const TOKEN_ENDPOINT = "https://oauth2.googleapis.com/token";
const JWKS_URI = "https://www.googleapis.com/oauth2/v3/certs";
const ISSUERS = ["https://accounts.google.com", "accounts.google.com"];
const DEFAULT_SCOPES = ["openid", "email", "profile"];

/** The `warlock add` feature that installs `jose`. */
export const GOOGLE_AUTH_FEATURE = "auth-google";

/** The slice of `jose` the Google provider uses — declared locally because `jose` is an optional peer. */
export type JoseModule = {
  createRemoteJWKSet: (url: URL) => unknown;
  jwtVerify: (
    token: string,
    key: unknown,
    options: { issuer: string[]; audience: string },
  ) => Promise<{ payload: Record<string, unknown> }>;
};

/** Google's key set, created once per process; `jose` caches the fetched JWKS inside it. */
let googleKeySet: unknown;

/** PKCE S256 code challenge for a verifier. */
export function pkceChallenge(codeVerifier: string): string {
  return createHash("sha256").update(codeVerifier).digest("base64url");
}

/**
 * Google sign-in: OpenID Connect authorization code flow with PKCE (S256),
 * `state` and `nonce`. The code is exchanged with plain `fetch`; the id_token
 * is verified with `jose` against Google's JWKS (signature, `iss`, `aud` = the
 * client id, `exp`), then its `nonce` is compared. No Google SDK.
 */
export class GoogleProvider implements AuthProvider {
  public readonly name = "google";

  public constructor(private readonly settings: GoogleProviderConfig) {}

  public authorizationUrl(state: ProviderAuthorizationState): string {
    const url = new URL(AUTHORIZATION_ENDPOINT);

    url.searchParams.set("client_id", this.settings.clientId);
    url.searchParams.set("redirect_uri", this.settings.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", (this.settings.scopes ?? DEFAULT_SCOPES).join(" "));
    url.searchParams.set("state", state.state);
    url.searchParams.set("nonce", state.nonce);
    url.searchParams.set("code_challenge", pkceChallenge(state.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");

    return url.toString();
  }

  public async handleCallback({
    query,
    expected,
  }: ProviderCallbackParams): Promise<ProviderProfile> {
    // Load the peer first: a missing SDK fails loudly before any network call.
    const jose = await loadOptionalPeer<JoseModule>("jose", GOOGLE_AUTH_FEATURE);

    const code = query.code;

    if (typeof code !== "string" || code.length === 0) {
      throw new InvalidProviderCallbackError("missing-code");
    }

    const idToken = await this.exchangeCode(code, expected.codeVerifier);
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
      // Google sends a boolean; anything else counts as NOT verified.
      emailVerified: claims.email_verified === true,
      name: typeof claims.name === "string" ? claims.name : undefined,
      avatar: typeof claims.picture === "string" ? claims.picture : undefined,
      raw: claims,
    };
  }

  /** Redeem the authorization code (with the PKCE verifier) for an id_token. */
  private async exchangeCode(code: string, codeVerifier: string): Promise<string> {
    let body: { id_token?: unknown };

    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: "POST",
        headers: { "content-type": "application/x-www-form-urlencoded" },
        body: new URLSearchParams({
          code,
          client_id: this.settings.clientId,
          client_secret: this.settings.clientSecret,
          redirect_uri: this.settings.redirectUri,
          grant_type: "authorization_code",
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        throw new Error(`Google token endpoint answered ${response.status}`);
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
  private async verifyIdToken(jose: JoseModule, idToken: string): Promise<Record<string, unknown>> {
    googleKeySet ??= jose.createRemoteJWKSet(new URL(JWKS_URI));

    try {
      const { payload } = await jose.jwtVerify(idToken, googleKeySet, {
        issuer: ISSUERS,
        audience: this.settings.clientId,
      });

      return payload;
    } catch (error) {
      throw new InvalidProviderCallbackError("invalid-id-token", error);
    }
  }
}
