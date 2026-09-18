import type {
  AuthProvider,
  LinkedInProviderConfig,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { loadOptionalPeer } from "../services/optional-peer";
import type { JoseModule } from "./google-provider";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://www.linkedin.com/oauth/v2/authorization";
const TOKEN_ENDPOINT = "https://www.linkedin.com/oauth/v2/accessToken";
const JWKS_URI = "https://www.linkedin.com/oauth/openid/jwks";
const ISSUERS = ["https://www.linkedin.com", "https://www.linkedin.com/oauth"];
const DEFAULT_SCOPES = ["openid", "profile", "email"];

/** The `warlock add` feature that installs `jose`. */
export const LINKEDIN_AUTH_FEATURE = "auth-linkedin";

/** LinkedIn's key set, created once per process; `jose` caches the fetched JWKS inside it. */
let linkedinKeySet: unknown;

/**
 * LinkedIn sign-in: OpenID Connect authorization code flow with PKCE (S256)
 * and `state` and `nonce` — LinkedIn's "Sign In with LinkedIn using OpenID
 * Connect" product, the same shape as {@link GoogleProvider}. The code is
 * exchanged with plain `fetch`; the id_token is verified with `jose` against
 * LinkedIn's JWKS (signature, `iss`, `aud` = the client id, `exp`), then its
 * `nonce` is compared. No LinkedIn SDK.
 *
 * The exact issuer string LinkedIn signs (`ISSUERS` above) and whether its
 * token endpoint honours `code_verifier` are asserted from LinkedIn's public
 * OIDC docs, not from a live exchange — this package has no LinkedIn test
 * credentials. See the worker report for what is and is not proven.
 */
export class LinkedInProvider implements AuthProvider {
  public readonly name = "linkedin";

  public constructor(private readonly settings: LinkedInProviderConfig) {}

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
    const jose = await loadOptionalPeer<JoseModule>("jose", LINKEDIN_AUTH_FEATURE);

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
      // LinkedIn sends a boolean; anything else counts as NOT verified.
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
        throw new Error(`LinkedIn token endpoint answered ${response.status}`);
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
    linkedinKeySet ??= jose.createRemoteJWKSet(new URL(JWKS_URI));

    try {
      const { payload } = await jose.jwtVerify(idToken, linkedinKeySet, {
        issuer: ISSUERS,
        audience: this.settings.clientId,
      });

      return payload;
    } catch (error) {
      throw new InvalidProviderCallbackError("invalid-id-token", error);
    }
  }
}
