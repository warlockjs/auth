import type {
  AuthProvider,
  FacebookProviderConfig,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://www.facebook.com/v19.0/dialog/oauth";
const TOKEN_ENDPOINT = "https://graph.facebook.com/v19.0/oauth/access_token";
const USER_ENDPOINT = "https://graph.facebook.com/v19.0/me";
const DEFAULT_SCOPES = ["email", "public_profile"];

type FacebookUser = {
  id: string;
  name?: string;
  email?: string;
  picture?: { data?: { url?: string } };
};

/**
 * Facebook sign-in: plain OAuth 2 authorization code flow with PKCE (S256).
 * Facebook is not OpenID Connect — there is no `id_token`. Unlike every other
 * built-in provider, Facebook's token endpoint is redeemed with a `GET`
 * request (query-string parameters, not a POST body) — that shape comes
 * straight from Facebook's Graph API docs, not from a live exchange (this
 * package has no Facebook test app). The profile is then read once from
 * `Graph /me?fields=id,name,email,picture`, over a direct HTTPS call; no
 * Facebook SDK is involved.
 *
 * Facebook only ever returns a confirmed address for `email` — there is no
 * separate verified flag — so an email present on the profile is treated as
 * verified. An app without `email` permission granted, or one that simply has
 * no email on file, gets `email: undefined`, which `resolveProviderUser`
 * already rejects as an unverified/missing email, the same path GitHub's
 * unverified addresses take.
 */
export class FacebookProvider implements AuthProvider {
  public readonly name = "facebook";

  public constructor(private readonly settings: FacebookProviderConfig) {}

  public authorizationUrl(state: ProviderAuthorizationState): string {
    const url = new URL(AUTHORIZATION_ENDPOINT);

    url.searchParams.set("client_id", this.settings.clientId);
    url.searchParams.set("redirect_uri", this.settings.redirectUri);
    url.searchParams.set("response_type", "code");
    url.searchParams.set("scope", (this.settings.scopes ?? DEFAULT_SCOPES).join(" "));
    url.searchParams.set("state", state.state);
    url.searchParams.set("code_challenge", pkceChallenge(state.codeVerifier));
    url.searchParams.set("code_challenge_method", "S256");

    return url.toString();
  }

  public async handleCallback({
    query,
    expected,
  }: ProviderCallbackParams): Promise<ProviderProfile> {
    const code = query.code;

    if (typeof code !== "string" || code.length === 0) {
      throw new InvalidProviderCallbackError("missing-code");
    }

    const accessToken = await this.exchangeCode(code, expected.codeVerifier);
    const user = await this.fetchUser(accessToken);

    if (typeof user.id !== "string" || user.id.length === 0) {
      throw new InvalidProviderCallbackError("missing-subject");
    }

    return {
      provider: this.name,
      providerUserId: user.id,
      email: user.email,
      // Facebook does not report a verification flag; a returned address is confirmed.
      emailVerified: typeof user.email === "string" && user.email.length > 0,
      name: user.name,
      avatar: user.picture?.data?.url,
      raw: user,
    };
  }

  /** Redeem the authorization code (with the PKCE verifier) for an access token. */
  private async exchangeCode(code: string, codeVerifier: string): Promise<string> {
    let body: { access_token?: unknown; error?: unknown };

    try {
      const url = new URL(TOKEN_ENDPOINT);

      url.searchParams.set("client_id", this.settings.clientId);
      url.searchParams.set("client_secret", this.settings.clientSecret);
      url.searchParams.set("redirect_uri", this.settings.redirectUri);
      url.searchParams.set("code", code);
      url.searchParams.set("code_verifier", codeVerifier);

      const response = await fetch(url.toString(), { headers: { accept: "application/json" } });

      if (!response.ok) {
        throw new Error(`Facebook token endpoint answered ${response.status}`);
      }

      body = (await response.json()) as { access_token?: unknown; error?: unknown };
    } catch (error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", error);
    }

    if (body.error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", body.error);
    }

    if (typeof body.access_token !== "string" || body.access_token.length === 0) {
      throw new InvalidProviderCallbackError("missing-access-token");
    }

    return body.access_token;
  }

  private async fetchUser(accessToken: string): Promise<FacebookUser> {
    try {
      const url = new URL(USER_ENDPOINT);

      url.searchParams.set("fields", "id,name,email,picture");
      url.searchParams.set("access_token", accessToken);

      const response = await fetch(url.toString(), { headers: { accept: "application/json" } });

      if (!response.ok) {
        throw new Error(`Facebook /me endpoint answered ${response.status}`);
      }

      return (await response.json()) as FacebookUser;
    } catch (error) {
      throw new InvalidProviderCallbackError("profile-fetch-failed", error);
    }
  }
}
