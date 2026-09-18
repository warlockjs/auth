import type {
  AuthProvider,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
  XProviderConfig,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://twitter.com/i/oauth2/authorize";
const TOKEN_ENDPOINT = "https://api.twitter.com/2/oauth2/token";
const USER_ENDPOINT = "https://api.twitter.com/2/users/me";
const DEFAULT_SCOPES = ["tweet.read", "users.read"];

type XUser = {
  id: string;
  name?: string;
  username?: string;
  profile_image_url?: string;
};

/**
 * X (Twitter) sign-in: OAuth 2.0 authorization code flow with PKCE (S256). X
 * is not OpenID Connect — there is no `id_token`. X's confidential clients
 * authenticate the token request with HTTP Basic auth (`client_id:client_secret`),
 * on top of PKCE — both are required together, per X's developer docs (this
 * package has no X test app, so the exchange itself is unverified against a
 * live endpoint). The access token is then redeemed once against
 * `GET /2/users/me`.
 *
 * X does not return an email address from this API at all — there is no
 * "email" scope to request it with — so `email` is always left `undefined`
 * rather than invented, and `resolveProviderUser` rejects it the same way it
 * rejects any other missing email.
 */
export class XProvider implements AuthProvider {
  public readonly name = "x";

  public constructor(private readonly settings: XProviderConfig) {}

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
      // X does not hand back an email address from this API.
      email: undefined,
      emailVerified: false,
      name: user.name ?? user.username,
      avatar: user.profile_image_url,
      raw: user,
    };
  }

  /** Basic-auth credential for the confidential-client token request. */
  private basicAuth(): string {
    return Buffer.from(`${this.settings.clientId}:${this.settings.clientSecret}`).toString(
      "base64",
    );
  }

  /** Redeem the authorization code (with the PKCE verifier) for an access token. */
  private async exchangeCode(code: string, codeVerifier: string): Promise<string> {
    let body: { access_token?: unknown; error?: unknown };

    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          authorization: `Basic ${this.basicAuth()}`,
        },
        body: new URLSearchParams({
          code,
          client_id: this.settings.clientId,
          redirect_uri: this.settings.redirectUri,
          grant_type: "authorization_code",
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        throw new Error(`X token endpoint answered ${response.status}`);
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

  private async fetchUser(accessToken: string): Promise<XUser> {
    try {
      const url = new URL(USER_ENDPOINT);

      url.searchParams.set("user.fields", "profile_image_url");

      const response = await fetch(url.toString(), {
        headers: { authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        throw new Error(`X /2/users/me endpoint answered ${response.status}`);
      }

      const body = (await response.json()) as { data?: XUser };

      return body.data ?? ({} as XUser);
    } catch (error) {
      throw new InvalidProviderCallbackError("profile-fetch-failed", error);
    }
  }
}
