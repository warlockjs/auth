import type {
  AuthProvider,
  DiscordProviderConfig,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://discord.com/oauth2/authorize";
const TOKEN_ENDPOINT = "https://discord.com/api/oauth2/token";
const USER_ENDPOINT = "https://discord.com/api/users/@me";
const DEFAULT_SCOPES = ["identify", "email"];

type DiscordUser = {
  id: string;
  username: string;
  global_name?: string | null;
  avatar?: string | null;
  email?: string | null;
  verified?: boolean;
};

/**
 * Discord sign-in: plain OAuth 2 authorization code flow with PKCE (S256).
 * Like GitHub, Discord is not OpenID Connect — there is no `id_token`; the
 * access token is redeemed once for `/users/@me` over a direct HTTPS call.
 * No vendor SDK is involved.
 */
export class DiscordProvider implements AuthProvider {
  public readonly name = "discord";

  public constructor(private readonly settings: DiscordProviderConfig) {}

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
      email: user.email ?? undefined,
      emailVerified: user.verified === true,
      name: user.global_name ?? user.username,
      avatar: user.avatar
        ? `https://cdn.discordapp.com/avatars/${user.id}/${user.avatar}.png`
        : undefined,
      raw: user,
    };
  }

  /** Redeem the authorization code (with the PKCE verifier) for an access token. */
  private async exchangeCode(code: string, codeVerifier: string): Promise<string> {
    let body: { access_token?: unknown };

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
        throw new Error(`Discord token endpoint answered ${response.status}`);
      }

      body = (await response.json()) as { access_token?: unknown };
    } catch (error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", error);
    }

    if (typeof body.access_token !== "string" || body.access_token.length === 0) {
      throw new InvalidProviderCallbackError("missing-access-token");
    }

    return body.access_token;
  }

  private async fetchUser(accessToken: string): Promise<DiscordUser> {
    try {
      const response = await fetch(USER_ENDPOINT, {
        headers: { authorization: `Bearer ${accessToken}` },
      });

      if (!response.ok) {
        throw new Error(`Discord user endpoint answered ${response.status}`);
      }

      return (await response.json()) as DiscordUser;
    } catch (error) {
      throw new InvalidProviderCallbackError("profile-fetch-failed", error);
    }
  }
}
