import type {
  AuthProvider,
  GitHubProviderConfig,
  ProviderAuthorizationState,
  ProviderCallbackParams,
  ProviderProfile,
} from "../contracts/providers";
import { InvalidProviderCallbackError } from "../errors/invalid-provider-callback.error";
import { pkceChallenge } from "./google-provider";

const AUTHORIZATION_ENDPOINT = "https://github.com/login/oauth/authorize";
const TOKEN_ENDPOINT = "https://github.com/login/oauth/access_token";
const USER_ENDPOINT = "https://api.github.com/user";
const EMAILS_ENDPOINT = "https://api.github.com/user/emails";
const DEFAULT_SCOPES = ["read:user", "user:email"];

/** GitHub requires a `User-Agent`; identify the framework, not the app. */
const USER_AGENT = "warlock.js-auth";

type GitHubUser = {
  id: number;
  login: string;
  name?: string | null;
  avatar_url?: string;
};

type GitHubEmail = {
  email: string;
  primary: boolean;
  verified: boolean;
};

/**
 * GitHub sign-in: plain OAuth 2 authorization code flow with PKCE (S256).
 * GitHub is not OpenID Connect — there is no `id_token` and nothing to verify
 * against a JWKS. The access token is redeemed once for the profile, over a
 * direct HTTPS call to GitHub's API; no vendor SDK is involved.
 *
 * The account email is fetched separately from `/user/emails`, because
 * `/user.email` is `null` unless the user made it public — the emails
 * endpoint is also where GitHub reports whether an address is verified.
 */
export class GitHubProvider implements AuthProvider {
  public readonly name = "github";

  public constructor(private readonly settings: GitHubProviderConfig) {}

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
    const email = await this.fetchPrimaryEmail(accessToken);

    if (typeof user.id !== "number") {
      throw new InvalidProviderCallbackError("missing-subject");
    }

    return {
      provider: this.name,
      providerUserId: String(user.id),
      email: email?.email,
      emailVerified: email?.verified === true,
      name: user.name ?? user.login,
      avatar: user.avatar_url,
      raw: user,
    };
  }

  /** Redeem the authorization code (with the PKCE verifier) for an access token. */
  private async exchangeCode(code: string, codeVerifier: string): Promise<string> {
    let body: { access_token?: unknown; error?: unknown };

    try {
      const response = await fetch(TOKEN_ENDPOINT, {
        method: "POST",
        headers: {
          "content-type": "application/x-www-form-urlencoded",
          accept: "application/json",
        },
        body: new URLSearchParams({
          code,
          client_id: this.settings.clientId,
          client_secret: this.settings.clientSecret,
          redirect_uri: this.settings.redirectUri,
          code_verifier: codeVerifier,
        }),
      });

      if (!response.ok) {
        throw new Error(`GitHub token endpoint answered ${response.status}`);
      }

      body = (await response.json()) as { access_token?: unknown; error?: unknown };
    } catch (error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", error);
    }

    // GitHub answers 200 even on a rejected code, with `error` set instead.
    if (body.error) {
      throw new InvalidProviderCallbackError("code-exchange-failed", body.error);
    }

    if (typeof body.access_token !== "string" || body.access_token.length === 0) {
      throw new InvalidProviderCallbackError("missing-access-token");
    }

    return body.access_token;
  }

  private async fetchUser(accessToken: string): Promise<GitHubUser> {
    try {
      const response = await fetch(USER_ENDPOINT, {
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/vnd.github+json",
          "user-agent": USER_AGENT,
        },
      });

      if (!response.ok) {
        throw new Error(`GitHub user endpoint answered ${response.status}`);
      }

      return (await response.json()) as GitHubUser;
    } catch (error) {
      throw new InvalidProviderCallbackError("profile-fetch-failed", error);
    }
  }

  /** The primary, verified email — `undefined` when none is both primary and verified. */
  private async fetchPrimaryEmail(accessToken: string): Promise<GitHubEmail | undefined> {
    let emails: GitHubEmail[];

    try {
      const response = await fetch(EMAILS_ENDPOINT, {
        headers: {
          authorization: `Bearer ${accessToken}`,
          accept: "application/vnd.github+json",
          "user-agent": USER_AGENT,
        },
      });

      if (!response.ok) {
        throw new Error(`GitHub emails endpoint answered ${response.status}`);
      }

      emails = (await response.json()) as GitHubEmail[];
    } catch (error) {
      throw new InvalidProviderCallbackError("profile-fetch-failed", error);
    }

    return emails.find((email) => email.primary && email.verified);
  }
}
