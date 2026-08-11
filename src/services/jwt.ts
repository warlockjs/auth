import { createSigner, createVerifier, type SignerOptions, type VerifierOptions } from "fast-jwt";
import { authConfig } from "./auth-config";

const getSecretKey = () => authConfig.accessToken.secret();
const getAlgorithm = () => authConfig.accessToken.algorithm();

// Refresh tokens may declare their own secret; when unset/empty we fall back to
// the access-token secret (the documented optional behavior).
const getRefreshSecretKey = () => authConfig.refreshToken.secret() || getSecretKey();

/**
 * Token class. Stamped as the `tokenType` claim on every signed token and
 * checked on verify so an access token can never be accepted where a refresh
 * token is expected (and vice versa) — even when both share the same secret
 * under the documented refresh-secret fallback. Legacy tokens minted before
 * this claim existed carry no `tokenType` and remain accepted; a *mismatched*
 * type is always rejected.
 */
export type TokenType = "access" | "refresh";

const ACCESS_TOKEN_TYPE: TokenType = "access";
const REFRESH_TOKEN_TYPE: TokenType = "refresh";

/**
 * Reject the token when its `tokenType` claim is present and does not match the
 * expected class. Absent claim ⇒ legacy token, accepted (backward compatible).
 */
function assertTokenType(decoded: unknown, expected: TokenType): void {
  const actual = (decoded as { tokenType?: unknown } | null | undefined)?.tokenType;

  if (typeof actual === "string" && actual !== expected) {
    throw new Error(`Invalid token type: expected "${expected}", received "${actual}".`);
  }
}

/**
 * Claims no token may be missing, whatever the caller asks for.
 *
 * A JWT with no `exp` is not "a token with a long life" — it is a credential
 * with *no* life, because a verifier with no deadline to check simply succeeds,
 * forever (measured against `fast-jwt@6.2.4`: a token with no `exp` verifies
 * unchanged at `clockTimestamp` + 100 years). Nothing in this package can mint
 * one as of 4.12.0, but tokens minted by an earlier version are already in the
 * wild, so the rejection lives on the *verify* side where it catches a token
 * from any version, including one signed by a service this package never ran.
 *
 * There is no legitimate source to preserve: an app that wants a token that
 * effectively never expires sets `expiresIn: NO_EXPIRATION` (`"100y"`), which
 * mints a real `exp` roughly a century out (measured: `ms("100y")` ⇒
 * `3155760000000`, `exp - iat` ⇒ `3155760000` seconds). "No deadline" and "a
 * distant deadline" are different things, and only the second one is asked for.
 */
const REQUIRED_CLAIMS = ["exp"];

/**
 * Union the caller's `requiredClaims` with the mandatory ones — a caller may
 * add requirements, never drop them.
 */
function withRequiredClaims(callerClaims?: string[]): string[] {
  if (!callerClaims?.length) return REQUIRED_CLAIMS;

  return [...new Set([...callerClaims, ...REQUIRED_CLAIMS])];
}

export const jwt = {
  /**
   * Generate a new JWT token for the user.
   * @param payload The payload to encode in the JWT token.
   */
  async generate(
    payload: any,
    {
      key = getSecretKey(),
      algorithm = getAlgorithm(),
      ...options
    }: SignerOptions & { key?: string } = {},
  ): Promise<string> {
    // Create a signer function with predefined options
    const sign = createSigner({ key, ...options, algorithm });

    const token = await sign({ ...payload, tokenType: ACCESS_TOKEN_TYPE });
    return token;
  },

  /**
   * Verify the given token.
   * @param token The JWT token to verify.
   * @returns The decoded token payload if verification is successful.
   */
  async verify<T = unknown>(
    token: string,
    {
      key = getSecretKey(),
      algorithms = [getAlgorithm()],
      requiredClaims,
      ...options
    }: VerifierOptions & { key?: string } = {},
  ): Promise<T> {
    const verify = createVerifier({
      key,
      ...options,
      algorithms,
      requiredClaims: withRequiredClaims(requiredClaims),
    });

    const decoded = await verify(token as string);

    assertTokenType(decoded, ACCESS_TOKEN_TYPE);

    return decoded;
  },

  /**
   * Generate a new refresh token for the user.
   */
  async generateRefreshToken(
    payload: any,
    {
      key = getRefreshSecretKey(),
      expiresIn,
      algorithm = getAlgorithm(),
      ...options
    }: SignerOptions & { key?: string } = {},
  ): Promise<string> {
    const sign = createSigner({ key, expiresIn, algorithm, ...options });
    return sign({ ...payload, tokenType: REFRESH_TOKEN_TYPE });
  },

  /**
   * Verify the given refresh token.
   */
  async verifyRefreshToken<T = unknown>(
    token: string,
    {
      key = getRefreshSecretKey(),
      algorithms = [getAlgorithm()],
      requiredClaims,
      ...options
    }: VerifierOptions & { key?: string } = {},
  ): Promise<T> {
    const verify = createVerifier({
      key,
      algorithms,
      ...options,
      requiredClaims: withRequiredClaims(requiredClaims),
    });

    const decoded = await verify(token);

    assertTokenType(decoded, REFRESH_TOKEN_TYPE);

    return decoded;
  },
};
