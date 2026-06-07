import { config } from "@warlock.js/core";
import {
  createSigner,
  createVerifier,
  type Algorithm,
  type SignerOptions,
  type VerifierOptions,
} from "fast-jwt";
import ms from "ms";

const getSecretKey = () => config.key("auth.jwt.secret") as string;
const getAlgorithm = () => config.key("auth.jwt.algorithm", "HS256") as Algorithm;

// Refresh tokens may declare their own secret. When `auth.jwt.refresh.secret`
// is unset/empty we fall back to the main JWT secret, matching the documented
// optional behavior in `contracts/types.ts`.
const getRefreshSecretKey = () =>
  (config.key("auth.jwt.refresh.secret") || getSecretKey()) as string;
// Refresh token validity — defaults to 7d when not configured. Opt in to
// no-expiry semantics with `NO_EXPIRATION` (100y) from `contracts/types.ts`.
const getRefreshTokenValidity = () => {
  const expiresIn = config.key("auth.jwt.refresh.expiresIn") || "7d";

  return ms(expiresIn);
};

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
  async verify<T = any>(
    token: string,
    {
      key = getSecretKey(),
      algorithms = getAlgorithm() ? [getAlgorithm()] : undefined,
      ...options
    }: VerifierOptions & { key?: string } = {},
  ): Promise<T> {
    const verify = createVerifier({ key, ...options, algorithms });

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
  async verifyRefreshToken<T = any>(
    token: string,
    {
      key = getRefreshSecretKey(),
      algorithms = [getAlgorithm()],
      ...options
    }: VerifierOptions & { key?: string } = {},
  ): Promise<T> {
    const verify = createVerifier({ key, algorithms, ...options });

    const decoded = await verify(token);

    assertTokenType(decoded, REFRESH_TOKEN_TYPE);

    return decoded;
  },
};
