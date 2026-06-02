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

    const token = await sign({ ...payload });
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

    return await verify(token as string);
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
    return sign({ ...payload });
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
    return await verify(token);
  },
};
