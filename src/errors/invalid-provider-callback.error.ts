import { BadRequestError } from "@warlock.js/core";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * A redirect-provider callback was rejected — missing, forged or expired
 * state cookie, `state` mismatch, failed code exchange, or an id_token with a
 * bad signature, issuer, audience, expiry or nonce. `reason` is for logs;
 * the response message stays generic. Answers `400` with `EC009`.
 */
export class InvalidProviderCallbackError extends BadRequestError {
  public readonly code = AuthErrorCodes.InvalidProviderCallback;

  public constructor(
    public readonly reason: string,
    cause?: unknown,
  ) {
    super("Login with the provider failed.", {
      errorCode: AuthErrorCodes.InvalidProviderCallback,
    });
    this.name = "InvalidProviderCallbackError";
    this.cause = cause;
  }
}
