import { BadRequestError } from "@warlock.js/core";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * An email-verification or password-reset token was rejected: unknown, issued
 * for the other purpose, expired, or already consumed (including losing a
 * concurrent consumption race). Deliberately ONE error for all of them, so a
 * caller cannot probe which case applies. Answers `400` with `EC008`.
 */
export class InvalidOneTimeTokenError extends BadRequestError {
  public readonly code = AuthErrorCodes.InvalidOneTimeToken;

  public constructor(message = "Invalid or expired token.") {
    super(message, { errorCode: AuthErrorCodes.InvalidOneTimeToken });
    this.name = "InvalidOneTimeTokenError";
  }
}
