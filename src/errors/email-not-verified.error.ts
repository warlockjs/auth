import { ForbiddenError } from "@warlock.js/core";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * The authenticated user has not verified their email address. Thrown by
 * `requireVerifiedEmail()`; core's error handler answers it with `403` and a
 * `payload.errorCode` of `EC007`.
 */
export class EmailNotVerifiedError extends ForbiddenError {
  public readonly code = AuthErrorCodes.EmailNotVerified;

  public constructor(message = "Email address is not verified.") {
    super(message, { errorCode: AuthErrorCodes.EmailNotVerified });
    this.name = "EmailNotVerifiedError";
  }
}
