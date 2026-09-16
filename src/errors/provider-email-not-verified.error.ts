import { ForbiddenError } from "@warlock.js/core";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * The provider did not verify the email on a profile with no existing link,
 * so auth refused to link it to (or create) an account. Answers `403` with
 * `EC010`.
 */
export class ProviderEmailNotVerifiedError extends ForbiddenError {
  public readonly code = AuthErrorCodes.ProviderEmailNotVerified;

  public constructor(message = "The provider has not verified this email address.") {
    super(message, { errorCode: AuthErrorCodes.ProviderEmailNotVerified });
    this.name = "ProviderEmailNotVerifiedError";
  }
}
