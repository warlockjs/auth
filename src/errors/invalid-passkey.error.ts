import { BadRequestError } from "@warlock.js/core";
import { AuthErrorCodes } from "../utils/auth-error-codes";

/**
 * A passkey registration or authentication was rejected — unknown, expired
 * or used challenge, unknown credential, failed verification, or a signature
 * counter that did not advance. `reason` is for logs; the message stays
 * generic. Answers `400` with `EC011`.
 */
export class InvalidPasskeyError extends BadRequestError {
  public readonly code = AuthErrorCodes.InvalidPasskey;

  public constructor(
    public readonly reason: string,
    cause?: unknown,
  ) {
    super("Passkey verification failed.", { errorCode: AuthErrorCodes.InvalidPasskey });
    this.name = "InvalidPasskeyError";
    this.cause = cause;
  }
}
