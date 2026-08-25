export enum AuthErrorCodes {
  /**
   * Missing Access Token Error Code EC001
   * EC001 = Missing Access Token
   */
  MissingAccessToken = "EC001", // Error Code 001
  /**
   * Invalid Access Token Error Code EC002
   * EC002 = Invalid Access Token
   */
  InvalidAccessToken = "EC002", // Error Code 002
  /**
   * Unauthorized Error Code EC003
   * EC003 = Unauthorized
   */
  Unauthorized = "EC003", // Error Code 003
  /**
   * Too Many Attempts Error Code EC004
   * EC004 = Too Many Attempts — issued by the login-throttle middleware once
   * a per-account or per-IP failure counter trips its threshold.
   */
  TooManyAttempts = "EC004", // Error Code 004
  /**
   * Invalid Token Type Error Code EC005
   * EC005 = Invalid Token Type — the token's `tokenType` claim does not match
   * what the caller expects (e.g. a refresh token presented where an access
   * token is required, or vice versa). Carried on the `code` property of the
   * `Error` thrown by `assertTokenType` (`services/jwt.ts`) so callers can
   * classify it as a credential failure without matching on the message.
   */
  InvalidTokenType = "EC005", // Error Code 005
}
