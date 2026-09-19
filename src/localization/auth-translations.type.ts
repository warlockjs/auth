/**
 * Text for every error key auth passes to `t()`.
 *
 * Every key is required so a locale shipped by auth can never silently miss
 * one — translating a new `auth.errors.*` key means adding it here, and the
 * compiler then demands a string in each built-in locale.
 */
export type AuthErrorTranslations = {
  /** 401 — no credential was sent. */
  missingAccessToken: string;
  /** 401 — the credential is malformed, expired, or revoked. */
  invalidAccessToken: string;
  /** 401 — the credential is valid but its user type is not allowed here. */
  unauthorized: string;
  /** 403 — a cookie-authenticated unsafe request came from a foreign origin. */
  csrfOriginMismatch: string;
  /** 429 — login throttle lockout. */
  tooManyAttempts: string;
};

/**
 * One locale's worth of auth translations, shaped as the keyword tree
 * `@mongez/localization`'s `extend(localeCode, keywords)` accepts.
 */
export type AuthTranslations = {
  auth: {
    errors: AuthErrorTranslations;
  };
};
