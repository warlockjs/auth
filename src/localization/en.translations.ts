import type { AuthTranslations } from "./auth-translations.type";

/**
 * Built-in English text for auth's translation keys. Applications override
 * any of these by registering the same key in their own locale files.
 */
export const authEnglishTranslations: AuthTranslations = {
  auth: {
    errors: {
      missingAccessToken: "Missing access token.",
      invalidAccessToken: "Invalid or expired access token.",
      unauthorized: "You are not authorized to access this resource.",
      csrfOriginMismatch: "Request origin is not allowed.",
      tooManyAttempts: "Too many attempts. Please try again later.",
    },
  },
};
