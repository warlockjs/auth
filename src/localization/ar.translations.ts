import type { AuthTranslations } from "./auth-translations.type";

/**
 * Built-in Arabic text for auth's translation keys. Applications override
 * any of these by registering the same key in their own locale files.
 */
export const authArabicTranslations: AuthTranslations = {
  auth: {
    errors: {
      missingAccessToken: "رمز الوصول مفقود.",
      invalidAccessToken: "رمز الوصول غير صالح أو منتهي الصلاحية.",
      unauthorized: "غير مصرح لك بالوصول إلى هذا المورد.",
      csrfOriginMismatch: "مصدر الطلب غير مسموح به.",
      tooManyAttempts: "محاولات كثيرة جدًا. يرجى المحاولة مرة أخرى لاحقًا.",
    },
  },
};
