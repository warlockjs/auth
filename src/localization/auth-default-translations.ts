import { authArabicTranslations } from "./ar.translations";
import type { AuthTranslations } from "./auth-translations.type";
import { authEnglishTranslations } from "./en.translations";

/**
 * Every locale auth ships default text for, keyed by locale code.
 */
export const authDefaultTranslations: Record<string, AuthTranslations> = {
  en: authEnglishTranslations,
  ar: authArabicTranslations,
};
