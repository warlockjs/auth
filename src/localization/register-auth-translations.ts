import { flatten, get, set } from "@mongez/reinforcements";
import { extend, getKeywordsListOf, type Keywords } from "@warlock.js/core";
import { authDefaultTranslations } from "./auth-default-translations";

/**
 * Register auth's built-in translations with `@mongez/localization`, the
 * same store `t()` from `@warlock.js/core` reads.
 *
 * Only keys the application has NOT already translated are added, so an app
 * translation wins regardless of load order: registered before this runs, it
 * is left untouched; registered after, `extend()` merges it over the default.
 * An app locale file that predates a newer auth key therefore gets the
 * default text for that key instead of the raw key string.
 *
 * Runs once at import of `@warlock.js/auth`; safe to call again.
 */
export function registerAuthTranslations(): void {
  for (const [localeCode, translations] of Object.entries(authDefaultTranslations)) {
    const existing = getKeywordsListOf(localeCode) ?? {};
    const missing: Keywords = {};

    for (const [key, text] of Object.entries(flatten(translations))) {
      if (get(existing, key) === undefined) {
        set(missing, key, text);
      }
    }

    if (Object.keys(missing).length > 0) {
      extend(localeCode, missing);
    }
  }
}
