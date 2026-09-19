import { config } from "@warlock.js/core";

/**
 * Prefixes `loginPath` with `locale` when `web`'s locale-URL routing is
 * active for that locale — so a guarded `/ar/admin` page redirects an
 * anonymous request to `/ar/login`, not the bare `/login` (finding: the
 * `returnUrl` carried the locale, the login destination itself did not).
 *
 * `auth` is not on `web`'s dependency graph, and `web` is not on `auth`'s
 * (neither package declares the other, in either `dependencies` or
 * `peerDependencies`) — so this cannot import `web`'s
 * `resolveLocaleRouting()` / `withLocalePrefix()` / `isPrefixedLocale()`
 * (`web/src/routing/locale-routing.ts`, `web/src/routing/locale-prefixed-paths.ts`).
 * Instead it reads the SAME config keys those read — `web.localeRouting.strategy`,
 * `app.localeCodes`, `app.localeCode` — by convention rather than by import,
 * the same pattern `web/src/server/auth-cookie-name.ts` uses in the other
 * direction for `auth.cookie.name`.
 *
 * Left alone (returned unchanged) when:
 * - `loginPath` is absolute (`http://…`, `https://…`) — a redirect target
 *   outside this app has no "locale prefix" to add.
 * - `loginPath` is already prefixed with a known locale code (an app that
 *   configured `auth.pageAuth.loginPath` as `/ar/login` itself).
 * - `web.localeRouting.strategy` is `"none"` (the default) or unset.
 * - `locale` is not one of `app.localeCodes`, or — under
 *   `"prefix-except-default"` — `locale` is the default locale.
 */
export function localizedLoginPath(loginPath: string, locale: string): string {
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(loginPath)) return loginPath;

  const strategy = config.key<string>("web.localeRouting.strategy", "none");

  if (strategy !== "prefix" && strategy !== "prefix-except-default") return loginPath;

  const codes = config.key<string[]>("app.localeCodes", []) ?? [];

  if (isAlreadyPrefixed(loginPath, codes)) return loginPath;

  if (!codes.includes(locale)) return loginPath;

  if (strategy === "prefix-except-default") {
    const defaultLocale = config.key<string>("app.localeCode", "");

    if (locale === defaultLocale) return loginPath;
  }

  return loginPath === "/" ? `/${locale}` : `/${locale}${loginPath}`;
}

/** `true` when `path` already starts with one of `codes` as its own URL segment. */
function isAlreadyPrefixed(path: string, codes: readonly string[]): boolean {
  return codes.some((code) => path === `/${code}` || path.startsWith(`/${code}/`));
}
