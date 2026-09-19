import { readdirSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";
import { afterEach, describe, expect, it } from "vitest";
import { extend, getCurrentLocaleCode, setCurrentLocaleCode, t } from "@warlock.js/core";
import { registerAuthTranslations } from "./register-auth-translations";

// The package entry is what an application imports; loading it proves the
// defaults are wired at import time, with no app locale registered.
import "../index";

const SOURCE_ROOT = resolve(__dirname, "..");

/**
 * Every literal key auth passes to `t()` / `trans()` in its shipped source.
 * Scanned rather than hand-listed so a key added later without a default
 * turns this spec red instead of leaking the raw key to clients.
 */
function inventoryTranslationKeys(): string[] {
  const keys = new Set<string>();
  const keyPattern = /\b(?:t|trans)\(\s*["'`]([\w.-]+)["'`]/g;

  const walk = (directory: string): void => {
    for (const entry of readdirSync(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);

      if (entry.isDirectory()) {
        walk(path);
        continue;
      }

      if (!entry.name.endsWith(".ts") || entry.name.endsWith(".spec.ts")) {
        continue;
      }

      for (const match of readFileSync(path, "utf8").matchAll(keyPattern)) {
        keys.add(match[1]);
      }
    }
  };

  walk(SOURCE_ROOT);

  return [...keys].sort();
}

const inventory = inventoryTranslationKeys();
const originalLocale = getCurrentLocaleCode();

afterEach(() => {
  setCurrentLocaleCode(originalLocale);
});

describe("auth default translations", () => {
  it("inventories the keys auth translates", () => {
    expect(inventory).toEqual([
      "auth.errors.csrfOriginMismatch",
      "auth.errors.invalidAccessToken",
      "auth.errors.missingAccessToken",
      "auth.errors.tooManyAttempts",
      "auth.errors.unauthorized",
    ]);
  });

  it.each(inventory)("resolves %s to English text with no app locale registered", (key) => {
    setCurrentLocaleCode("en");

    const text = t(key);

    expect(typeof text).toBe("string");
    expect(text).not.toBe(key);
    expect(text.trim().length).toBeGreaterThan(0);
  });

  it.each(inventory)("resolves %s to Arabic text for the ar locale", (key) => {
    setCurrentLocaleCode("en");
    const english = t(key);

    setCurrentLocaleCode("ar");
    const arabic = t(key);

    expect(arabic).not.toBe(key);
    expect(arabic).not.toBe(english);
    expect(arabic).toMatch(/[؀-ۿ]/);
  });

  it("lets an app translation registered after the defaults override them", () => {
    extend("en", { auth: { errors: { unauthorized: "App says no." } } });

    setCurrentLocaleCode("en");

    expect(t("auth.errors.unauthorized")).toBe("App says no.");
    // A sibling key the app did not translate still falls back to the default.
    expect(t("auth.errors.missingAccessToken")).not.toBe("auth.errors.missingAccessToken");
  });

  it("never clobbers an app translation registered before the defaults", () => {
    extend("en", { auth: { errors: { csrfOriginMismatch: "App origin text." } } });

    registerAuthTranslations();
    setCurrentLocaleCode("en");

    expect(t("auth.errors.csrfOriginMismatch")).toBe("App origin text.");
  });
});
