import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
      // Deep, package-specifier-shaped paths into two specific core files
      // (never the whole `@warlock.js/core` barrel) — kept ahead of the
      // bare "@warlock.js/core" entry below so Vite matches the longer key
      // first. `request-locals-isolation.spec.ts` needs core's REAL
      // `Request`/`requestContext`/`useCurrentUser` (not stubbed) and
      // reaches them this way rather than a `../../../core/src/...`
      // relative crossing, which `strictness-gate.ts`'s `PROGRAM_CONTAINMENT_CODES`
      // would charge to auth, and rather than `importOriginal()` on the
      // bare specifier, which forces the whole real barrel — including
      // `core/src/database/utils.ts`, which imports `@warlock.js/auth`
      // back (a genuine core→auth cycle) — to evaluate mid-mock.
      "@warlock.js/core/src/http/request": resolve(__dirname, "../core/src/http/request.ts"),
      "@warlock.js/core/src/http/context/request-context": resolve(
        __dirname,
        "../core/src/http/context/request-context.ts",
      ),
      "@warlock.js/core": resolve(__dirname, "../core/src/index.ts"),
      "@warlock.js/cascade": resolve(__dirname, "../cascade/src/index.ts"),
      "@warlock.js/logger": resolve(__dirname, "../logger/src/index.ts"),
      "@warlock.js/seal": resolve(__dirname, "../seal/src/index.ts"),
      "@warlock.js/fs": resolve(__dirname, "../fs/src/index.ts"),
      "@warlock.js/cache": resolve(__dirname, "../cache/src/index.ts"),
    },
  },
  test: {
    environment: "node",
    globals: false,
    include: ["src/**/*.spec.ts"],
  },
});
