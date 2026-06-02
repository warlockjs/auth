import { resolve } from "node:path";
import { defineConfig } from "vitest/config";

export default defineConfig({
  resolve: {
    alias: {
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
