import { colors } from "@mongez/copper";
import { command } from "@warlock.js/core";
import { authService } from "../services/auth.service";

/**
 * Register the auth:cleanup CLI command
 *
 * @example
 * ```bash
 * warlock auth:cleanup
 * ```
 */
export function registerAuthCleanupCommand() {
  return command({
    name: "auth.cleanup",
    description: "Remove expired refresh tokens from the database",
    preload: {
      env: true,
      config: ["auth", "database"],
      connectors: ["database"],
    },
    action: async () => {
      console.log(colors.cyan("🧹 Cleaning up expired tokens..."));

      const count = await authService.cleanupExpiredTokens();

      if (count === 0) {
        console.log(colors.green("✅ No expired tokens found."));
      } else {
        console.log(colors.green(`✅ Removed ${count} expired token(s).`));
      }
    },
  });
}
