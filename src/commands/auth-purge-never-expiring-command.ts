import { colors } from "@mongez/copper";
import { command } from "@warlock.js/core";
import { authService } from "../services/auth.service";

/**
 * Register the `auth.purge-never-expiring` CLI command — remediation for the
 * pre-4.12.0 `expiresIn` defect (#25).
 *
 * **Why a command and not a migration.** The rows this removes cannot be
 * selected by a date predicate (an `Invalid Date` compares `false` against
 * every date, so `WHERE expires_at < now()` never matches one) and the
 * definitive signal — a token with no `exp` claim — lives inside the JWT
 * string, not in a column. A migration would also run once, silently, at deploy
 * time; an operator dealing with possibly-leaked credentials needs to *look*
 * first, then act, and to repeat it. Hence `--dry-run`, which is the default
 * posture this command is expected to be run in first.
 *
 * A migration is additionally the wrong shape for a fix that must reach both
 * supported stores: the same row is a different thing in MongoDB and Postgres,
 * and this goes through the models so a registered override
 * (`config.auth.accessToken.model`) is honoured.
 *
 * @example
 * ```bash
 * warlock auth.purge-never-expiring --dry-run   # report only
 * warlock auth.purge-never-expiring             # report, then delete
 * ```
 */
export function registerAuthPurgeNeverExpiringCommand() {
  return command({
    name: "auth.purge-never-expiring",
    description:
      "Find (and delete) token rows that can never expire — an unusable expires_at, or a token with no exp claim",
    options: [
      {
        text: "--dry-run",
        description: "Report the affected rows without deleting anything",
        type: "boolean",
      },
    ],
    preload: {
      env: true,
      config: ["auth", "database"],
      connectors: ["database"],
    },
    action: async (data: { options?: Record<string, unknown> } = {}) => {
      // Core camelCases flags (`--dry-run` ⇒ `dryRun`); both spellings are read
      // so the command does not depend on that detail staying true.
      //
      // Read fail-safe: the flag counts as set unless it is *explicitly* false
      // (`--dry-run=false`). An operator who asked to look before deleting and
      // got a delete because a flag arrived as `"true"` instead of `true` would
      // lose live credentials to a parsing detail.
      const flags = data.options ?? {};
      const flag = flags["dryRun"] ?? flags["dry-run"];
      const dryRun = flag !== undefined && flag !== false && flag !== "false";

      console.log(colors.cyan("🔎 Scanning for tokens that can never expire..."));

      const { accessTokens, refreshTokens } = await authService.findNeverExpiringTokens();
      const total = accessTokens.length + refreshTokens.length;

      if (total === 0) {
        console.log(colors.green("✅ No never-expiring tokens found."));

        return;
      }

      console.log(
        colors.yellow(
          `⚠️  ${total} never-expiring token(s): ` +
            `${accessTokens.length} access, ${refreshTokens.length} refresh.`,
        ),
      );

      // Identify each row so an operator can correlate with their own audit
      // trail before (or after) the rows are gone. The token string itself is
      // never printed — it is a live credential until this command removes it.
      for (const token of accessTokens) {
        console.log(
          colors.yellow(
            `  access  id=${token.id} user_id=${token.get("user_id")} ` +
              `user_type=${token.get("user_type")} expires_at=${String(token.get("expires_at"))}`,
          ),
        );
      }

      for (const token of refreshTokens) {
        console.log(
          colors.yellow(
            `  refresh id=${token.id} user_id=${token.get("user_id")} ` +
              `user_type=${token.get("user_type")} expires_at=${String(token.get("expires_at"))}`,
          ),
        );
      }

      if (dryRun) {
        console.log(
          colors.cyan("Dry run — nothing deleted. Re-run without --dry-run to revoke these tokens."),
        );

        return;
      }

      // Re-selects rather than deleting the rows just listed: the delete then
      // acts on the table's current state instead of a snapshot taken before
      // the operator read the report. A second full scan is affordable here —
      // this is a one-off remediation, not a request path.
      const purged = await authService.purgeNeverExpiringTokens();

      console.log(
        colors.green(
          `✅ Revoked ${purged.accessTokens} access token(s) and ` +
            `${purged.refreshTokens} refresh token(s). Affected users must log in again.`,
        ),
      );
    },
  });
}
