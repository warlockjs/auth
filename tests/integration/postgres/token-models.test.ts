import { MigrationRunner } from "@warlock.js/cascade";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AccessToken } from "../../../src/models/access-token/access-token.model";
import { AccessTokenMigration } from "../../../src/models/access-token/migration";
import { RefreshToken } from "../../../src/models/refresh-token/refresh-token.model";
import { RefreshTokenMigration } from "../../../src/models/refresh-token/migration";
import { startPostgresHarness, type PostgresHarness } from "../helpers/postgres-harness";

/**
 * Token MODELS against a REAL Postgres container. This is the layer the
 * mock-based unit suite is structurally blind to — it asserts behavior that
 * only a live datasource can prove:
 *
 *   - `revokeAllFor` / `revokeFamily` RETURN the revoked rows (the C1 defect: a
 *     `findAndUpdate` keyed on `revoked_at: null` re-queried after the update
 *     and returned `[]`, so per-token events never fired).
 *   - `revokeIfActive` is a genuine atomic guard: two concurrent rotations of
 *     one refresh token cannot both win (replay detection).
 *   - deletes are really awaited and really remove rows.
 *
 * The migrations are run through the real `MigrationRunner`, so a green setup is
 * also free proof that the migrations and the model schemas agree.
 */

// user_id is a UUID column, so the synthetic users carry UUID ids.
const USER_A = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", userType: "user" } as never;
const USER_B = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", userType: "user" } as never;

const DAY_MS = 86_400_000;
const future = () => new Date(Date.now() + DAY_MS);
const past = () => new Date(Date.now() - DAY_MS);

let harness: PostgresHarness;

beforeAll(async () => {
  harness = await startPostgresHarness();

  const runner = new MigrationRunner({ dataSource: harness.dataSource, verbose: false });
  await runner.run(RefreshTokenMigration);
  await runner.run(AccessTokenMigration);
}, 120_000);

afterAll(async () => {
  await harness?.stop();
});

beforeEach(async () => {
  await harness.query(`TRUNCATE TABLE "refresh_tokens", "access_tokens"`);
});

/** Live column names for a table, read from the catalog. */
async function columnNames(table: string): Promise<Set<string>> {
  const result = await harness.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns
     WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );

  return new Set(result.rows.map((row) => row.column_name));
}

describe("Postgres integration — schema ↔ migration parity", () => {
  it("the refresh_tokens table carries every column the model writes", async () => {
    const columns = await columnNames("refresh_tokens");

    for (const column of [
      "token",
      "user_id",
      "user_type",
      "family_id",
      "expires_at",
      "last_used_at",
      "revoked_at",
      "device_info",
    ]) {
      expect(columns.has(column)).toBe(true);
    }
  });

  it("the access_tokens table carries every column the model writes", async () => {
    const columns = await columnNames("access_tokens");

    for (const column of ["token", "user_id", "user_type", "expires_at"]) {
      expect(columns.has(column)).toBe(true);
    }
  });
});

describe("Postgres integration — RefreshToken", () => {
  it("issue persists a row that findByToken reads back", async () => {
    await RefreshToken.issue(USER_A, "rt-1", {
      familyId: "fam-1",
      expiresAt: future().toISOString(),
    });

    const found = await RefreshToken.findByToken("rt-1");

    expect(found).not.toBeNull();
    expect(found!.get("user_id")).toBe(USER_A.id);
    expect(found!.familyId).toBe("fam-1");
    expect(found!.isValid).toBe(true);
  });

  it("findForUser only returns a token that belongs to the caller", async () => {
    await RefreshToken.issue(USER_A, "rt-a", { familyId: "fa", expiresAt: future().toISOString() });

    expect(await RefreshToken.findForUser(USER_A, "rt-a")).not.toBeNull();
    expect(await RefreshToken.findForUser(USER_B, "rt-a")).toBeNull();
  });

  it("activeFor excludes expired and revoked tokens", async () => {
    await RefreshToken.issue(USER_A, "live", { familyId: "f1", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "expired", { familyId: "f2", expiresAt: past().toISOString() });
    await RefreshToken.issue(USER_A, "revoked", { familyId: "f3", expiresAt: future().toISOString() });

    const toRevoke = await RefreshToken.findByToken("revoked");
    await toRevoke!.revoke();

    const active = await RefreshToken.activeFor(USER_A);
    const tokens = active.map((row) => row.get("token"));

    expect(tokens).toContain("live");
    expect(tokens).not.toContain("expired");
    expect(tokens).not.toContain("revoked");
  });

  it("revokeAllFor revokes every active token AND returns the revoked rows (C1)", async () => {
    await RefreshToken.issue(USER_A, "r1", { familyId: "f1", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "r2", { familyId: "f2", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_B, "other", { familyId: "f3", expiresAt: future().toISOString() });

    const revoked = await RefreshToken.revokeAllFor(USER_A);

    // The whole point of C1: the returned set must NOT be empty, so callers can
    // emit a `token.revoked` event per row.
    expect(revoked.map((row) => row.get("token")).sort()).toEqual(["r1", "r2"]);

    // USER_A's rows are revoked in the DB; USER_B's is untouched.
    const live = await harness.query<{ token: string }>(
      `SELECT token FROM "refresh_tokens" WHERE revoked_at IS NULL`,
    );
    expect(live.rows.map((row) => row.token)).toEqual(["other"]);
  });

  it("revokeFamily revokes only the named family AND returns those rows (C1)", async () => {
    await RefreshToken.issue(USER_A, "f1-a", { familyId: "fam", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "f1-b", { familyId: "fam", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "f2", { familyId: "other", expiresAt: future().toISOString() });

    const revoked = await RefreshToken.revokeFamily("fam");

    expect(revoked.map((row) => row.get("token")).sort()).toEqual(["f1-a", "f1-b"]);

    const stillActive = await RefreshToken.findByToken("f2");
    expect(stillActive!.isRevoked).toBe(false);
  });

  it("revokeIfActive lets only ONE of two concurrent callers win (rotation replay guard)", async () => {
    await RefreshToken.issue(USER_A, "race", { familyId: "f", expiresAt: future().toISOString() });

    // Two independent in-memory copies of the SAME row, as two concurrent
    // rotation requests would load.
    const first = await RefreshToken.findByToken("race");
    const second = await RefreshToken.findByToken("race");

    const outcomes = await Promise.all([first!.revokeIfActive(), second!.revokeIfActive()]);

    expect(outcomes.filter(Boolean)).toHaveLength(1);
  });

  it("enforceMax revokes the oldest tokens so room is left for one more", async () => {
    for (const token of ["t1", "t2", "t3"]) {
      await RefreshToken.issue(USER_A, token, {
        familyId: token,
        expiresAt: future().toISOString(),
      });
    }

    // max = 2 → revoke down to at most 1 active (max - 1), making room.
    await RefreshToken.enforceMax(USER_A, 2);

    const active = await RefreshToken.activeFor(USER_A);
    expect(active).toHaveLength(1);
  });

  it("purgeExpired hard-deletes expired rows and returns them", async () => {
    await RefreshToken.issue(USER_A, "keep", { familyId: "f1", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "drop", { familyId: "f2", expiresAt: past().toISOString() });

    const purged = await RefreshToken.purgeExpired();

    expect(purged.map((row) => row.get("token"))).toEqual(["drop"]);

    const remaining = await harness.query<{ token: string }>(`SELECT token FROM "refresh_tokens"`);
    expect(remaining.rows.map((row) => row.token)).toEqual(["keep"]);
  });
});

describe("Postgres integration — AccessToken", () => {
  it("issue persists a row that findByToken reads back", async () => {
    await AccessToken.issue(USER_A, "at-1", future());

    const found = await AccessToken.findByToken("at-1");

    expect(found).not.toBeNull();
    expect(found!.userId).toBe(USER_A.id);
    expect(found!.userType).toBe("user");
  });

  it("deleteForUser removes only the caller's token", async () => {
    await AccessToken.issue(USER_A, "mine", future());
    await AccessToken.issue(USER_B, "theirs", future());

    await AccessToken.deleteForUser(USER_A, "mine");

    expect(await AccessToken.findByToken("mine")).toBeNull();
    expect(await AccessToken.findByToken("theirs")).not.toBeNull();
  });

  it("deleteAllForUser clears every token for the user", async () => {
    await AccessToken.issue(USER_A, "a1", future());
    await AccessToken.issue(USER_A, "a2", future());
    await AccessToken.issue(USER_B, "b1", future());

    await AccessToken.deleteAllForUser(USER_A);

    const remaining = await harness.query<{ token: string }>(`SELECT token FROM "access_tokens"`);
    expect(remaining.rows.map((row) => row.token)).toEqual(["b1"]);
  });

  it("purgeExpired removes expired access tokens and returns the count", async () => {
    await AccessToken.issue(USER_A, "live", future());
    await AccessToken.issue(USER_A, "stale", past());

    const count = await AccessToken.purgeExpired();

    expect(count).toBe(1);

    const remaining = await harness.query<{ token: string }>(`SELECT token FROM "access_tokens"`);
    expect(remaining.rows.map((row) => row.token)).toEqual(["live"]);
  });
});
