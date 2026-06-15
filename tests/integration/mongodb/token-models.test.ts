import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AccessToken } from "../../../src/models/access-token/access-token.model";
import { RefreshToken } from "../../../src/models/refresh-token/refresh-token.model";
import { startMongodbHarness, type MongodbHarness } from "../helpers/mongodb-harness";

/**
 * The token models against a REAL MongoDB container — the same behavioral
 * contract the Postgres suite proves, re-run on the OTHER driver to confirm the
 * model statics are genuinely driver-agnostic (the original audit flagged
 * targeted revocation as silently no-oping on Mongo). Collections auto-create on
 * first write, so there is no migration step here.
 *
 * Asserts the mock-blind behavior: bulk revoke RETURNS the rows (C1),
 * `revokeIfActive` is a real atomic guard (replay race), and deletes really
 * remove documents.
 */

const USER_A = { id: "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa", userType: "user" } as never;
const USER_B = { id: "bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb", userType: "user" } as never;

const DAY_MS = 86_400_000;
const future = () => new Date(Date.now() + DAY_MS);
const past = () => new Date(Date.now() - DAY_MS);

let harness: MongodbHarness;

beforeAll(async () => {
  harness = await startMongodbHarness();
}, 120_000);

afterAll(async () => {
  await harness?.stop();
});

beforeEach(async () => {
  await harness.dropCollections("refresh_tokens", "access_tokens");
});

/** Tokens in a collection matching a native Mongo filter, as a plain string[]. */
async function tokensWhere(
  collection: string,
  filter: Record<string, unknown>,
): Promise<string[]> {
  const docs = await harness.db.collection(collection).find(filter).toArray();

  return docs.map((doc) => doc.token as string);
}

describe("MongoDB integration — RefreshToken", () => {
  it("issue persists a document that findByToken reads back", async () => {
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

    expect(revoked.map((row) => row.get("token")).sort()).toEqual(["r1", "r2"]);

    // `{ revoked_at: null }` matches null-or-missing on Mongo → the still-active set.
    const stillActive = await tokensWhere("refresh_tokens", { revoked_at: null });
    expect(stillActive).toEqual(["other"]);
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

    await RefreshToken.enforceMax(USER_A, 2);

    const active = await RefreshToken.activeFor(USER_A);
    expect(active).toHaveLength(1);
  });

  it("purgeExpired hard-deletes expired documents and returns them", async () => {
    await RefreshToken.issue(USER_A, "keep", { familyId: "f1", expiresAt: future().toISOString() });
    await RefreshToken.issue(USER_A, "drop", { familyId: "f2", expiresAt: past().toISOString() });

    const purged = await RefreshToken.purgeExpired();

    expect(purged.map((row) => row.get("token"))).toEqual(["drop"]);

    const remaining = await tokensWhere("refresh_tokens", {});
    expect(remaining).toEqual(["keep"]);
  });
});

describe("MongoDB integration — AccessToken", () => {
  it("issue persists a document that findByToken reads back", async () => {
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

    const remaining = await tokensWhere("access_tokens", {});
    expect(remaining).toEqual(["b1"]);
  });

  it("purgeExpired removes expired access tokens and returns the count", async () => {
    await AccessToken.issue(USER_A, "live", future());
    await AccessToken.issue(USER_A, "stale", past());

    const count = await AccessToken.purgeExpired();

    expect(count).toBe(1);

    const remaining = await tokensWhere("access_tokens", {});
    expect(remaining).toEqual(["live"]);
  });
});
