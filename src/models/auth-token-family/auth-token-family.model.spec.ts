import { afterEach, describe, expect, it, vi } from "vitest";
import { AuthTokenFamily } from "./auth-token-family.model";

function buildFamily(revokedAt?: Date): AuthTokenFamily {
  const family = Object.create(AuthTokenFamily.prototype) as AuthTokenFamily;

  Object.defineProperty(family, "get", {
    value: (key: string) => (key === "revoked_at" ? revokedAt : undefined),
  });

  return family;
}

describe("AuthTokenFamily", () => {
  afterEach(() => vi.restoreAllMocks());

  it("treats a stamped family as revoked", () => {
    expect(buildFamily(new Date()).isRevoked).toBe(true);
    expect(buildFamily().isRevoked).toBe(false);
  });

  it("uses a native upsert to bootstrap an existing family without a duplicate insert", async () => {
    const atomic = vi.spyOn(AuthTokenFamily, "atomic").mockResolvedValue(1);
    const family = Object.create(AuthTokenFamily.prototype) as AuthTokenFamily;
    Object.defineProperty(family, "get", {
      value: (key: string) => ({ user_id: 1, user_type: "user" })[key],
    });
    vi.spyOn(AuthTokenFamily, "findByFamilyId").mockResolvedValue(family);

    await expect(
      AuthTokenFamily.ensure({ id: 1, userType: "user" } as never, "legacy-family"),
    ).resolves.toBe(family);

    expect(atomic).toHaveBeenCalledWith(
      { family_id: "legacy-family" },
      { $setOnInsert: { user_id: 1, user_type: "user", revision: 0 } },
      { upsert: true },
    );
  });

  it("rejects a family identifier already owned by a different user", async () => {
    vi.spyOn(AuthTokenFamily, "atomic").mockResolvedValue(0);
    const family = Object.create(AuthTokenFamily.prototype) as AuthTokenFamily;
    Object.defineProperty(family, "get", {
      value: (key: string) => ({ user_id: 2, user_type: "user" })[key],
    });
    vi.spyOn(AuthTokenFamily, "findByFamilyId").mockResolvedValue(family);

    await expect(
      AuthTokenFamily.ensure({ id: 1, userType: "user" } as never, "family"),
    ).rejects.toThrow("Token family belongs to a different user");
  });
});
