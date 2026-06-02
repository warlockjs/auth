import { describe, expect, it, vi } from "vitest";

vi.mock("@warlock.js/cascade", () => ({
  Model: class {},
}));

vi.mock("@warlock.js/seal", () => {
  const chained = () => {
    const proxy: Record<string, unknown> = {};
    const handler = () => proxy;

    for (const method of ["required", "optional", "default", "defaultNow"]) {
      proxy[method] = handler;
    }

    return proxy;
  };

  return {
    v: {
      object: chained,
      string: chained,
      scalar: chained,
      date: chained,
      record: chained,
      any: chained,
    },
  };
});

import { RefreshToken } from "./refresh-token.model";

function buildToken(fields: Record<string, unknown>) {
  const token = Object.create(RefreshToken.prototype) as RefreshToken;

  Object.defineProperty(token, "get", {
    value: (key: string) => fields[key],
  });

  return token;
}

/**
 * Build a token whose `merge` records the merged patch and returns a
 * chainable object exposing `save` — mirroring cascade's `merge(): this`.
 */
function buildMutableToken() {
  const token = Object.create(RefreshToken.prototype) as RefreshToken;

  const save = vi.fn().mockResolvedValue(token);
  const merge = vi.fn(() => ({ save }));

  Object.defineProperty(token, "merge", { value: merge });

  return { token, merge, save };
}

describe("RefreshToken validity getters", () => {
  describe("isExpired", () => {
    it("is false when expires_at is in the future", () => {
      const token = buildToken({ expires_at: new Date(Date.now() + 60_000) });

      expect(token.isExpired).toBe(false);
    });

    it("is true when expires_at is in the past", () => {
      const token = buildToken({ expires_at: new Date(Date.now() - 60_000) });

      expect(token.isExpired).toBe(true);
    });

    it("treats a missing expires_at as never-expiring", () => {
      const token = buildToken({ expires_at: undefined });

      expect(token.isExpired).toBe(false);
    });
  });

  describe("isRevoked", () => {
    it("is true once revoked_at is stamped", () => {
      const token = buildToken({ revoked_at: new Date() });

      expect(token.isRevoked).toBe(true);
    });

    it("is false when revoked_at is absent", () => {
      const token = buildToken({ revoked_at: undefined });

      expect(token.isRevoked).toBe(false);
    });
  });

  describe("isValid", () => {
    it("is true only when neither expired nor revoked", () => {
      const token = buildToken({
        expires_at: new Date(Date.now() + 60_000),
        revoked_at: undefined,
      });

      expect(token.isValid).toBe(true);
    });

    it("is false when the token is revoked even if not expired", () => {
      const token = buildToken({
        expires_at: new Date(Date.now() + 60_000),
        revoked_at: new Date(),
      });

      expect(token.isValid).toBe(false);
    });

    it("is false when the token is expired even if not revoked", () => {
      const token = buildToken({
        expires_at: new Date(Date.now() - 60_000),
        revoked_at: undefined,
      });

      expect(token.isValid).toBe(false);
    });
  });
});

describe("RefreshToken.revoke", () => {
  it("merges a revoked_at timestamp and saves", async () => {
    const { token, merge, save } = buildMutableToken();

    await token.revoke();

    expect(merge).toHaveBeenCalledTimes(1);
    const [patch] = merge.mock.calls[0];
    expect(patch.revoked_at).toBeInstanceOf(Date);
    expect(save).toHaveBeenCalledOnce();
  });

  it("resolves to the result of save (the saved model)", async () => {
    const { token, save } = buildMutableToken();
    const saved = { id: "saved" };
    save.mockResolvedValue(saved);

    await expect(token.revoke()).resolves.toBe(saved);
  });
});

describe("RefreshToken.markAsUsed", () => {
  it("merges a fresh last_used_at timestamp and saves", async () => {
    const { token, merge, save } = buildMutableToken();

    await token.markAsUsed();

    expect(merge).toHaveBeenCalledTimes(1);
    const [patch] = merge.mock.calls[0];
    expect(patch.last_used_at).toBeInstanceOf(Date);
    expect(patch.revoked_at).toBeUndefined();
    expect(save).toHaveBeenCalledOnce();
  });

  it("resolves to undefined (does not surface the saved model)", async () => {
    const { token } = buildMutableToken();

    await expect(token.markAsUsed()).resolves.toBeUndefined();
  });
});
