import { beforeEach, describe, expect, it, vi } from "vitest";

const transaction = vi.fn();
const hasActiveTransaction = vi.fn();
const findByFamilyId = vi.fn();
const advanceRevision = vi.fn();

vi.mock("@warlock.js/cascade", () => ({
  transaction: (...args: unknown[]) => transaction(...args),
  databaseTransactionContext: {
    hasActiveTransaction: () => hasActiveTransaction(),
  },
}));

vi.mock("../models/auth-token-family", () => ({
  AuthTokenFamily: {
    findByFamilyId: (...args: unknown[]) => findByFamilyId(...args),
    advanceRevision: (...args: unknown[]) => advanceRevision(...args),
  },
}));

import { afterTokenFamilyOperation, runTokenFamilyOperation } from "./token-family-operation";

const family = {
  isRevoked: false,
  get: (key: string) => (key === "revision" ? 4 : undefined),
};

beforeEach(() => {
  vi.clearAllMocks();
  hasActiveTransaction.mockReturnValue(false);
  findByFamilyId.mockResolvedValue(family);
  advanceRevision.mockResolvedValue(1);
  transaction.mockImplementation((operation: () => unknown) => operation());
});

describe("runTokenFamilyOperation", () => {
  it("rejects a revoked family without retrying or invoking the operation", async () => {
    findByFamilyId.mockResolvedValue({ ...family, isRevoked: true });
    const operation = vi.fn();
    await expect(runTokenFamilyOperation("family-1", operation)).rejects.toThrow(
      "Token family is unavailable",
    );
    expect(transaction).toHaveBeenCalledOnce();
    expect(operation).not.toHaveBeenCalled();
  });

  it("uses a serializable transaction and advances the durable revision before work", async () => {
    const operation = vi.fn().mockResolvedValue("done");

    await expect(runTokenFamilyOperation("family-1", operation)).resolves.toBe("done");

    expect(transaction).toHaveBeenCalledWith(expect.any(Function), {
      isolationLevel: "SERIALIZABLE",
    });
    expect(advanceRevision).toHaveBeenCalledWith("family-1", 4);
    expect(operation).toHaveBeenCalledWith(family);
  });

  it("does not retry a conflict while joining an outer transaction", async () => {
    hasActiveTransaction.mockReturnValue(true);
    advanceRevision.mockResolvedValue(0);

    await expect(runTokenFamilyOperation("family-1", vi.fn())).rejects.toThrow(
      "Token family changed concurrently",
    );
    expect(transaction).toHaveBeenCalledOnce();
  });

  it("discards failed-attempt events and emits only after successful commit", async () => {
    const events: number[] = [];
    let attempt = 0;
    transaction.mockImplementation(async (operation: () => Promise<unknown>) => {
      const value = await operation();
      expect(events).toEqual([]);
      if (attempt === 1) throw Object.assign(new Error("serialization"), { code: "40001" });
      return value;
    });
    await runTokenFamilyOperation("family-1", async () => {
      const currentAttempt = ++attempt;
      afterTokenFamilyOperation(() => events.push(currentAttempt));
    });
    expect(events).toEqual([2]);
    expect(transaction).toHaveBeenCalledTimes(2);
  });

  it("does not retry committed work when an event listener throws", async () => {
    await expect(
      runTokenFamilyOperation("family-1", async () => {
        afterTokenFamilyOperation(() => {
          throw Object.assign(new Error("listener"), { code: "40001" });
        });
      }),
    ).rejects.toThrow("listener");
    expect(transaction).toHaveBeenCalledOnce();
  });

  it("discards nested operation events if the owning transaction fails", async () => {
    const effect = vi.fn();
    await expect(
      runTokenFamilyOperation("family-1", async () => {
        hasActiveTransaction.mockReturnValue(true);
        await runTokenFamilyOperation("family-2", async () => {
          afterTokenFamilyOperation(effect);
        });
        throw new Error("rollback");
      }),
    ).rejects.toThrow("rollback");
    expect(effect).not.toHaveBeenCalled();
  });
});
