import { createSigner } from "fast-jwt";
import { describe, expect, it } from "vitest";
import { isNeverExpiring, isUsableExpiry, tokenHasExpClaim } from "./token-expiry";

const KEY = "token-expiry-spec-secret-0123456789";
const withExp = createSigner({ key: KEY, expiresIn: 3_600_000 })({ id: 1 }) as unknown as string;
const withoutExp = createSigner({ key: KEY })({ id: 1 }) as unknown as string;

describe("isUsableExpiry", () => {
  it("accepts a Date, an ISO string, and an epoch number", () => {
    expect(isUsableExpiry(new Date())).toBe(true);
    expect(isUsableExpiry(new Date().toISOString())).toBe(true);
    expect(isUsableExpiry(Date.now())).toBe(true);
  });

  // The row shape a pre-4.12.0 unparseable `expiresIn` wrote. It compares
  // `false` against every date, so it satisfies neither `< now` nor `> now`.
  it("rejects an Invalid Date", () => {
    expect(isUsableExpiry(new Date("30dayz"))).toBe(false);
    expect(isUsableExpiry("not a date")).toBe(false);
    expect(isUsableExpiry(NaN)).toBe(false);
  });

  it("rejects absent values", () => {
    expect(isUsableExpiry(undefined)).toBe(false);
    expect(isUsableExpiry(null)).toBe(false);
    expect(isUsableExpiry("")).toBe(false);
  });
});

describe("tokenHasExpClaim", () => {
  it("is true for a token signed with a lifetime", () => {
    expect(tokenHasExpClaim(withExp)).toBe(true);
  });

  it("is false for a token signed without one", () => {
    expect(tokenHasExpClaim(withoutExp)).toBe(false);
  });

  it("is false for anything it cannot decode", () => {
    expect(tokenHasExpClaim("not.a.jwt")).toBe(false);
    expect(tokenHasExpClaim("")).toBe(false);
    expect(tokenHasExpClaim(undefined)).toBe(false);
    expect(tokenHasExpClaim(42)).toBe(false);
  });

  it("does not require a valid signature — it reads claims, not trust", () => {
    const foreign = createSigner({ key: "a-completely-different-key-0123456789", expiresIn: 1000 })({
      id: 1,
    }) as unknown as string;

    expect(tokenHasExpClaim(foreign)).toBe(true);
  });
});

describe("isNeverExpiring", () => {
  it("is true when the row's expiry is unusable", () => {
    expect(isNeverExpiring(withExp, new Date("30dayz"))).toBe(true);
  });

  it("is true when the token carries no exp, however sane the row looks", () => {
    expect(isNeverExpiring(withoutExp, new Date(Date.now() + 60_000))).toBe(true);
  });

  it("is false only when both the row and the token carry a real deadline", () => {
    expect(isNeverExpiring(withExp, new Date(Date.now() + 60_000))).toBe(false);
  });
});
