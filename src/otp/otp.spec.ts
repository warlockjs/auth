import { beforeEach, describe, expect, it, vi } from "vitest";

const configValues = vi.hoisted(() => ({}) as Record<string, unknown>);

vi.mock("@warlock.js/core", async () =>
  (await import("../test-support/fake-core")).fakeCoreModule(configValues),
);
vi.mock(
  "@warlock.js/cascade",
  async () => (await import("../test-support/in-memory-cascade")).cascadeModule,
);
vi.mock(
  "@warlock.js/seal",
  async () => (await import("../test-support/in-memory-cascade")).sealModule,
);
vi.mock("@warlock.js/logger", () => ({ log: { warn: vi.fn(), error: vi.fn() } }));

const sent = vi.hoisted(
  () => [] as Array<{ channel: string; to: string; payload: { code: string; body: string } }>,
);

vi.mock("@warlock.js/notifications", () => ({
  notify: {
    channel: (channel: string) => ({
      send: async (to: string, payload: { code: string; body: string }) => {
        sent.push({ channel, to, payload });
      },
    }),
  },
}));

const completeLogin = vi.hoisted(() => vi.fn());

vi.mock("../services/auth.service", () => ({ authService: { completeLogin } }));

import { InvalidOneTimeTokenError } from "../errors/invalid-one-time-token.error";
import { InMemoryModel, resetTables, tables } from "../test-support/in-memory-cascade";
import { requestOtp, verifyOtp } from "./otp";
import { defined } from "../test-support/defined";

class User extends InMemoryModel {
  public static table = "users";

  public get userType() {
    return "user";
  }
}

const PHONE = "+201000000000";

/** A 6-digit code that is NOT the one sent. */
const wrongCode = (code: string) => String((Number(code) + 1) % 1_000_000).padStart(6, "0");

let user: User;

beforeEach(async () => {
  resetTables();
  sent.length = 0;
  for (const key of Object.keys(configValues)) delete configValues[key];
  configValues["auth.accessToken.secret"] = "test-secret";

  vi.clearAllMocks();
  completeLogin.mockImplementation(async (resolved: unknown) => ({
    user: resolved,
    tokens: { accessToken: { token: "t" } },
  }));

  user = (await User.create({ phone: PHONE })) as User;
});

async function issuedCode(): Promise<string> {
  await requestOtp(User as never, PHONE);

  return defined(sent.at(-1), "sent message").payload.code;
}

const otpRows = () => (tables.get("one_time_tokens") ?? []).filter((row) => row.purpose === "otp");

describe("requestOtp", () => {
  it("sends a 6-digit code through the configured notifications channel and stores only a keyed hash", async () => {
    configValues["auth.otp.channel"] = "whatsapp";

    const code = await issuedCode();
    const row = defined(otpRows()[0], "otp row");

    expect(code).toMatch(/^\d{6}$/);
    expect(sent[0]).toMatchObject({ channel: "whatsapp", to: PHONE });
    expect(defined(sent[0], "sent message").payload.body).toContain(code);
    expect(row).toMatchObject({ purpose: "otp", user_id: user.id, attempts: 0, consumed_at: null });
    expect(JSON.stringify(row)).not.toContain(code);
    expect(String(row.token_hash).length).toBeLessThanOrEqual(64);
  });

  it("expires 5 minutes out by default", async () => {
    const before = Date.now();
    await issuedCode();

    const expiresAt = (defined(otpRows()[0], "otp row").expires_at as Date).getTime();

    expect(expiresAt - before).toBeGreaterThanOrEqual(5 * 60_000 - 50);
    expect(expiresAt - before).toBeLessThanOrEqual(5 * 60_000 + 1000);
  });

  it("answers an unknown phone the same way and sends nothing (anti-enumeration)", async () => {
    await expect(requestOtp(User as never, "+19999999999")).resolves.toBeUndefined();

    expect(sent).toHaveLength(0);
    expect(otpRows()).toHaveLength(0);
  });

  it("a new code invalidates the earlier one", async () => {
    const first = await issuedCode();
    await issuedCode();

    await expect(verifyOtp(User as never, PHONE, first)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
  });
});

describe("verifyOtp", () => {
  it("logs in through completeLogin with the right code, once", async () => {
    const code = await issuedCode();

    const result = await verifyOtp(User as never, PHONE, code, { ip: "1.2.3.4" });

    expect(completeLogin).toHaveBeenCalledWith(expect.objectContaining({ id: user.id }), {
      ip: "1.2.3.4",
    });
    expect(result.tokens.accessToken.token).toBe("t");
    await expect(verifyOtp(User as never, PHONE, code)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    expect(completeLogin).toHaveBeenCalledTimes(1);
  });

  it("rejects an expired code", async () => {
    const code = await issuedCode();
    defined(otpRows()[0], "otp row").expires_at = new Date(Date.now() - 1);

    await expect(verifyOtp(User as never, PHONE, code)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("invalidates the code after 5 wrong attempts — the right code no longer works", async () => {
    const code = await issuedCode();

    for (let attempt = 0; attempt < 5; attempt++) {
      await expect(verifyOtp(User as never, PHONE, wrongCode(code))).rejects.toBeInstanceOf(
        InvalidOneTimeTokenError,
      );
    }

    await expect(verifyOtp(User as never, PHONE, code)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
    expect(defined(otpRows()[0], "otp row").consumed_at).toBeInstanceOf(Date);
    expect(completeLogin).not.toHaveBeenCalled();
  });

  it("caps comparisons under concurrent guessing: at most 5 attempts are ever counted", async () => {
    const code = await issuedCode();

    await Promise.allSettled(
      Array.from({ length: 20 }, () => verifyOtp(User as never, PHONE, wrongCode(code))),
    );

    expect(defined(otpRows()[0], "otp row").attempts).toBe(5);
    await expect(verifyOtp(User as never, PHONE, code)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
  });

  it("the 5th attempt may still be the right one", async () => {
    const code = await issuedCode();

    for (let attempt = 0; attempt < 4; attempt++) {
      await verifyOtp(User as never, PHONE, wrongCode(code)).catch(() => undefined);
    }

    await expect(verifyOtp(User as never, PHONE, code)).resolves.toBeDefined();
  });

  it("gives an unknown phone the same error as a wrong code (anti-enumeration)", async () => {
    const code = await issuedCode();

    const unknown = await verifyOtp(User as never, "+19999999999", code).catch((e) => e);
    const wrong = await verifyOtp(User as never, PHONE, wrongCode(code)).catch((e) => e);

    expect(unknown).toBeInstanceOf(InvalidOneTimeTokenError);
    expect(wrong).toBeInstanceOf(InvalidOneTimeTokenError);
    expect(unknown.message).toBe(wrong.message);
  });

  it("a code for one user never logs in another", async () => {
    await User.create({ phone: "+202000000000" });
    const code = await issuedCode();

    await expect(verifyOtp(User as never, "+202000000000", code)).rejects.toBeInstanceOf(
      InvalidOneTimeTokenError,
    );
  });
});
