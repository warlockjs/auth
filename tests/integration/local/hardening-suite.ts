import { migrate, Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { InvalidOneTimeTokenError } from "../../../src/errors/invalid-one-time-token.error";
import { InvalidPasskeyError } from "../../../src/errors/invalid-passkey.error";
import { authMigrations } from "../../../src/models";
import { AccessToken } from "../../../src/models/access-token/access-token.model";
import { OneTimeToken } from "../../../src/models/one-time-token/one-time-token.model";
import { RefreshToken } from "../../../src/models/refresh-token/refresh-token.model";
import { PasskeyCredential } from "../../../src/models/passkey-credential/passkey-credential.model";
import { ProviderAccount } from "../../../src/models/provider-account/provider-account.model";
import { requestOtp, verifyOtp } from "../../../src/otp/otp";
import {
  generatePasskeyAuthenticationOptions,
  verifyPasskeyAuthentication,
} from "../../../src/passkeys/passkey-authentication";
import {
  generatePasskeyRegistrationOptions,
  verifyPasskeyRegistration,
} from "../../../src/passkeys/passkey-registration";
import { authService } from "../../../src/services/auth.service";
import { consumeOneTimeToken, issueOneTimeToken } from "../../../src/services/one-time-tokens";
import { SoftwareAuthenticator } from "../../../src/test-support/software-authenticator";
import type { LocalDatabaseHarness } from "../helpers/local-database-harness";

/**
 * The 5.13 one-time-token / OTP / passkey / provider-link guarantees against a
 * REAL database. The unit specs prove the logic over an in-memory store; only a
 * live driver proves the conditional updates (`consumed_at: null`,
 * `attempts: { $lt }` + `$inc`, counter compare-and-set), the nullable
 * `user_id`, and the unique indexes the migrations declare.
 *
 * Shared by the MongoDB and Postgres entry files, which own the module mocks.
 */

class ItestUser extends Model {
  public static table = "auth_itest_users";

  public static schema = v.object({
    phone: v.string().optional(),
    email: v.string().optional(),
  });

  public get userType(): string {
    return "user";
  }
}

const ItestUserMigration = migrate(ItestUser, {
  name: "authItestUser",
  up() {
    this.createTableIfNotExists();
    this.primaryUuid();
    this.string("phone", 32).nullable();
    this.string("email", 255).nullable();
    this.timestamps();
  },
  down() {
    this.dropTableIfExists();
  },
});

const TABLES = [
  "access_tokens",
  "refresh_tokens",
  "one_time_tokens",
  "provider_accounts",
  "passkey_credentials",
  ItestUser.table,
];

/** Where cascade's Mongo default "trash" delete strategy would move destroyed rows. */
const MONGO_TRASH = "one_time_tokensTrash";
const MONGO_ACCESS_TOKEN_TRASH = "access_tokensTrash";
const MONGO_REFRESH_TOKEN_TRASH = "refresh_tokensTrash";

const ORIGIN = "https://app.test";
const RP_ID = "app.test";
const PHONE = "+201000000000";
const CONCURRENCY = 20;

export type HardeningSuiteOptions = {
  available: boolean;
  start: () => Promise<LocalDatabaseHarness>;
  configValues: Record<string, unknown>;
};

const request = (origin: string) => ({ origin }) as never;

export function defineAuthHardeningSuite(label: string, options: HardeningSuiteOptions): void {
  describe.skipIf(!options.available)(`${label} — auth 5.13 hardening on a real database`, () => {
    let harness: LocalDatabaseHarness;
    const sentCodes: string[] = [];
    // Token issuance is not under test here; the login ending is observed only.
    const completeLogin = vi.spyOn(authService, "completeLogin");

    const tokenRows = async (purpose: string) =>
      (await harness.rows("one_time_tokens")).filter((row) => row.purpose === purpose);

    beforeAll(async () => {
      harness = await options.start();
      await harness.migrateFresh(TABLES, [...authMigrations, ItestUserMigration]);
    });

    afterAll(async () => {
      await harness?.stop();
    });

    beforeEach(async () => {
      await harness.truncate(TABLES);

      if (harness.label === "mongodb") {
        await harness.truncate([MONGO_TRASH, MONGO_ACCESS_TOKEN_TRASH, MONGO_REFRESH_TOKEN_TRASH]);
      }

      sentCodes.length = 0;

      for (const key of Object.keys(options.configValues)) delete options.configValues[key];

      Object.assign(options.configValues, {
        "auth.userType.user": ItestUser,
        "auth.accessToken.secret": "integration-secret",
        "auth.passkeys": { rpID: RP_ID, rpName: "App", origin: ORIGIN },
        "auth.otp.send": async (_phone: string, message: { code: string }) => {
          sentCodes.push(message.code);
        },
      });

      completeLogin.mockReset();
      completeLogin.mockImplementation(async (user) => ({ user, tokens: {} }) as never);
    });

    it("the migrations create every auth table", async () => {
      for (const table of TABLES) {
        await expect(harness.rows(table)).resolves.toEqual([]);
      }
    });

    it(`a one-time token consumed ${CONCURRENCY}x concurrently succeeds exactly once`, async () => {
      const user = await ItestUser.create({ email: "ada@example.com" });
      const { token } = await issueOneTimeToken(user as never, "password-reset", 60_000);

      const outcomes = await Promise.allSettled(
        Array.from({ length: CONCURRENCY }, () => consumeOneTimeToken(token, "password-reset")),
      );

      const fulfilled = outcomes.filter((outcome) => outcome.status === "fulfilled");
      const rejected = outcomes.filter(
        (outcome): outcome is PromiseRejectedResult => outcome.status === "rejected",
      );

      expect(fulfilled).toHaveLength(1);
      expect(rejected.every((outcome) => outcome.reason instanceof InvalidOneTimeTokenError)).toBe(
        true,
      );

      const [row] = await tokenRows("password-reset");

      expect(row.consumed_at).toBeTruthy();
    });

    it(`an OTP under ${CONCURRENCY} concurrent wrong guesses counts at most 5 attempts and is invalidated`, async () => {
      await ItestUser.create({ phone: PHONE });
      await requestOtp(ItestUser as never, PHONE);

      const code = sentCodes[0];
      const wrong = String((Number(code) + 1) % 1_000_000).padStart(6, "0");

      const outcomes = await Promise.allSettled(
        Array.from({ length: CONCURRENCY }, () => verifyOtp(ItestUser as never, PHONE, wrong)),
      );

      expect(outcomes.every((outcome) => outcome.status === "rejected")).toBe(true);

      const [row] = await tokenRows("otp");

      expect(Number(row.attempts)).toBeLessThanOrEqual(5);
      expect(Number(row.attempts)).toBe(5);
      expect(row.consumed_at).toBeTruthy();

      // The right code no longer works either — the row is dead.
      await expect(verifyOtp(ItestUser as never, PHONE, code)).rejects.toBeInstanceOf(
        InvalidOneTimeTokenError,
      );
      expect(completeLogin).not.toHaveBeenCalled();
    });

    it("a correct OTP logs in once and is consumed", async () => {
      await ItestUser.create({ phone: PHONE });
      await requestOtp(ItestUser as never, PHONE);

      await verifyOtp(ItestUser as never, PHONE, sentCodes[0]);

      await expect(verifyOtp(ItestUser as never, PHONE, sentCodes[0])).rejects.toBeInstanceOf(
        InvalidOneTimeTokenError,
      );
      expect(completeLogin).toHaveBeenCalledTimes(1);
    });

    it("registers a passkey, then logs in: the userless challenge persists and is consumed, the counter advances, a regression is rejected", async () => {
      const user = await ItestUser.create({ email: "ada@example.com" });
      const authenticator = new SoftwareAuthenticator({ rpID: RP_ID, origin: ORIGIN });

      const registration = await generatePasskeyRegistrationOptions(user as never);
      await verifyPasskeyRegistration(
        request(ORIGIN),
        user as never,
        authenticator.register(registration.challenge),
      );

      const login = await generatePasskeyAuthenticationOptions();
      const [challenge] = await tokenRows("passkey-authentication");

      expect(challenge.user_id ?? null).toBeNull();
      expect(challenge.consumed_at ?? null).toBeNull();

      authenticator.counter = 1;
      await verifyPasskeyAuthentication(
        request(ORIGIN),
        authenticator.authenticate(login.challenge),
      );

      const [consumed] = await tokenRows("passkey-authentication");
      expect(consumed.consumed_at).toBeTruthy();

      const [stored] = await harness.rows("passkey_credentials");
      expect(Number(stored.counter)).toBe(1);
      expect(completeLogin).toHaveBeenCalledTimes(1);

      // Replay of the same challenge: single use.
      const replay = await verifyPasskeyAuthentication(
        request(ORIGIN),
        authenticator.authenticate(login.challenge),
      ).catch((error) => error);
      expect(replay).toBeInstanceOf(InvalidPasskeyError);

      // A clone presenting the same counter on a fresh challenge.
      const again = await generatePasskeyAuthenticationOptions();
      const cloned = await verifyPasskeyAuthentication(
        request(ORIGIN),
        authenticator.authenticate(again.challenge),
      ).catch((error) => error);

      expect(cloned).toBeInstanceOf(InvalidPasskeyError);
      expect(cloned.reason).toBe("counter-regression");

      const [afterClone] = await harness.rows("passkey_credentials");
      expect(Number(afterClone.counter)).toBe(1);
      expect(completeLogin).toHaveBeenCalledTimes(1);
    });

    it(`the passkey counter compare-and-set lets one of ${CONCURRENCY} stale writers win`, async () => {
      const user = await ItestUser.create({ email: "ada@example.com" });
      const credential = await PasskeyCredential.create({
        credential_id: "cred-cas",
        public_key: "AQID",
        counter: 4,
        transports: ["internal"],
        user_id: user.id,
        user_type: "user",
      });

      const copies = await Promise.all(
        Array.from({ length: CONCURRENCY }, () => PasskeyCredential.find(credential.id)),
      );
      const outcomes = await Promise.all(
        copies.map((copy, index) => copy!.advanceCounter(4, 5 + index)),
      );

      expect(outcomes.filter(Boolean)).toHaveLength(1);
    });

    it("provider_accounts allows one link per (provider, provider_user_id)", async () => {
      const ada = await ItestUser.create({ email: "ada@example.com" });
      const eve = await ItestUser.create({ email: "eve@example.com" });

      const outcomes = await Promise.allSettled(
        Array.from({ length: 10 }, (_, index) =>
          ProviderAccount.link("google", "sub-123", (index % 2 ? ada : eve) as never),
        ),
      );

      expect(outcomes.filter((outcome) => outcome.status === "fulfilled")).toHaveLength(1);
      expect(await harness.rows("provider_accounts")).toHaveLength(1);

      // A different provider with the same subject id is a different identity.
      await ProviderAccount.link("github", "sub-123", ada as never);
      expect(await harness.rows("provider_accounts")).toHaveLength(2);
    });

    it("auth.cleanup purges expired and consumed one-time tokens and keeps live ones", async () => {
      const user = await ItestUser.create({ email: "ada@example.com" });
      const live = await issueOneTimeToken(user as never, "email-verification", 60_000);
      await issueOneTimeToken(user as never, "password-reset", -60_000);
      const used = await issueOneTimeToken(user as never, "password-reset", 60_000);
      await consumeOneTimeToken(used.token, "password-reset");

      await authService.cleanupExpiredTokens();

      const remaining = await harness.rows("one_time_tokens");

      expect(remaining).toHaveLength(1);
      expect(remaining[0].purpose).toBe("email-verification");

      // A purge is a hard delete: token hashes are not copied into a trash table.
      if (harness.label === "mongodb") {
        expect(await harness.rows(MONGO_TRASH)).toHaveLength(0);
      }

      await expect(consumeOneTimeToken(live.token, "email-verification")).resolves.toBeTruthy();
      expect(await OneTimeToken.purgeSpent()).toBe(1);
    });

    it("auth.cleanup purges expired access and refresh tokens without copying them into trash collections", async () => {
      const user = await ItestUser.create({ email: "ada@example.com" });

      await AccessToken.issue(user as never, "expired-access-token", new Date(Date.now() - 60_000));
      const liveAccessToken = await AccessToken.issue(
        user as never,
        "live-access-token",
        new Date(Date.now() + 60_000),
      );

      await RefreshToken.issue(user as never, "expired-refresh-token", {
        familyId: "family-1",
        expiresAt: new Date(Date.now() - 60_000).toISOString(),
      });
      const liveRefreshToken = await RefreshToken.issue(user as never, "live-refresh-token", {
        familyId: "family-2",
        expiresAt: new Date(Date.now() + 60_000).toISOString(),
      });

      await authService.cleanupExpiredTokens();

      const remainingAccessTokens = await harness.rows("access_tokens");
      const remainingRefreshTokens = await harness.rows("refresh_tokens");

      expect(remainingAccessTokens).toHaveLength(1);
      expect(remainingAccessTokens[0].token).toBe(liveAccessToken.get("token"));
      expect(remainingRefreshTokens).toHaveLength(1);
      expect(remainingRefreshTokens[0].token).toBe(liveRefreshToken.get("token"));

      // A purge is a hard delete: credential material is not copied into a trash table.
      if (harness.label === "mongodb") {
        expect(await harness.rows(MONGO_ACCESS_TOKEN_TRASH)).toHaveLength(0);
        expect(await harness.rows(MONGO_REFRESH_TOKEN_TRASH)).toHaveLength(0);
      }
    });
  });
}
