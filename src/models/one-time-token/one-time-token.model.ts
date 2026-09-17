import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import { isUsableExpiry } from "../../utils/token-expiry";
import type { Auth } from "../auth.model";

/** What a one-time token may be used for. A token only ever satisfies its own purpose. */
export type OneTimeTokenPurpose =
  | "email-verification"
  | "password-reset"
  | "otp"
  | "passkey-registration"
  | "passkey-authentication";

/**
 * Seal schema for the persisted one-time token. Exported so an override can
 * extend it (e.g. a tenant key).
 */
export const oneTimeTokenSchema = v.object({
  token_hash: v.string().required(),
  purpose: v.string().required(),
  // Absent only on a passkey authentication challenge (no user identified yet).
  user_id: v.scalar().optional(),
  user_type: v.string().optional(),
  expires_at: v.date().required(),
  consumed_at: v.date().optional(),
  attempts: v.int().optional(),
});

/**
 * Persisted one-time secret: email-verification / password-reset token, OTP
 * code, or passkey ceremony challenge.
 *
 * **Only a SHA-256 hash is stored** — the raw token exists in the notification
 * and nowhere else, so a leaked table cannot be replayed. Single use is
 * enforced by {@link consumeIfActive}, a conditional update in the same shape
 * as `RefreshToken.revokeIfActive`. Override via `config.auth.oneTimeToken.model`.
 */
export class OneTimeToken extends Model {
  public static table = "one_time_tokens";

  public static schema = oneTimeTokenSchema;

  /**
   * Permanent regardless of the data source default — Mongo's driver default
   * is `"trash"`, which would copy spent token hashes into
   * `one_time_tokensTrash` on every `destroy()`. A purged one-time token must
   * not survive anywhere.
   */
  public static deleteStrategy = "permanent" as const;

  /** The user this token was issued for. */
  public get userId() {
    return this.get("user_id");
  }

  /** The user-type slug this token was issued for. */
  public get userType(): string {
    return this.get("user_type");
  }

  /** Whether the token has been used (or invalidated by a newer one). */
  public get isConsumed(): boolean {
    return !!this.get("consumed_at");
  }

  /** Whether the expiry has passed. Fails closed: an unusable `expires_at` counts as expired. */
  public get isExpired(): boolean {
    const expiresAt = this.get("expires_at");

    if (!isUsableExpiry(expiresAt)) return true;

    return new Date(expiresAt).getTime() <= Date.now();
  }

  /**
   * Atomically mark this token consumed ONLY if nobody has yet. Resolves `true`
   * for the single caller that won; every concurrent or later caller gets
   * `false`.
   */
  public async consumeIfActive(): Promise<boolean> {
    const modelClass = this.constructor as typeof OneTimeToken;

    const consumed = await modelClass.atomic(
      { id: this.id, consumed_at: null },
      { $set: { consumed_at: new Date() } },
    );

    return consumed > 0;
  }

  /** Persist a new token row. `tokenHash` is the SHA-256 hex digest, never the raw token. */
  public static issue(
    user: Auth,
    purpose: OneTimeTokenPurpose,
    tokenHash: string,
    expiresAt: Date,
  ) {
    return this.create({
      token_hash: tokenHash,
      purpose,
      user_id: user.id,
      user_type: user.userType,
      expires_at: expiresAt,
      consumed_at: null,
      attempts: 0,
    });
  }

  /**
   * Persist a passkey ceremony challenge. `user` is omitted for an
   * authentication challenge, issued before anyone is identified.
   */
  public static issueChallenge(
    purpose: OneTimeTokenPurpose,
    tokenHash: string,
    expiresAt: Date,
    user?: Auth,
  ) {
    return this.create({
      token_hash: tokenHash,
      purpose,
      user_id: user?.id ?? null,
      user_type: user?.userType ?? null,
      expires_at: expiresAt,
      consumed_at: null,
      attempts: 0,
    });
  }

  /** The user's newest unconsumed token of `purpose` (at most one for OTP). */
  public static findActiveFor(
    user: Auth,
    purpose: OneTimeTokenPurpose,
  ): Promise<OneTimeToken | null> {
    return this.query()
      .where({ user_id: user.id, user_type: user.userType, purpose, consumed_at: null })
      .orderBy("created_at", "desc")
      .first();
  }

  /**
   * Atomically count one verify attempt, ONLY while fewer than `max` have been
   * counted and the token is unconsumed. Resolves `false` once the cap is
   * reached — of N concurrent attempts, at most `max` ever resolve `true`.
   */
  public async recordAttempt(max: number): Promise<boolean> {
    const modelClass = this.constructor as typeof OneTimeToken;

    const counted = await modelClass.atomic(
      { id: this.id, consumed_at: null, attempts: { $lt: max } },
      { $inc: { attempts: 1 } },
      // Code-authored filter; nothing here comes from the request.
      { trustedFilter: true },
    );

    return counted > 0;
  }

  /**
   * Hard-delete every spent row — expired, or consumed (used, invalidated by a
   * newer token, or exhausted). Neither can ever be redeemed again, so nothing
   * reads them. Hard-deleted, never trashed. Returns the number removed. Runs from the `auth.cleanup` CLI
   * command (a cold batch path).
   */
  public static async purgeSpent(): Promise<number> {
    const expired = await this.query().where("expires_at", "<", new Date()).get();
    const consumed = await this.query().whereNotNull("consumed_at").get();
    const spent = new Map([...expired, ...consumed].map((token) => [String(token.id), token]));

    for (const token of spent.values()) {
      // `static deleteStrategy` above already forces "permanent" regardless
      // of the data source default (Mongo's is "trash").
      await token.destroy();
    }

    return spent.size;
  }

  /** Find a token by hash, scoped to a purpose — a token of the other purpose is not found. */
  public static findByHash(
    tokenHash: string,
    purpose: OneTimeTokenPurpose,
  ): Promise<OneTimeToken | null> {
    return this.first({ token_hash: tokenHash, purpose });
  }

  /**
   * Consume every still-unused token of `purpose` for the user, returning how
   * many were invalidated. Used before issuing a new password-reset token.
   */
  public static invalidateActiveFor(user: Auth, purpose: OneTimeTokenPurpose): Promise<number> {
    return this.atomic(
      { user_id: user.id, user_type: user.userType, purpose, consumed_at: null },
      { $set: { consumed_at: new Date() } },
    );
  }
}
