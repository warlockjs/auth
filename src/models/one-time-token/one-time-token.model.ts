import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import { isUsableExpiry } from "../../utils/token-expiry";
import type { Auth } from "../auth.model";

/** What a one-time token may be used for. A token only ever satisfies its own purpose. */
export type OneTimeTokenPurpose = "email-verification" | "password-reset";

/**
 * Seal schema for the persisted one-time token. Exported so an override can
 * extend it (e.g. a tenant key).
 */
export const oneTimeTokenSchema = v.object({
  token_hash: v.string().required(),
  purpose: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  expires_at: v.date().required(),
  consumed_at: v.date().optional(),
});

/**
 * Persisted email-verification / password-reset token.
 *
 * **Only a SHA-256 hash is stored** — the raw token exists in the notification
 * and nowhere else, so a leaked table cannot be replayed. Single use is
 * enforced by {@link consumeIfActive}, a conditional update in the same shape
 * as `RefreshToken.revokeIfActive`. Override via `config.auth.oneTimeToken.model`.
 */
export class OneTimeToken extends Model {
  public static table = "one_time_tokens";

  public static schema = oneTimeTokenSchema;

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
    });
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
