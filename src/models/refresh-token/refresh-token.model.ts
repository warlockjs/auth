import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import type { DeviceInfo } from "../../contracts/types";
import type { Auth } from "../auth.model";

/**
 * Seal schema for the persisted refresh-token record. Exported so an override
 * can spread it and add columns (e.g. a tenant key) without re-declaring the
 * base shape:
 *
 * @example
 * export class AppRefreshToken extends RefreshToken {
 *   public static schema = refreshTokenSchema.extend({
 *     organization_id: v.string().required(),
 *   });
 * }
 */
export const refreshTokenSchema = v.object({
  token: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  family_id: v.string().required(),
  expires_at: v.date().required(),
  last_used_at: v.date().default(() => new Date()),
  revoked_at: v.date().optional(),
  device_info: v.record(v.any()).optional(),
});

/**
 * Extra attributes captured when a refresh token is issued.
 */
export type RefreshTokenIssueOptions = {
  familyId: string;
  expiresAt: string;
  deviceInfo?: DeviceInfo;
};

/**
 * Persisted refresh-token record + the data layer for refresh tokens.
 *
 * **Role.** Owns every refresh-token read, write, and lifecycle transition.
 * The auth service drives refresh-token state exclusively through this model's
 * named statics and instance methods, so it never hard-codes a column name —
 * which is what makes a snake/camel mismatch (the historical `userId` bug)
 * structurally impossible and lets an override rename or add columns by
 * extending this class and registering it under `config.auth.refreshToken.model`.
 */
export class RefreshToken extends Model {
  public static table = "refresh_tokens";

  public static schema = refreshTokenSchema;

  /** Token family this row belongs to (rotation / replay grouping). */
  public get familyId(): string {
    return this.get("family_id");
  }

  /** Whether the token's `expires_at` is in the past. */
  public get isExpired(): boolean {
    const expiresAt = this.get("expires_at");

    if (!expiresAt) return false;

    return new Date() > new Date(expiresAt);
  }

  /** Whether the token has been revoked. */
  public get isRevoked(): boolean {
    return !!this.get("revoked_at");
  }

  /** Whether the token is still usable (not expired and not revoked). */
  public get isValid(): boolean {
    return !this.isExpired && !this.isRevoked;
  }

  /**
   * Unconditionally stamp `revoked_at` on this token.
   */
  public async revoke(): Promise<this> {
    return this.merge({ revoked_at: new Date() }).save();
  }

  /**
   * Atomically revoke this token ONLY if it is still active. Resolves to `true`
   * when this call performed the revoke, `false` when a concurrent request had
   * already revoked it — the win/lose signal that powers rotation replay
   * detection. Uses a conditional UPDATE so two concurrent rotations of the
   * same token can never both succeed.
   */
  public async revokeIfActive(): Promise<boolean> {
    const modelClass = this.constructor as typeof RefreshToken;

    const revokedCount = await modelClass.atomic(
      { id: this.id, revoked_at: null },
      { $set: { revoked_at: new Date() } },
    );

    return revokedCount > 0;
  }

  /**
   * Touch `last_used_at` without revoking — the non-rotating refresh path.
   */
  public async markAsUsed(): Promise<void> {
    await this.merge({ last_used_at: new Date() }).save();
  }

  /**
   * Persist a freshly-signed refresh token for the user.
   */
  public static issue(user: Auth, token: string, options: RefreshTokenIssueOptions) {
    return this.create({
      token,
      user_id: user.id,
      user_type: user.userType,
      family_id: options.familyId,
      expires_at: options.expiresAt,
      device_info: options.deviceInfo
        ? {
            userAgent: options.deviceInfo.userAgent,
            ip: options.deviceInfo.ip,
            deviceId: options.deviceInfo.deviceId,
          }
        : undefined,
    });
  }

  /**
   * Find a refresh-token row by its raw token string.
   */
  public static findByToken(token: string): Promise<RefreshToken | null> {
    return this.first({ token });
  }

  /**
   * Find a refresh token scoped to a user — used by logout so a caller can only
   * revoke a token that actually belongs to them.
   */
  public static findForUser(user: Auth, token: string): Promise<RefreshToken | null> {
    return this.first({ token, user_id: user.id });
  }

  /**
   * Delete a specific refresh token belonging to the user.
   */
  public static deleteForUser(user: Auth, token: string) {
    return this.delete({ token, user_id: user.id });
  }

  /**
   * Active, unexpired sessions for the user, newest first.
   */
  public static activeFor(user: Auth): Promise<RefreshToken[]> {
    return this.query()
      .where({ user_id: user.id, user_type: user.userType, revoked_at: null })
      .where("expires_at", ">", new Date())
      .orderBy("created_at", "desc")
      .get();
  }

  /**
   * Revoke every still-active refresh token for the user, returning the rows
   * that were revoked so the caller can emit a per-token event for each.
   *
   * Rows are fetched BEFORE they are revoked: a bulk `findAndUpdate` keyed on
   * `revoked_at: null` would re-query the same predicate after the update and
   * match nothing, returning an empty set.
   */
  public static async revokeAllFor(user: Auth): Promise<RefreshToken[]> {
    const tokens = await this.query()
      .where({ user_id: user.id, user_type: user.userType, revoked_at: null })
      .get();

    for (const token of tokens) {
      await token.revoke();
    }

    return tokens;
  }

  /**
   * Revoke every still-active token in a family (rotation breach containment),
   * returning the revoked rows (fetched before revocation — see `revokeAllFor`).
   */
  public static async revokeFamily(familyId: string): Promise<RefreshToken[]> {
    const tokens = await this.query().where({ family_id: familyId, revoked_at: null }).get();

    for (const token of tokens) {
      await token.revoke();
    }

    return tokens;
  }

  /**
   * Revoke the oldest active tokens so at most `max - 1` remain — making room
   * for the about-to-be-issued one. Bounded by `max`, so the per-row loop is
   * small.
   */
  public static async enforceMax(user: Auth, max: number): Promise<void> {
    const activeTokens = await this.query()
      .where({ user_id: user.id, user_type: user.userType, revoked_at: null })
      .orderBy("created_at", "asc")
      .get();

    if (activeTokens.length < max) return;

    const tokensToRevoke = activeTokens.slice(0, activeTokens.length - max + 1);

    for (const token of tokensToRevoke) {
      await token.revoke();
    }
  }

  /**
   * Hard-delete every expired refresh token, returning the deleted rows so the
   * caller can emit a per-token event. Runs from the `auth.cleanup` CLI command
   * (a cold batch path).
   */
  public static async purgeExpired(): Promise<RefreshToken[]> {
    const expiredTokens = await this.query().where("expires_at", "<", new Date()).get();

    for (const token of expiredTokens) {
      await token.destroy();
    }

    return expiredTokens;
  }
}
