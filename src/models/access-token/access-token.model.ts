import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import type { Auth } from "../auth.model";

/**
 * Seal schema for the persisted access-token record. Exported so an override
 * can spread it and add columns (e.g. a tenant key) without re-declaring the
 * base shape.
 *
 * `last_access` and the `is_active` soft-revoke flag were removed — neither was
 * ever read; access tokens are revoked by deleting the row.
 */
export const accessTokenSchema = v.object({
  token: v.string().required(),
  user_id: v.scalar().required(),
  user_type: v.string().required(),
  expires_at: v.date().required(),
});

/**
 * Persisted access-token record + the data layer for access tokens.
 *
 * **Role.** Owns access-token persistence and lookup. The middleware checks a
 * presented JWT against this table so deleting a row (logout) invalidates the
 * token immediately, before its JWT expiry. The auth service goes through the
 * named statics exclusively, so it never hard-codes a column name and an
 * override can rename/add columns by registering under
 * `config.auth.accessToken.model`.
 */
export class AccessToken extends Model {
  public static table = "access_tokens";

  public static schema = accessTokenSchema;

  /** The user this token was issued for. */
  public get userId() {
    return this.get("user_id");
  }

  /** The user-type slug this token was issued for. */
  public get userType(): string {
    return this.get("user_type");
  }

  /**
   * Persist a freshly-signed access token for the user.
   */
  public static issue(user: Auth, token: string, expiresAt: Date) {
    return this.create({
      token,
      user_id: user.id,
      user_type: user.userType,
      expires_at: expiresAt,
    });
  }

  /**
   * Find an access-token row by its raw token string.
   */
  public static findByToken(token: string): Promise<AccessToken | null> {
    return this.first({ token });
  }

  /**
   * Delete a specific token that belongs to the given user.
   */
  public static deleteForUser(user: Auth, token: string) {
    return this.delete({ token, user_id: user.id });
  }

  /**
   * Delete every access token belonging to the user.
   */
  public static deleteAllForUser(user: Auth) {
    return this.delete({ user_id: user.id });
  }

  /**
   * Hard-delete every expired access-token row. Returns the number removed.
   * Runs from the `auth.cleanup` CLI command (a cold batch path).
   */
  public static async purgeExpired(): Promise<number> {
    const expiredTokens = await this.query().where("expires_at", "<", new Date()).get();

    for (const token of expiredTokens) {
      await token.destroy();
    }

    return expiredTokens.length;
  }
}
