import { Model } from "@warlock.js/cascade";
import { v } from "@warlock.js/seal";
import { isNeverExpiring, isUsableExpiry } from "../../utils/token-expiry";
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
   * Whether the persisted expiry has passed.
   *
   * The middleware asks this on every request, which is what makes the row the
   * authority it always looked like it was: before 4.12.0 the gate only checked
   * that the row *existed*, so a row the database knew was dead still let its
   * token through — the database was never asked.
   *
   * **Fails closed.** A missing or unparseable `expires_at` counts as expired.
   * `expires_at` is `required` in the schema, so a row that cannot answer "when
   * does this die" is malformed, and the safe reading of a malformed credential
   * is that it is not one. This is deliberately stricter than a naive
   * `now > expires_at`, which answers `false` for an `Invalid Date` and thereby
   * grants exactly the poisoned rows an unlimited life.
   */
  public get isExpired(): boolean {
    const expiresAt = this.get("expires_at");

    if (!isUsableExpiry(expiresAt)) return true;

    return new Date(expiresAt).getTime() <= Date.now();
  }

  /**
   * Whether nothing about this row can ever retire it — an unusable
   * `expires_at`, or a token carrying no `exp` claim. See
   * {@link isNeverExpiring}; this is the predicate `purgeNeverExpiring` selects
   * on.
   */
  public get neverExpires(): boolean {
    return isNeverExpiring(this.get("token"), this.get("expires_at"));
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

  /**
   * Every row that can never retire itself — see {@link neverExpires}.
   *
   * **A full scan, filtered in memory, on purpose.** The defining case is a row
   * whose `expires_at` is an `Invalid Date`, which no date predicate can select
   * (`< now` and `> now` are both `false` for it), and the definitive case is a
   * token with no `exp` claim, which lives inside the token string rather than
   * in a column. Neither is expressible as a `where`, so the rows have to be
   * read to be judged. This runs from a one-off remediation command, not a
   * request path.
   */
  public static async findNeverExpiring(): Promise<AccessToken[]> {
    const tokens = await this.query().get();

    return tokens.filter((token: AccessToken) => token.neverExpires);
  }

  /**
   * Hard-delete every never-expiring row, returning the rows removed so the
   * caller can report what it revoked. Deletion *is* revocation for access
   * tokens — the middleware rejects a token with no row.
   */
  public static async purgeNeverExpiring(): Promise<AccessToken[]> {
    const tokens = await this.findNeverExpiring();

    for (const token of tokens) {
      await token.destroy();
    }

    return tokens;
  }
}
