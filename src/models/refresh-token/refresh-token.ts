import { Model, type Casts } from "@warlock.js/cascade";

export class RefreshToken extends Model {
  /**
   * {@inheritDoc}
   */
  public static collection = "refreshTokens";

  /**
   * {@inheritDoc}
   */
  protected casts: Casts = {
    token: "string",
    userId: "int",
    userType: "string",
    familyId: "string",
    expiresAt: "date",
    lastUsedAt: "date",
    revokedAt: "date",
    deviceInfo: "object",
  };

  /**
   * Check if token is expired
   */
  public get isExpired(): boolean {
    const expiresAt = this.get("expiresAt");
    if (!expiresAt) return false;
    return new Date() > new Date(expiresAt);
  }

  /**
   * Check if token is revoked
   */
  public get isRevoked(): boolean {
    return !!this.get("revokedAt");
  }

  /**
   * Check if token is valid (not expired and not revoked)
   */
  public get isValid(): boolean {
    return !this.isExpired && !this.isRevoked;
  }

  /**
   * Revoke this token
   */
  public async revoke(): Promise<this> {
    return this.save({ revokedAt: new Date() });
  }

  /**
   * Mark token as used (update lastUsedAt)
   */
  public async markAsUsed(): Promise<void> {
    this.silentSaving({ lastUsedAt: new Date() });
  }
}
