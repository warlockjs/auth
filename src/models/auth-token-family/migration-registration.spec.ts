import { describe, expect, it } from "vitest";
import { authMigrations } from "../index";

describe("auth family migrations", () => {
  it("registers each additive migration for installed Auth schemas", () => {
    const migrationNames = authMigrations.map(
      (Migration) => (Migration as { migrationName?: string }).migrationName,
    );

    expect(migrationNames).toEqual(
      expect.arrayContaining([
        "accessTokenFamilyAssociation",
        "refreshTokenSuccessorAssociation",
        "authTokenFamily",
      ]),
    );
  });
});
