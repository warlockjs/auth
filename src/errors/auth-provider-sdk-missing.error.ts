import { ServerError } from "@warlock.js/core";

/**
 * A login method needs a vendor SDK that is an optional peer of
 * `@warlock.js/auth` and is not installed. The message names the package and
 * the `warlock add` command that installs it; the resolver failure is kept on
 * `cause`.
 */
export class AuthProviderSdkMissingError extends ServerError {
  public constructor(
    public readonly packageName: string,
    public readonly feature: string,
    cause?: unknown,
  ) {
    super(
      `@warlock.js/auth: this login method needs "${packageName}", which is not installed — ` +
        `run \`warlock add ${feature}\`.`,
    );
    this.name = "AuthProviderSdkMissingError";
    this.cause = cause;
  }
}
