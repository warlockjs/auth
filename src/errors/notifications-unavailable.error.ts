import { ServerError } from "@warlock.js/core";

/**
 * Email verification / password reset could not send its notification because
 * `@warlock.js/notifications` is not installed or not configured. Thrown BEFORE
 * any token is issued — auth never issues a token it cannot deliver, and never
 * skips the send silently. The original failure is kept on `cause`.
 */
export class NotificationsUnavailableError extends ServerError {
  public constructor(reason: "not-installed" | "not-configured", cause?: unknown) {
    super(
      reason === "not-installed"
        ? "@warlock.js/auth: email verification and password reset send through " +
            "@warlock.js/notifications, which is not installed — add it to the app's dependencies."
        : "@warlock.js/auth: email verification and password reset send through " +
            "@warlock.js/notifications, which is not configured — add `src/config/notifications.ts` " +
            "with a `mail` channel.",
    );
    this.name = "NotificationsUnavailableError";
    this.cause = cause;
  }
}
