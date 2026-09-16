import type { AuthNotification, OneTimeTokenNotificationData } from "../contracts/types";
import { NotificationsUnavailableError } from "../errors/notifications-unavailable.error";
import { authConfig } from "./auth-config";

/** Which token notification to resolve. */
export type TokenNotificationType = "email-verification" | "password-reset";

/**
 * The slice of `@warlock.js/notifications` auth uses. Declared locally because
 * the package is an OPTIONAL peer: auth must type-check and load without it.
 */
type NotificationsModule = {
  getNotificationConfig: () => unknown;
  defineNotification: (definition: {
    type: string;
    via: string[];
    mail: (data: OneTimeTokenNotificationData) => { subject: string; html: string; text: string };
  }) => AuthNotification;
};

/** Non-literal on purpose: keeps type-checkers and bundlers from requiring the optional peer. */
const NOTIFICATIONS_PACKAGE: string = "@warlock.js/notifications";

const defaults = new Map<TokenNotificationType, AuthNotification>();

/**
 * Whether `error` (or an error it wraps as `cause`, as some loaders do) is the
 * resolver saying the notifications package itself is absent. A missing
 * TRANSITIVE dependency names a different package and is rethrown untouched.
 */
function isPackageMissing(error: unknown): boolean {
  for (let current = error, depth = 0; current && depth < 5; depth++) {
    const { code, message } = current as { code?: unknown; message?: unknown };

    if (
      (code === "ERR_MODULE_NOT_FOUND" || code === "MODULE_NOT_FOUND") &&
      typeof message === "string" &&
      message.includes(`'${NOTIFICATIONS_PACKAGE}'`)
    ) {
      return true;
    }

    current = (current as { cause?: unknown }).cause;
  }

  return false;
}

async function loadNotifications(): Promise<NotificationsModule> {
  let notifications: NotificationsModule;

  try {
    notifications = (await import(NOTIFICATIONS_PACKAGE)) as NotificationsModule;
  } catch (error) {
    if (isPackageMissing(error)) {
      throw new NotificationsUnavailableError("not-installed", error);
    }

    throw error;
  }

  try {
    notifications.getNotificationConfig();
  } catch (error) {
    throw new NotificationsUnavailableError("not-configured", error);
  }

  return notifications;
}

function escapeHtml(value: string): string {
  return value
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

function mailBody(intro: string, data: OneTimeTokenNotificationData) {
  const action = data.url ?? data.token;
  const expires = data.expiresAt.toISOString();

  return {
    html:
      `<p>${intro}</p>` +
      (data.url
        ? `<p><a href="${escapeHtml(data.url)}">${escapeHtml(data.url)}</a></p>`
        : `<p><code>${escapeHtml(data.token)}</code></p>`) +
      `<p>This link expires at ${expires}. If you did not request it, ignore this email.</p>`,
    text: `${intro}\n\n${action}\n\nThis link expires at ${expires}. If you did not request it, ignore this email.`,
  };
}

function defineDefault(
  notifications: NotificationsModule,
  type: TokenNotificationType,
): AuthNotification {
  if (type === "email-verification") {
    return notifications.defineNotification({
      type: "auth.email-verification",
      via: ["mail"],
      mail: (data) => ({
        subject: "Verify your email address",
        ...mailBody("Confirm your email address to finish setting up your account.", data),
      }),
    });
  }

  return notifications.defineNotification({
    type: "auth.password-reset",
    via: ["mail"],
    mail: (data) => ({
      subject: "Reset your password",
      ...mailBody("Use this to choose a new password.", data),
    }),
  });
}

/**
 * Resolve the notification a token of `type` is delivered through — the app's
 * configured override, else auth's default mail notification.
 *
 * Always confirms `@warlock.js/notifications` is installed AND configured
 * first, even when an override is set, so an app can never issue a token that
 * silently goes nowhere. Throws {@link NotificationsUnavailableError}.
 */
export async function resolveTokenNotification(
  type: TokenNotificationType,
): Promise<AuthNotification> {
  const notifications = await loadNotifications();

  const override =
    type === "email-verification"
      ? authConfig.verification.notification()
      : authConfig.passwordReset.notification();

  if (override) return override;

  let notification = defaults.get(type);

  if (!notification) {
    notification = defineDefault(notifications, type);
    defaults.set(type, notification);
  }

  return notification;
}
