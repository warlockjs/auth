import events, { type EventSubscription } from "@mongez/events";
import type { DeviceInfo, TokenPair } from "../contracts/types";
import type { Auth } from "../models/auth.model";
import type { RefreshToken } from "../models/refresh-token";

/**
 * Auth event payload types
 */
export type AuthEventPayloads = {
  // Login events
  "login.success": [user: Auth, tokenPair: TokenPair, deviceInfo?: DeviceInfo];
  "login.failed": [credentials: { email?: string; username?: string }, reason: string];
  "login.attempt": [credentials: { email?: string; username?: string }];

  // Logout events
  logout: [user: Auth];
  "logout.all": [user: Auth];
  "logout.failsafe": [user: Auth];

  // Token events
  "token.created": [user: Auth, tokenPair: TokenPair];
  "token.refreshed": [user: Auth, newTokenPair: TokenPair, oldRefreshToken: RefreshToken];
  "token.revoked": [user: Auth, token: RefreshToken];
  "token.expired": [token: RefreshToken];
  "token.familyRevoked": [familyId: string, tokens: RefreshToken[]];

  // Password events
  "password.changed": [user: Auth];
  "password.resetRequested": [user: Auth, resetToken: string];
  "password.reset": [user: Auth];

  // Session events
  "session.created": [user: Auth, refreshToken: RefreshToken, deviceInfo?: DeviceInfo];
  "session.destroyed": [user: Auth, refreshToken: RefreshToken];

  // Cleanup events
  "cleanup.completed": [expiredCount: number];
};

/**
 * Auth event names
 */
export type AuthEventName = keyof AuthEventPayloads;

/**
 * Callback type for a specific event
 */
export type AuthEventCallback<T extends AuthEventName> = (
  ...args: AuthEventPayloads[T]
) => void | Promise<void>;

/**
 * Event namespace prefix for auth events
 */
const AUTH_EVENT_PREFIX = "auth.";

/**
 * Type-safe auth events manager
 *
 * @example
 * ```typescript
 * // Subscribe to events with full autocomplete
 * authEvents.on("login.success", (user, tokenPair, deviceInfo) => {
 *   console.log(`User ${user.id} logged in`);
 * });
 *
 * authEvents.on("token.refreshed", (user, newPair, oldToken) => {
 *   console.log(`Token refreshed for user ${user.id}`);
 * });
 *
 * // Trigger events
 * authEvents.emit("login.success", user, tokenPair, deviceInfo);
 * ```
 */
export const authEvents = {
  /**
   * Subscribe to an auth event
   */
  on<T extends AuthEventName>(event: T, callback: AuthEventCallback<T>): EventSubscription {
    return events.subscribe(AUTH_EVENT_PREFIX + event, callback as Function);
  },

  /**
   * Subscribe to an auth event (alias for `on`)
   */
  subscribe<T extends AuthEventName>(event: T, callback: AuthEventCallback<T>): EventSubscription {
    return this.on(event, callback);
  },

  /**
   * Emit an auth event
   */
  emit<T extends AuthEventName>(event: T, ...args: AuthEventPayloads[T]): void {
    events.trigger(AUTH_EVENT_PREFIX + event, ...args);
  },

  /**
   * Emit an auth event (alias for `emit`)
   */
  trigger<T extends AuthEventName>(event: T, ...args: AuthEventPayloads[T]): void {
    this.emit(event, ...args);
  },

  /**
   * Unsubscribe from all auth events
   */
  unsubscribeAll(): void {
    events.unsubscribeNamespace(AUTH_EVENT_PREFIX.slice(0, -1));
  },

  /**
   * Unsubscribe from a specific auth event
   */
  off(event?: AuthEventName): void {
    if (event) {
      events.unsubscribe(AUTH_EVENT_PREFIX + event);
    } else {
      this.unsubscribeAll();
    }
  },
};
