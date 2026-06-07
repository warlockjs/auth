import { afterEach, describe, expect, it, vi } from "vitest";

vi.mock("@warlock.js/logger", () => ({
  log: { error: vi.fn() },
}));

import { log } from "@warlock.js/logger";
import { authEvents } from "./auth-events";

afterEach(() => {
  authEvents.unsubscribeAll();
});

describe("authEvents", () => {
  it("delivers emitted payloads to `on` subscribers", () => {
    const listener = vi.fn();

    authEvents.on("cleanup.completed", listener);
    authEvents.emit("cleanup.completed", 5);

    expect(listener).toHaveBeenCalledWith(5);
  });

  it("treats `subscribe` as an alias for `on`", () => {
    const listener = vi.fn();

    authEvents.subscribe("cleanup.completed", listener);
    authEvents.emit("cleanup.completed", 3);

    expect(listener).toHaveBeenCalledWith(3);
  });

  it("treats `trigger` as an alias for `emit`", () => {
    const listener = vi.fn();

    authEvents.on("cleanup.completed", listener);
    authEvents.trigger("cleanup.completed", 9);

    expect(listener).toHaveBeenCalledWith(9);
  });

  it("passes every positional argument through to the listener", () => {
    const listener = vi.fn();
    const user = { id: 1 };
    const tokenPair = { accessToken: { token: "t", expiresAt: "soon" } };
    const deviceInfo = { ip: "127.0.0.1" };

    authEvents.on("login.success", listener);
    authEvents.emit("login.success", user as never, tokenPair as never, deviceInfo as never);

    expect(listener).toHaveBeenCalledWith(user, tokenPair, deviceInfo);
  });

  it("stops delivering to a specific event after `off(event)`", () => {
    const listener = vi.fn();

    authEvents.on("cleanup.completed", listener);
    authEvents.off("cleanup.completed");
    authEvents.emit("cleanup.completed", 1);

    expect(listener).not.toHaveBeenCalled();
  });

  it("removes every auth subscription on `unsubscribeAll`", () => {
    const loginListener = vi.fn();
    const logoutListener = vi.fn();

    authEvents.on("login.success", loginListener);
    authEvents.on("logout", logoutListener);
    authEvents.unsubscribeAll();

    authEvents.emit("login.success", {} as never, {} as never);
    authEvents.emit("logout", {} as never);

    expect(loginListener).not.toHaveBeenCalled();
    expect(logoutListener).not.toHaveBeenCalled();
  });

  it("returns an unsubscribe handle from `on`", () => {
    const listener = vi.fn();

    const subscription = authEvents.on("cleanup.completed", listener);
    subscription.unsubscribe();
    authEvents.emit("cleanup.completed", 1);

    expect(listener).not.toHaveBeenCalled();
  });

  it("isolates a throwing listener — emit logs and does not rethrow", () => {
    authEvents.on("login.success", () => {
      throw new Error("listener boom");
    });

    // a throwing listener must not break the auth flow that emitted the event
    expect(() => authEvents.emit("login.success", {} as never, {} as never)).not.toThrow();
    expect(log.error).toHaveBeenCalled();
  });
});
