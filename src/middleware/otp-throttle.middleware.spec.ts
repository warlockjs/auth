import { beforeEach, describe, expect, it, vi } from "vitest";

const loginThrottleMiddleware = vi.hoisted(() => vi.fn((options: unknown) => options));

vi.mock("./login-throttle.middleware", () => ({ loginThrottleMiddleware }));

import {
  otpRequestThrottleMiddleware,
  otpVerifyThrottleMiddleware,
} from "./otp-throttle.middleware";
import { defined } from "../test-support/defined";

beforeEach(() => {
  loginThrottleMiddleware.mockClear();
});

describe("OTP throttle presets (built on loginThrottleMiddleware)", () => {
  it("issue: every request counts, per phone + IP, 3 per 1h", () => {
    otpRequestThrottleMiddleware();

    const options = defined(loginThrottleMiddleware.mock.calls[0], "first call")[0] as Record<string, unknown> & {
      isFailure: () => boolean;
    };

    expect(options).toMatchObject({
      max: 3,
      window: "1h",
      by: ["email", "ip"],
      identifierKey: "phone",
    });
    expect(options.isFailure()).toBe(true);
  });

  it("verify: failure-aware, per phone + IP, 5 per 15m", () => {
    otpVerifyThrottleMiddleware();

    const options = defined(loginThrottleMiddleware.mock.calls[0], "first call")[0] as Record<string, unknown>;

    expect(options).toMatchObject({
      max: 5,
      window: "15m",
      lockoutDuration: "15m",
      by: ["email", "ip"],
      identifierKey: "phone",
    });
    expect(options.isFailure).toBeUndefined();
  });

  it("app overrides win", () => {
    otpVerifyThrottleMiddleware({ max: 2 });

    expect(defined(loginThrottleMiddleware.mock.calls[0], "first call")[0]).toMatchObject({
      max: 2,
      identifierKey: "phone",
    });
  });
});
