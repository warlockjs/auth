import { NO_EXPIRATION } from "../contracts/types";

/**
 * Duration object for specifying time periods
 * All units are additive (e.g., { days: 1, hours: 6 } = 30 hours)
 *
 * @example
 * ```typescript
 * { hours: 1 }           // 1 hour
 * { days: 7, hours: 12 } // 7.5 days
 * { minutes: 30 }        // 30 minutes
 * ```
 */
export type Duration = {
  milliseconds?: number;
  seconds?: number;
  minutes?: number;
  hours?: number;
  days?: number;
  weeks?: number;
};

/**
 * Expiration value type - can be a Duration object, string format, or NO_EXPIRATION
 */
export type ExpiresIn = Duration | typeof NO_EXPIRATION | string | number;

/**
 * Parse duration to milliseconds
 * Supports Duration object, string format ("1d 2h 30m"), or number (raw ms)
 *
 * @example
 * ```typescript
 * parseExpirationToMs({ hours: 1 })       // 3600000
 * parseExpirationToMs({ days: 1 })        // 86400000
 * parseExpirationToMs("1h")               // 3600000
 * parseExpirationToMs("1d 2h 30m")        // 95400000
 * parseExpirationToMs(3600000)            // 3600000
 * parseExpirationToMs(NO_EXPIRATION)      // undefined
 * ```
 */
export function parseExpirationToMs(
  expiration: ExpiresIn | undefined,
  defaultMs: number = 3600000, // 1 hour
): number | undefined {
  if (expiration === undefined) {
    return defaultMs;
  }

  if (expiration === NO_EXPIRATION) {
    return undefined;
  }

  if (typeof expiration === "number") {
    return expiration;
  }

  if (typeof expiration === "string") {
    return parseStringDuration(expiration);
  }

  // It's a Duration object
  return parseDurationObject(expiration);
}

/**
 * Parse a Duration object to milliseconds
 */
function parseDurationObject(duration: Duration): number {
  let ms = 0;

  if (duration.milliseconds) ms += duration.milliseconds;
  if (duration.seconds) ms += duration.seconds * 1000;
  if (duration.minutes) ms += duration.minutes * 60 * 1000;
  if (duration.hours) ms += duration.hours * 60 * 60 * 1000;
  if (duration.days) ms += duration.days * 24 * 60 * 60 * 1000;
  if (duration.weeks) ms += duration.weeks * 7 * 24 * 60 * 60 * 1000;

  return ms;
}

/**
 * Parse a string duration to milliseconds
 * Supports formats: "1h", "7d", "30m", "90s", "1d 2h 30m"
 */
function parseStringDuration(str: string): number {
  let totalMs = 0;
  const parts = str.trim().split(/\s+/);

  for (const part of parts) {
    const match = part.match(/^(\d+(?:\.\d+)?)([smhdw])$/i);
    if (!match) continue;

    const value = parseFloat(match[1]);
    const unit = match[2].toLowerCase();

    switch (unit) {
      case "s":
        totalMs += value * 1000;
        break;
      case "m":
        totalMs += value * 60 * 1000;
        break;
      case "h":
        totalMs += value * 60 * 60 * 1000;
        break;
      case "d":
        totalMs += value * 24 * 60 * 60 * 1000;
        break;
      case "w":
        totalMs += value * 7 * 24 * 60 * 60 * 1000;
        break;
    }
  }

  return totalMs || 3600000; // Default to 1 hour if nothing parsed
}

/**
 * Convert ExpiresIn to a value suitable for jwt.generate (string or number)
 * Returns undefined if NO_EXPIRATION
 */
export function toJwtExpiresIn(
  expiration: ExpiresIn | undefined,
  defaultMs: number = 3600000,
): string | undefined {
  const ms = parseExpirationToMs(expiration, defaultMs);
  if (ms === undefined) return undefined;

  // Convert ms to seconds for JWT (more common format)
  return Math.floor(ms / 1000) + "s";
}
