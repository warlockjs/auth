import type { HttpContext, Request, Response } from "@warlock.js/core";

/**
 * The single registered boundary where specs bridge partial request/response
 * mocks to `HttpContext` (canon `8b75e45b` §7). Every other spec call site
 * builds its context through this factory instead of casting `as never` at
 * the invocation, so a signature change to `Middleware`/`RequestHandler` now
 * fails to compile AT EVERY CALL SITE instead of hiding behind scattered
 * casts.
 */
export function makeCtx(input: { request?: object; response?: object } = {}): HttpContext {
  const { request = {}, response = {} } = input;

  return {
    request: request as unknown as Request,
    response: response as unknown as Response,
  };
}
