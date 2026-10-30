import { requireThat } from '../core/model.js';
import { secretEqual } from '../core/crypto.js';

export interface BrowserPolicy {
  origin: string;
  protectedPrefixes: readonly string[];
  machinePrefixes?: readonly string[];
  publicWrites?: readonly string[];
}
/** matchedRoute MUST be router metadata, never a raw or manually decoded URL. */
export function guardBrowserRequest(request: {
  method: string; matchedRoute?: string; origin?: string; csrfToken?: unknown;
}, policy: BrowserPolicy, sessionCsrf: () => string | undefined): void {
  if (request.origin !== undefined) requireThat(request.origin === policy.origin, 'ORIGIN_REJECTED', 403);
  const route = request.matchedRoute;
  if (!route || ['GET', 'HEAD', 'OPTIONS'].includes(request.method) ||
      !policy.protectedPrefixes.some(prefix => route.startsWith(prefix)) ||
      policy.machinePrefixes?.some(prefix => route.startsWith(prefix))) return;
  requireThat(request.origin === policy.origin, 'ORIGIN_REQUIRED', 403);
  if (policy.publicWrites?.includes(route)) return;
  const expected = sessionCsrf();
  requireThat(expected, 'AUTH_REQUIRED', 401);
  requireThat(typeof request.csrfToken === 'string' && secretEqual(expected, request.csrfToken), 'CSRF_REJECTED', 403);
}
