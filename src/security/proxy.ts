import { isIP } from 'node:net';
import { requireThat } from '../core/model.js';

/** Only explicitly enumerated proxy addresses/subnets; never trust all hops. */
export function trustedProxies(value = ''): false | string[] {
  if (!value.trim()) return false;
  const entries = value.split(',').map(item => item.trim());
  requireThat(entries.length <= 16, 'TOO_MANY_TRUSTED_PROXIES');
  for (const entry of entries) {
    const parts = entry.split('/'), address = parts[0]!;
    const family = isIP(address), bits = family === 4 ? 32 : 128;
    requireThat(family && parts.length <= 2, 'INVALID_TRUSTED_PROXY');
    if (parts.length === 2) {
      requireThat(/^\d{1,3}$/.test(parts[1]!) && Number(parts[1]) > 0 && Number(parts[1]) <= bits, 'INVALID_TRUSTED_PROXY');
    }
    requireThat(address !== '0.0.0.0' && address !== '::', 'UNBOUNDED_TRUSTED_PROXY');
  }
  return entries;
}
