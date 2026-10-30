import { scrypt } from 'node:crypto';
import { DomainError } from '../core/model.js';

// Limit memory-hard work across IPs as well as at individual HTTP endpoints.
let active = 0;
const waiting: Array<() => void> = [];
const concurrency = 4, maxQueued = 32;
async function acquire() {
  if (active < concurrency) { active++; return; }
  if (waiting.length >= maxQueued) throw new DomainError('AUTH_BUSY', 503);
  await new Promise<void>(resolve => waiting.push(resolve));
}
function release() {
  const next = waiting.shift();
  if (next) next(); else active--;
}
export async function hashPassword(password: string, salt: string): Promise<string> {
  await acquire();
  try {
    return await new Promise<string>((resolve, reject) => scrypt(password, salt, 64,
      { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 },
      (error, key) => error ? reject(error) : resolve(key.toString('hex'))));
  } finally { release(); }
}
