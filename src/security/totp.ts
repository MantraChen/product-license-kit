import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import { requireThat } from '../core/model.js';

const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
export function newTotpSecret() {
  let bits = 0,
    value = 0,
    result = '';
  for (const byte of randomBytes(20)) {
    value = (value << 8) | byte;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      result += alphabet[(value >>> bits) & 31];
    }
  }
  return result;
}
function decode(secret: string) {
  requireThat(/^[A-Z2-7]{32,128}$/.test(secret), 'INVALID_TOTP_SECRET');
  let bits = 0,
    value = 0;
  const bytes: number[] = [];
  for (const char of secret) {
    value = (value << 5) | alphabet.indexOf(char);
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 255);
    }
  }
  requireThat(
    bits === 0 || (value & ((1 << bits) - 1)) === 0,
    'INVALID_TOTP_SECRET',
  );
  return Buffer.from(bytes);
}
/** RFC 4226 dynamic truncation; RFC 6238 SHA-1, 30-second counter. */
export function totpCode(secret: string, counter: number, digits: 6 | 8 = 6) {
  requireThat(
    Number.isSafeInteger(counter) && counter >= 0 && [6, 8].includes(digits),
    'INVALID_TOTP_COUNTER',
  );
  const moving = Buffer.alloc(8);
  moving.writeBigUInt64BE(BigInt(counter));
  const digest = createHmac('sha1', decode(secret)).update(moving).digest(),
    offset = digest.at(-1)! & 15;
  return String(
    (digest.readUInt32BE(offset) & 0x7fffffff) % 10 ** digits,
  ).padStart(digits, '0');
}
export function verifyTotp(
  secret: string,
  code: string,
  time: number,
  lastCounter: number,
) {
  requireThat(
    Number.isSafeInteger(time) &&
      time >= 0 &&
      Number.isSafeInteger(lastCounter),
    'INVALID_TOTP_COUNTER',
  );
  if (!/^\d{6}$/.test(code)) return null;
  const current = Math.floor(time / 30000);
  let found: number | null = null;
  for (const counter of [current - 1, current, current + 1]) {
    if (counter < 0) continue;
    const matches = timingSafeEqual(
      Buffer.from(totpCode(secret, counter)),
      Buffer.from(code),
    );
    if (matches && counter > lastCounter) found = counter;
  }
  return found;
}
