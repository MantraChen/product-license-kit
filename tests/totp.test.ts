import test from 'node:test';
import assert from 'node:assert/strict';
import { newTotpSecret, totpCode, verifyTotp } from '../src/security/totp.js';
test('TOTP SHA-1 matches all RFC 6238 eight-digit vectors and enforces six-digit replay counters', () => {
  const secret = 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ';
  for (const [time, expected] of [
    [59, '94287082'],
    [1111111109, '07081804'],
    [1111111111, '14050471'],
    [1234567890, '89005924'],
    [2000000000, '69279037'],
    [20000000000, '65353130'],
  ] as const)
    assert.equal(totpCode(secret, Math.floor(time / 30), 8), expected);
  assert.equal(verifyTotp(secret, '287082', 59000, -1), 1);
  assert.equal(verifyTotp(secret, '287082', 59000, 1), null);
  assert.equal(verifyTotp(secret, '287082', 150000, -1), null);
  assert.equal(verifyTotp(secret, '287082x', 59000, -1), null);
  assert.match(newTotpSecret(), /^[A-Z2-7]{32}$/);
  assert.throws(() => totpCode(secret, -1), { code: 'INVALID_TOTP_COUNTER' });
});
