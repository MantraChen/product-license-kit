import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { encryptBackup, decryptBackup } from '../src/security/backup.js';

test('backups above the previous 64 MiB limit round-trip with authentication', () => {
  const source = Buffer.alloc(65 * 1024 * 1024, 71);
  const password = 'capacity-test-password-only';
  const encrypted = encryptBackup({'database.sqlite': source}, password);
  const restored = decryptBackup(encrypted, password)['database.sqlite']!;
  assert.equal(restored.length, source.length);
  const digest = (b: Buffer) => createHash('sha256').update(b).digest('hex');
  assert.equal(digest(restored), digest(source));
});
