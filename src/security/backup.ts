import { createCipheriv, createDecipheriv, randomBytes, scryptSync } from 'node:crypto';
import { existsSync, writeFileSync } from 'node:fs';
import { resolve, join } from 'node:path';
import { z } from 'zod';
import { requireThat } from '../core/model.js';
import { privateDirectory, protectPrivatePath } from './private-storage.js';

export const backupMaxBytes = 256 * 1024 * 1024;
const maxBytes = backupMaxBytes;
const magic = Buffer.from('PLKBACKUP1\n');
const fileName = /^[A-Za-z0-9_.-]{1,100}$/;
function key(password: string, salt: Buffer) {
  requireThat(password.length >= 20 && password.length <= 256, 'BACKUP_PASSWORD_LENGTH');
  return scryptSync(password, salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 });
}
function validateNames(names: string[]) {
  requireThat(names.length > 0 && names.length <= 32 && new Set(names.map(name => name.toLowerCase())).size === names.length, 'INVALID_BACKUP_FILES');
  requireThat(names.every(name => fileName.test(name) && name !== '.' && name !== '..' && !name.endsWith('.') &&
    !/^(con|prn|aux|nul|com[0-9]|lpt[0-9])(?:\.|$)/i.test(name)), 'INVALID_BACKUP_FILENAME');
}
export function encryptBackup(files: Record<string, Uint8Array>, password: string): Buffer {
  validateNames(Object.keys(files));
  requireThat(Object.values(files).reduce((sum, file) => sum + file.byteLength, 0) <= maxBytes, 'BACKUP_TOO_LARGE');
  const salt = randomBytes(16), iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', key(password, salt), iv);
  cipher.setAAD(magic);
  const payload = Buffer.from(JSON.stringify({ version: 1, files: Object.fromEntries(
    Object.entries(files).map(([name, content]) => [name, Buffer.from(content).toString('base64')])) }));
  return Buffer.concat([magic, salt, iv, cipher.update(payload), cipher.final(), cipher.getAuthTag()]);
}
export function decryptBackup(bundle: Uint8Array, password: string): Record<string, Buffer> {
  const bytes = Buffer.from(bundle);
  requireThat(bytes.length <= maxBytes * 2 && bytes.length > magic.length + 44 && bytes.subarray(0, magic.length).equals(magic), 'INVALID_BACKUP');
  let raw: unknown;
  try {
    const offset = magic.length;
    const decipher = createDecipheriv('aes-256-gcm', key(password, bytes.subarray(offset, offset + 16)), bytes.subarray(offset + 16, offset + 28));
    decipher.setAAD(magic); decipher.setAuthTag(bytes.subarray(-16));
    raw = JSON.parse(Buffer.concat([decipher.update(bytes.subarray(offset + 28, -16)), decipher.final()]).toString('utf8'));
  } catch { requireThat(false, 'BACKUP_AUTH_FAILED'); }
  const parsed = z.object({ version: z.literal(1), files: z.record(z.string(), z.string()) }).strict().parse(raw);
  validateNames(Object.keys(parsed.files));
  const files = Object.fromEntries(Object.entries(parsed.files).map(([name, data]) => [name, Buffer.from(data, 'base64')]));
  // Compare canonical encoding without a repetition-heavy regex over large files.
  requireThat(Object.entries(parsed.files).every(([name, data]) => files[name]!.toString('base64') === data), 'INVALID_BACKUP');
  requireThat(Object.values(files).reduce((sum, file) => sum + file.length, 0) <= maxBytes, 'BACKUP_TOO_LARGE');
  return files;
}
/** Restores only to a new private directory, never over a live deployment. */
export function restoreBackup(bundle: Uint8Array, password: string, destination: string): void {
  const files = decryptBackup(bundle, password);
  const target = resolve(destination);
  requireThat(!existsSync(target), 'RESTORE_TARGET_EXISTS');
  privateDirectory(target);
  for (const [name, content] of Object.entries(files)) {
    const path = join(target, name);
    writeFileSync(path, content, { flag: 'wx', mode: 0o600 });
    protectPrivatePath(path);
  }
}
