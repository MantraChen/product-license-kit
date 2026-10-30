import { readFileSync, existsSync, writeFileSync, unlinkSync } from 'node:fs';
import { join, dirname, resolve } from 'node:path';
import { randomUUID } from 'node:crypto';
import { backupDatabase } from '../adapters/sqlite.js';
import { encryptBackup, restoreBackup } from '../security/backup.js';
import { privateDirectory, protectPrivatePath } from '../security/private-storage.js';
import { rotateSigningKey } from '../security/signing-rotation.js';
import { assertServiceStopped } from '../security/process-lock.js';
import { requireThat } from '../core/model.js';

const [action, passwordFile, destination] = process.argv.slice(2);
requireThat(action && ['backup', 'restore', 'rotate-signing'].includes(action) && passwordFile,
  'USAGE_maintenance_ACTION_PASSWORD_FILE_DESTINATION');
const password = readFileSync(resolve(passwordFile), 'utf8').trim();
requireThat(password.length >= 20, 'BACKUP_PASSWORD_LENGTH');
if (action === 'restore') {
  requireThat(destination && process.argv[5], 'RESTORE_REQUIRES_BUNDLE_AND_NEW_DIRECTORY');
  restoreBackup(readFileSync(resolve(destination)), password, resolve(process.argv[5]!));
  console.log('Backup verified and restored into a new private directory.');
} else {
  const database = resolve(process.env.DATABASE_PATH ?? '.data/framework.sqlite');
  const data = dirname(database);
  assertServiceStopped(join(data, 'framework.lock'));
  const output = destination ? resolve(destination) : join(data, 'backups', `${Date.now()}-${randomUUID()}.plkbackup`);
  privateDirectory(dirname(output));
  const snapshot = join(data, `snapshot-${randomUUID()}.sqlite`);
  backupDatabase(database, snapshot);
  const files: Record<string, Uint8Array> = { 'framework.sqlite':readFileSync(snapshot),
    'signing.pem':readFileSync(resolve(process.env.SIGNING_KEY_PATH ?? join(data, 'signing.pem'))) };
  if (existsSync('.env')) files['environment.env'] = readFileSync('.env');
  if (existsSync(join(data, 'local-identities.json'))) files['local-identities.json'] = readFileSync(join(data, 'local-identities.json'));
  writeFileSync(output, encryptBackup(files, password), {flag:'wx', mode:0o600});
  protectPrivatePath(output);
  unlinkSync(snapshot);
  if (action === 'rotate-signing') {
    requireThat(resolve(process.env.SIGNING_KEY_PATH ?? join(data, 'signing.pem')) === join(data, 'signing.pem'), 'ROTATION_REQUIRES_STANDARD_KEY_PATH');
    console.log(JSON.stringify({ backup:output, ...rotateSigningKey(data) }));
  } else console.log(JSON.stringify({backup:output}));
}
