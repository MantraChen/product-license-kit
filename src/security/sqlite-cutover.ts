import { existsSync, realpathSync } from 'node:fs';
import { resolve } from 'node:path';
import { requireThat } from '../core/model.js';

export function sqliteCutoverPath(database: string) {
  const path = resolve(database);
  return (
    (existsSync(path) ? realpathSync(path) : path) + '.postgres-cutover.json'
  );
}
/** Both pending and completed cutovers require explicit operator review before any SQLite restart. */
export function assertSqliteNotCutOver(database: string) {
  if (database === ':memory:') return;
  requireThat(
    !existsSync(sqliteCutoverPath(database)),
    'SQLITE_CUTOVER_REVIEW_REQUIRED',
    409,
  );
}
