import { DatabaseSync, type SQLInputValue } from 'node:sqlite';
import { existsSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { privateDirectory, protectPrivatePath } from '../security/private-storage.js';

/** Snapshot an existing database without running application migrations first. */
export function backupDatabase(source: string, destination: string): void {
  const path = resolve(destination);
  if (existsSync(path)) throw new Error('BACKUP_ALREADY_EXISTS');
  privateDirectory(dirname(path));
  const database = new DatabaseSync(resolve(source), { readOnly: true });
  try { database.prepare('VACUUM INTO ?').run(path); } finally { database.close(); }
  protectPrivatePath(path);
}

export class SqliteStore {
  private readonly db: DatabaseSync;
  private depth = 0;
  constructor(path: string) {
    this.db = new DatabaseSync(path);
    this.db.exec('PRAGMA foreign_keys = ON; PRAGMA journal_mode = WAL; PRAGMA busy_timeout = 5000;');
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS schema_version (version INTEGER PRIMARY KEY CHECK(version=1));
      INSERT OR IGNORE INTO schema_version VALUES (1);
      CREATE TABLE IF NOT EXISTS accounts (
        id TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
        created_at INTEGER NOT NULL, UNIQUE(provider, subject));
      CREATE TABLE IF NOT EXISTS invitations (
        hash TEXT PRIMARY KEY, provider TEXT NOT NULL, subject TEXT NOT NULL,
        expires_at INTEGER NOT NULL, used_at INTEGER);
      CREATE TABLE IF NOT EXISTS sessions (
        hash TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), expires_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS orders (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), offer_json TEXT NOT NULL,
        status TEXT NOT NULL CHECK(status IN ('pending','paid','cancelled')), created_at INTEGER NOT NULL,
        paid_at INTEGER, payment_method TEXT, payment_reference TEXT,
        UNIQUE(payment_method, payment_reference));
      CREATE TABLE IF NOT EXISTS entitlements (
        account_id TEXT NOT NULL REFERENCES accounts(id), edition_id TEXT NOT NULL,
        order_id TEXT NOT NULL REFERENCES orders(id), active INTEGER NOT NULL CHECK(active IN (0,1)),
        PRIMARY KEY(account_id, edition_id));
      CREATE TABLE IF NOT EXISTS credits (
        account_id TEXT NOT NULL REFERENCES accounts(id), group_id TEXT NOT NULL,
        balance INTEGER NOT NULL CHECK(balance>=0), PRIMARY KEY(account_id, group_id));
      CREATE TABLE IF NOT EXISTS bindings (
        account_id TEXT NOT NULL REFERENCES accounts(id), group_id TEXT NOT NULL, device_id TEXT NOT NULL UNIQUE,
        public_key TEXT NOT NULL, key_thumbprint TEXT NOT NULL, fingerprint_json TEXT NOT NULL,
        bound_at INTEGER NOT NULL, free_at INTEGER NOT NULL, generation INTEGER NOT NULL,
        enabled INTEGER NOT NULL CHECK(enabled IN (0,1)),
        PRIMARY KEY(account_id, group_id), UNIQUE(group_id, key_thumbprint));
      CREATE TABLE IF NOT EXISTS challenges (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), kind TEXT NOT NULL,
        payload TEXT NOT NULL, message TEXT NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER);
      CREATE TABLE IF NOT EXISTS commands (
        account_id TEXT NOT NULL, operation TEXT NOT NULL, command_key TEXT NOT NULL,
        request_hash TEXT NOT NULL, result_json TEXT NOT NULL,
        PRIMARY KEY(account_id, operation, command_key));
      CREATE TABLE IF NOT EXISTS audit (
        id TEXT PRIMARY KEY, actor TEXT NOT NULL, action TEXT NOT NULL, target TEXT NOT NULL,
        details TEXT NOT NULL, created_at INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS outbox (
        id TEXT PRIMARY KEY, topic TEXT NOT NULL, account_id TEXT NOT NULL REFERENCES accounts(id),
        created_at INTEGER NOT NULL, delivered_at INTEGER, attempts INTEGER NOT NULL DEFAULT 0);
      CREATE TABLE IF NOT EXISTS distributions (
        id TEXT PRIMARY KEY, account_id TEXT NOT NULL REFERENCES accounts(id), edition_id TEXT NOT NULL,
        release_id TEXT NOT NULL, identity_snapshot TEXT NOT NULL, artifact_sha256 TEXT,
        manifest TEXT, created_at INTEGER NOT NULL, finalized_at INTEGER);
      CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires_at);
      CREATE INDEX IF NOT EXISTS orders_account ON orders(account_id, created_at);
      CREATE INDEX IF NOT EXISTS challenges_expiry ON challenges(expires_at);
      CREATE INDEX IF NOT EXISTS outbox_pending ON outbox(delivered_at, created_at);
    `);
    // Additive migration: preserve the v1 accounts layout used by integrations.
    this.transaction(() => {
      this.db.exec(`CREATE TABLE IF NOT EXISTS plk_migrations(version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS account_states(account_id TEXT PRIMARY KEY REFERENCES accounts(id),
          active INTEGER NOT NULL CHECK(active IN (0,1)), reason TEXT NOT NULL, updated_at INTEGER NOT NULL);
        INSERT OR IGNORE INTO plk_migrations VALUES(2, CAST(strftime('%s','now') AS INTEGER)*1000);`);
    });
  }
  get<T>(sql: string, ...params: SQLInputValue[]): T | undefined {
    return this.db.prepare(sql).get(...params) as T | undefined;
  }
  all<T>(sql: string, ...params: SQLInputValue[]): T[] { return this.db.prepare(sql).all(...params) as T[]; }
  run(sql: string, ...params: SQLInputValue[]): void { this.db.prepare(sql).run(...params); }
  /** Synchronous callback only. No network IO inside the write transaction. */
  transaction<T>(work: () => T): T {
    const level = this.depth++;
    const savepoint = `plk_${level}`;
    try {
      this.db.exec(level === 0 ? 'BEGIN IMMEDIATE' : `SAVEPOINT ${savepoint}`);
      try {
        const result = work();
        if (result && typeof (result as { then?: unknown }).then === 'function') throw new Error('ASYNC_TRANSACTION_NOT_SUPPORTED');
        this.db.exec(level === 0 ? 'COMMIT' : `RELEASE SAVEPOINT ${savepoint}`);
        return result;
      } catch (error) {
        if (level === 0) this.db.exec('ROLLBACK');
        else this.db.exec(`ROLLBACK TO SAVEPOINT ${savepoint}; RELEASE SAVEPOINT ${savepoint}`);
        throw error;
      }
    } finally { this.depth--; }
  }
  /** Consistent SQLite snapshot, including committed WAL data; never overwrite. */
  backup(destination: string): void {
    const path = resolve(destination);
    if (existsSync(path)) throw new Error('BACKUP_ALREADY_EXISTS');
    privateDirectory(dirname(path));
    this.db.prepare('VACUUM INTO ?').run(path);
    protectPrivatePath(path);
  }
  close(): void { this.db.close(); }
}
