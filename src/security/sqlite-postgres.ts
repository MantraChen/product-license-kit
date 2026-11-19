import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  writeFileSync,
  realpathSync,
  rmSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { z } from 'zod';
import { SqliteStore, backupDatabase } from '../adapters/sqlite.js';
import { PostgresStore } from '../adapters/postgres.js';
import { postgresMigrations } from '../adapters/postgres-schema.js';
import {
  EnvelopeSigner,
  normalizePublicKey,
  sha256,
  verifyEnvelope,
} from '../core/crypto.js';
import { parseCatalog, requireThat, type Catalog } from '../core/model.js';
import {
  postgresBackupLayout,
  verifyPostgresBackupSchema,
} from './postgres-backup.js';
import { backupMaxBytes, decryptBackup, encryptBackup } from './backup.js';
import { acquireServiceLock } from './process-lock.js';
import {
  privateDirectory,
  protectPrivatePath,
  writePrivateAtomic,
} from './private-storage.js';
import { assertSqliteNotCutOver, sqliteCutoverPath } from './sqlite-cutover.js';

type Scalar = string | number | null;
type Row = Record<string, Scalar>;
const scalar = z.union([z.string(), z.number().int().safe(), z.null()]);
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
const excluded = new Set([
  'rate_limit_buckets',
  'signing_keys',
  'signing_policies',
  'signing_rotations',
  'signing_readiness',
  'compatibility_imports',
  'portal_settings','portal_mfa','portal_recovery','portal_operators','portal_oauth_states','portal_sessions','portal_reset_intents',
  'bot_settings','bot_messages','bot_actions','bot_handoffs','portal_registration_states','bot_notification_owners',
]);
const layout = postgresBackupLayout().filter(
  (table) => !excluded.has(table.name),
);
const ephemeral = new Set(['sessions', 'invitations', 'challenges']);
export interface SqliteMigrationOptions {
  database: string;
  issuer: string;
  catalog: Catalog;
  /** The current SQLite signing key. Cutover does not rotate it. */
  privateKey: string;
  /** Explicit historical public roots for finalized distribution manifests. */
  historicalPublicKeys?: readonly string[];
}
export interface SqliteMigrationPlan {
  formatVersion: 1;
  sourceVersion: 6 | 7 | 8;
  sourceDigest: string;
  planHash: string;
  currentKid: string;
  tables: { name: string; rows: number; importedRows: number }[];
  rows: number;
  clearedAuthenticationRows: number;
  pausedTasks: number;
  heldNotifications: number;
}
function fixed(input: SqliteMigrationOptions) {
  const database = realpathSync(resolve(input.database));
  requireThat(statSync(database).isFile(), 'SQLITE_MIGRATION_SOURCE_REQUIRED');
  const issuer = z.string().trim().min(1).max(256).parse(input.issuer);
  const catalog = parseCatalog(structuredClone(input.catalog));
  const signer = new EnvelopeSigner(input.privateKey);
  const publicKeys = [
    signer.publicKey,
    ...(input.historicalPublicKeys ?? []),
  ].map((pem) => normalizePublicKey(pem).pem);
  requireThat(
    publicKeys.length <= 32 && new Set(publicKeys).size === publicKeys.length,
    'SQLITE_MIGRATION_TRUST_INVALID',
  );
  return {
    database,
    issuer,
    catalog,
    privateKey: input.privateKey,
    signer,
    publicKeys: publicKeys.sort(),
  };
}
function definitions(db: DatabaseSync, version: number) {
  return db
    .prepare(
      "SELECT type,name,tbl_name,sql FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name",
    )
    .all()
    .filter(
      (row) =>
        (version >= 8 ||
          !['task_jobs', 'task_job_reviews'].includes(String(row.tbl_name))) &&
        (version >= 7 || row.tbl_name !== 'outbox_resources'),
    )
    .map((row) => ({
      type: String(row.type),
      name: String(row.name),
      tbl_name: String(row.tbl_name),
      sql: String(row.sql).replace(/\s+/g, ' ').trim(),
    }));
}
function capture(options: ReturnType<typeof fixed>) {
  const work = mkdtempSync(join(tmpdir(), 'plk-compat-'));
  privateDirectory(work);
  const image = join(work, 'source.sqlite');
  try {
    backupDatabase(options.database, image);
    requireThat(
      statSync(image).size <= backupMaxBytes - 65536,
      'BACKUP_TOO_LARGE',
    );
    const raw = readFileSync(image),
      source = new DatabaseSync(image, { readOnly: true });
    let version: 6 | 7 | 8;
    let data: { name: string; columns: string[]; rows: Row[] }[];
    try {
      requireThat(
        source.prepare('PRAGMA quick_check').get()?.quick_check === 'ok' &&
          source.prepare('PRAGMA foreign_key_check').all().length === 0,
        'SQLITE_MIGRATION_INTEGRITY_FAILED',
      );
      requireThat(
        same(
          source
            .prepare('SELECT version FROM schema_version')
            .all()
            .map((row) => row.version),
          [1],
        ),
        'SQLITE_MIGRATION_VERSION_UNSUPPORTED',
      );
      const versions = source
        .prepare('SELECT version FROM plk_migrations ORDER BY version')
        .all()
        .map((row) => row.version);
      requireThat(
        same(versions, [2, 3, 4, 5, 6]) ||
          same(versions, [2, 3, 4, 5, 6, 7]) ||
          same(versions, [2, 3, 4, 5, 6, 7, 8]),
        'SQLITE_MIGRATION_VERSION_UNSUPPORTED',
      );
      version = versions.at(-1) as 6 | 7 | 8;
      const referencePath = join(work, 'reference.sqlite'),
        referenceStore = new SqliteStore(referencePath);
      referenceStore.close();
      const reference = new DatabaseSync(referencePath, { readOnly: true });
      try {
        const actual = definitions(source, 8),
          expected = definitions(reference, version);
        // These known additive read indexes were introduced between v6 and v7 without changing domain data.
        // Missing indexes are allowed; present indexes must still exactly match the controlled definition.
        const optional = new Set([
          'orders_account_cursor',
          'audit_cursor',
          'distributions_account_cursor',
        ]);
        const expectedPresent = expected.filter(
          (row) =>
            !optional.has(String(row.name)) ||
            actual.some((item) => item.name === row.name),
        );
        requireThat(
          same(actual, expectedPresent),
          'SQLITE_MIGRATION_SCHEMA_UNSUPPORTED',
        );
      } finally {
        reference.close();
      }
      let size = 0,
        count = 0;
      data = layout.map((table) => {
        if (
          (version < 8 &&
            ['task_jobs', 'task_job_reviews'].includes(table.name)) ||
          (version < 7 && table.name === 'outbox_resources')
        )
          return { ...table, rows: [] };
        const info = source.prepare(`PRAGMA table_info(${table.name})`).all();
        requireThat(
          same(
            info.map((row) => String(row.name)).sort(),
            [...table.columns].sort(),
          ),
          'SQLITE_MIGRATION_COLUMNS_INVALID',
        );
        const primary = info
          .filter((row) => Number(row.pk) > 0)
          .sort((a, b) => Number(a.pk) - Number(b.pk))
          .map((row) => String(row.name));
        const rows: Row[] = [];
        // Iteration bounds memory before accepting each row; no source SQL or names come from user input.
        for (const original of source
          .prepare(
            `SELECT ${table.columns.join(',')} FROM ${table.name} ORDER BY ${primary.join(',')}`,
          )
          .iterate()) {
          const row = z.record(z.string(), scalar).parse(original);
          size += Buffer.byteLength(JSON.stringify(row));
          count++;
          requireThat(
            size <= backupMaxBytes - 65536 && count <= 250000,
            'BACKUP_TOO_LARGE',
          );
          rows.push(row);
        }
        return { ...table, rows };
      });
    } finally {
      source.close();
    }
    for (const table of data) {
      for (const row of table.rows) {
        if ('edition_id' in row)
          requireThat(
            options.catalog.editions.some(
              (edition) => edition.id === row.edition_id,
            ),
            'SQLITE_MIGRATION_CATALOG_MISMATCH',
          );
        if ('group_id' in row)
          requireThat(
            options.catalog.groups.some((group) => group.id === row.group_id),
            'SQLITE_MIGRATION_CATALOG_MISMATCH',
          );
        if (table.name !== 'distributions') continue;
        if (row.manifest === null) {
          requireThat(
            row.finalized_at === null && row.artifact_sha256 === null,
            'SQLITE_MIGRATION_MANIFEST_INVALID',
          );
          continue;
        }
        requireThat(
          typeof row.manifest === 'string' &&
            typeof row.finalized_at === 'number' &&
            row.finalized_at >= 0,
          'SQLITE_MIGRATION_MANIFEST_INVALID',
        );
        let claims: unknown;
        for (const pem of options.publicKeys) {
          try {
            claims = verifyEnvelope(row.manifest, pem, 'plk-distribution');
            break;
          } catch {
            /* Try only explicitly supplied trust roots. */
          }
        }
        const signed = z
          .object({
            distributionId: z.string(),
            editionId: z.string(),
            releaseId: z.string(),
            sha256: z.string().regex(/^[a-f0-9]{64}$/),
            issuedAt: z.number().int().safe().nonnegative(),
          })
          .strict()
          .safeParse(claims);
        // The old finalizer sampled its clock separately for the signature and database update.
        // Validate each timestamp, never rewrite either or assume millisecond equality.
        requireThat(
          signed.success &&
            signed.data.distributionId === row.id &&
            signed.data.editionId === row.edition_id &&
            signed.data.releaseId === row.release_id &&
            signed.data.sha256 === row.artifact_sha256,
          'SQLITE_MIGRATION_MANIFEST_INVALID',
        );
      }
    }
    const sourceDigest = sha256(JSON.stringify({ version, data }));
    const base = {
      formatVersion: 1 as const,
      sourceVersion: version,
      sourceDigest,
      currentKid: options.signer.kid,
      tables: data.map((table) => ({
        name: table.name,
        rows: table.rows.length,
        importedRows: ephemeral.has(table.name) ? 0 : table.rows.length,
      })),
      rows: data.reduce((sum, table) => sum + table.rows.length, 0),
      clearedAuthenticationRows: data
        .filter((table) => ephemeral.has(table.name))
        .reduce((sum, table) => sum + table.rows.length, 0),
      pausedTasks: data
        .find((table) => table.name === 'task_jobs')!
        .rows.filter((row) =>
          ['pending', 'leased', 'sending'].includes(String(row.state)),
        ).length,
      heldNotifications: data
        .find((table) => table.name === 'outbox')!
        .rows.filter((row) => row.delivered_at === null).length,
    };
    const planHash = sha256(
      JSON.stringify({
        base,
        issuer: options.issuer,
        catalog: options.catalog,
        publicKeys: options.publicKeys,
        migrations: postgresMigrations.map(({ version, checksum }) => ({
          version,
          checksum,
        })),
      }),
    );
    return {
      raw,
      data,
      plan: { ...base, planHash } satisfies SqliteMigrationPlan,
    };
  } finally {
    const exact = realpathSync(work),
      parent = realpathSync(tmpdir());
    requireThat(
      dirname(exact).toLowerCase() === parent.toLowerCase() &&
        exact
          .toLowerCase()
          .startsWith(join(parent, 'plk-compat-').toLowerCase()),
      'INVALID_MIGRATION_TEMPORARY_PATH',
    );
    rmSync(exact, { recursive: true });
  }
}
/** Read-only review, including committed WAL. Reports counts/digests only, never account data or keys. */
export function inspectSqliteMigration(
  input: SqliteMigrationOptions,
): SqliteMigrationPlan {
  const options = fixed(input);
  assertSqliteNotCutOver(options.database);
  return capture(options).plan;
}

/** Reconcile an interrupted cutover without changing either side or replaying any import. */
export async function reviewSqliteCutover(
  store: PostgresStore,
  input: SqliteMigrationOptions,
) {
  requireThat(store.maintenance, 'POSTGRES_MAINTENANCE_REQUIRED');
  const options = fixed(input);
  const marker = z
    .object({
      formatVersion: z.literal(1),
      id: z.string().uuid(),
      status: z.enum(['pending', 'completed']),
      planHash: z.string().regex(/^[a-f0-9]{64}$/),
      sourceDigest: z.string().regex(/^[a-f0-9]{64}$/),
      backupSha256: z.string().regex(/^[a-f0-9]{64}$/),
      targetSchema: z.string(),
    })
    .strict()
    .parse(
      JSON.parse(readFileSync(sqliteCutoverPath(options.database), 'utf8')),
    );
  const current = capture(options).plan;
  requireThat(
    marker.targetSchema === store.schema &&
      marker.sourceDigest === current.sourceDigest &&
      marker.planHash === current.planHash,
    'SQLITE_CUTOVER_CONTEXT_CHANGED',
  );
  return store.transaction(async (unit) => {
    const row = await unit.get<{
      source_digest: string;
      plan_hash: string;
      backup_sha256: string;
      status: string;
    }>('SELECT * FROM compatibility_imports WHERE id=$1', marker.id);
    requireThat(
      row &&
        row.source_digest === marker.sourceDigest &&
        row.plan_hash === marker.planHash &&
        row.backup_sha256 === marker.backupSha256,
      'SQLITE_CUTOVER_TARGET_MISMATCH',
    );
    if (row.status === 'completed') {
      const audit = await unit.get<{ details: string }>(
        "SELECT details FROM audit WHERE action='compatibility.sqlite-imported' AND target=$1",
        marker.id,
      );
      const details = audit
        ? (JSON.parse(audit.details) as Record<string, unknown>)
        : undefined;
      requireThat(
        details?.planHash === marker.planHash &&
          details.sourceDigest === marker.sourceDigest &&
          details.backupSha256 === marker.backupSha256,
        'SQLITE_CUTOVER_AUDIT_MISMATCH',
      );
    }
    return {
      id: marker.id,
      sourceStatus: marker.status,
      targetStatus: row.status,
      sourceDigest: marker.sourceDigest,
      planHash: marker.planHash,
      backupSha256: marker.backupSha256,
      committed: row.status === 'completed',
      sourceRemainsSealed: true,
    };
  });
}
export interface ApplySqliteMigrationOptions extends SqliteMigrationOptions {
  expectedPlanHash: string;
  actor: string;
  reason: string;
  backupDirectory: string;
  backupPassword: string;
}
/** Offline, one-shot cutover. On any ambiguous failure both sides stay sealed for operator review. */
export async function migrateSqliteToPostgres(
  store: PostgresStore,
  input: ApplySqliteMigrationOptions,
) {
  requireThat(store.maintenance, 'POSTGRES_MAINTENANCE_REQUIRED');
  const options = fixed(input),
    actor = z.string().trim().min(1).max(128).parse(input.actor),
    reason = z.string().trim().min(3).max(500).parse(input.reason);
  const expected = z
      .string()
      .regex(/^[a-f0-9]{64}$/)
      .parse(input.expectedPlanHash),
    password = input.backupPassword,
    destination = resolve(input.backupDirectory);
  assertSqliteNotCutOver(options.database);
  const release = acquireServiceLock(
    join(dirname(options.database), 'framework.lock'),
  );
  let source: DatabaseSync | undefined;
  try {
    assertSqliteNotCutOver(options.database);
    // Reserve the SQLite writer slot throughout all asynchronous target work. No source row is changed.
    source = new DatabaseSync(options.database);
    source.exec('PRAGMA busy_timeout=100; BEGIN IMMEDIATE');
    const captured = capture(options),
      plan = captured.plan;
    requireThat(
      plan.planHash === expected,
      'SQLITE_MIGRATION_PLAN_CHANGED',
      409,
    );
    await store.transaction(async (unit) => {
      await verifyPostgresBackupSchema(unit);
      for (const table of postgresBackupLayout())
        requireThat(
          !(await unit.get(`SELECT 1 FROM ${table.name} LIMIT 1`)),
          'SQLITE_MIGRATION_TARGET_NOT_EMPTY',
          409,
        );
    });
    const id = randomUUID(),
      bundle = encryptBackup(
        {
          'source.sqlite': captured.raw,
          'signing.pem': Buffer.from(options.privateKey),
          'migration-context.json': Buffer.from(
            JSON.stringify({
              issuer: options.issuer,
              catalog: options.catalog,
              publicKeys: options.publicKeys,
              plan,
            }),
          ),
        },
        password,
      );
    const backupPath = join(privateDirectory(destination), id + '.plkbackup');
    writeFileSync(backupPath, bundle, { flag: 'wx', mode: 0o600, flush: true });
    protectPrivatePath(backupPath);
    const persisted = readFileSync(backupPath),
      decoded = decryptBackup(persisted, password);
    requireThat(
      decoded['source.sqlite']!.equals(captured.raw) &&
        decoded['signing.pem']!.equals(Buffer.from(options.privateKey)) &&
        decoded['migration-context.json']!.equals(
          Buffer.from(
            JSON.stringify({
              issuer: options.issuer,
              catalog: options.catalog,
              publicKeys: options.publicKeys,
              plan,
            }),
          ),
        ),
      'SQLITE_MIGRATION_BACKUP_INVALID',
    );
    const backupSha256 = sha256(persisted),
      seal = {
        formatVersion: 1,
        id,
        status: 'pending',
        planHash: plan.planHash,
        sourceDigest: plan.sourceDigest,
        backupSha256,
        targetSchema: store.schema,
      };
    // Exclusive creation prevents overwriting an earlier cutover seal. A crash is deliberately fail-closed.
    const marker = sqliteCutoverPath(options.database);
    await store.run(
      "INSERT INTO compatibility_imports VALUES($1,$2,$3,'pending',$4,$5,$6,$7,NULL)",
      id,
      plan.sourceDigest,
      plan.planHash,
      backupSha256,
      actor,
      reason,
      Date.now(),
    );
    writeFileSync(marker, JSON.stringify(seal), {
      flag: 'wx',
      mode: 0o600,
      flush: true,
    });
    protectPrivatePath(marker);
    await store.transaction(async (unit) => {
      await verifyPostgresBackupSchema(unit);
      for (const table of postgresBackupLayout().filter(
        (table) => table.name !== 'compatibility_imports',
      ))
        requireThat(
          !(await unit.get(`SELECT 1 FROM ${table.name} LIMIT 1`)),
          'SQLITE_MIGRATION_TARGET_NOT_EMPTY',
          409,
        );
      const guard = await unit.get<{
        status: string;
        plan_hash: string;
        source_digest: string;
        backup_sha256: string;
      }>('SELECT * FROM compatibility_imports WHERE id=$1 FOR UPDATE', id);
      requireThat(
        guard?.status === 'pending' &&
          guard.plan_hash === plan.planHash &&
          guard.source_digest === plan.sourceDigest &&
          guard.backup_sha256 === backupSha256,
        'SQLITE_MIGRATION_STATE_CHANGED',
      );
      const now = (await unit.get<{ now: number }>(
        'SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AS now',
      ))!.now;
      for (const table of captured.data) {
        if (ephemeral.has(table.name)) continue;
        for (const original of table.rows) {
          const row = { ...original };
          if (
            table.name === 'task_jobs' &&
            ['pending', 'leased', 'sending'].includes(String(row.state))
          ) {
            row.state = 'uncertain';
            row.generation = Number(row.generation) + 1;
            row.lease_token = null;
            row.lease_until = null;
            row.last_error = 'SQLITE_MIGRATION_REVIEW_REQUIRED';
            row.updated_at = now;
            requireThat(
              Number.isSafeInteger(row.generation),
              'UNSAFE_DATABASE_INTEGER',
            );
          }
          await unit.run(
            `INSERT INTO ${table.name}(${table.columns.join(',')}) VALUES(${table.columns.map((_, i) => '$' + (i + 1)).join(',')})`,
            ...table.columns.map((name) => row[name]!),
          );
        }
      }
      // Historical SQLite outbox entries remain immutable records. No PostgreSQL task is created from them.
      await unit.run(
        'INSERT INTO audit VALUES($1,$2,$3,$4,$5,$6)',
        randomUUID(),
        actor,
        'compatibility.sqlite-imported',
        id,
        JSON.stringify({
          reason,
          planHash: plan.planHash,
          sourceDigest: plan.sourceDigest,
          backupSha256,
          rows: plan.rows,
          clearedAuthenticationRows: plan.clearedAuthenticationRows,
          pausedTasks: plan.pausedTasks,
          heldNotifications: plan.heldNotifications,
        }),
        now,
      );
      await unit.run(
        "UPDATE compatibility_imports SET status='completed',completed_at=$2 WHERE id=$1",
        id,
        now,
      );
    });
    writePrivateAtomic(
      marker,
      JSON.stringify({ ...seal, status: 'completed' }),
    );
    return {
      id,
      planHash: plan.planHash,
      sourceDigest: plan.sourceDigest,
      backupPath,
      backupSha256,
      rows: plan.rows - plan.clearedAuthenticationRows,
      pausedTasks: plan.pausedTasks,
      heldNotifications: plan.heldNotifications,
    };
  } finally {
    try {
      if (source) {
        try {
          source.exec('ROLLBACK');
        } finally {
          source.close();
        }
      }
    } finally {
      release();
    }
  }
}
