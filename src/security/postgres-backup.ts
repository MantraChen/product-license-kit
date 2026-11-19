import { randomUUID } from 'node:crypto';
import { readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { z } from 'zod';
import type { AsyncStore, SqlValue } from '../core/async-store.js';
import { StorageError } from '../core/async-store.js';
import { postgresMigrations } from '../adapters/postgres-schema.js';
import type {
  SigningRotationView,
  SigningBackupReceipt,
} from '../adapters/postgres-signing.js';
import { requireThat } from '../core/model.js';
import { EnvelopeSigner, sha256 } from '../core/crypto.js';
import { encryptBackup, decryptBackup, backupMaxBytes } from './backup.js';
import { privateDirectory, protectPrivatePath } from './private-storage.js';

const tables = postgresMigrations.flatMap((migration) =>
  [...migration.sql.matchAll(/CREATE TABLE ([a-z][a-z0-9_]*)\(/g)].map(
    (match) => match[1]!,
  ),
);
const migrations = postgresMigrations.map(({ version, checksum }) => ({
  version,
  checksum,
}));
// Controlled migration SQL only. Split column definitions outside CHECK/FK lists.
const expectedColumns = new Map(
  postgresMigrations.flatMap((migration) =>
    [
      ...migration.sql.matchAll(
        /CREATE TABLE ([a-z][a-z0-9_]*)\(([\s\S]*?)\);/g,
      ),
    ].map((match) => {
      const pieces: string[] = [];
      let start = 0,
        depth = 0,
        quoted = false;
      const body = match[2]!;
      for (let index = 0; index < body.length; index++) {
        const char = body[index];
        if (char === "'") {
          if (quoted && body[index + 1] === "'") {
            index++;
            continue;
          }
          quoted = !quoted;
        }
        if (quoted) continue;
        if (char === '(') depth++;
        else if (char === ')') depth--;
        else if (char === ',' && depth === 0) {
          pieces.push(body.slice(start, index));
          start = index + 1;
        }
      }
      pieces.push(body.slice(start));
      return [
        match[1]!,
        pieces.flatMap((piece) => {
          const column =
            /^\s*([a-z][a-z0-9_]*)\s+(TEXT|BIGINT|INTEGER|SMALLINT)\b/.exec(
              piece,
            );
          return column
            ? [{ column_name: column[1]!, data_type: column[2]!.toLowerCase() }]
            : [];
        }),
      ] as const;
    }),
  ),
);
const scalar = z.union([z.string(), z.number().int().safe(), z.null()]);
const stateSchema = z
  .object({
    formatVersion: z.literal(1),
    migrations: z.array(
      z.object({ version: z.number().int(), checksum: z.string() }).strict(),
    ),
    tables: z
      .array(
        z
          .object({
            name: z.string(),
            columns: z.array(z.string()).min(1).max(64),
            rows: z.array(z.record(z.string(), scalar)),
          })
          .strict(),
      )
      .length(tables.length),
  })
  .strict();
const same = (a: unknown, b: unknown) =>
  JSON.stringify(a) === JSON.stringify(b);
async function retry<T>(
  store: AsyncStore,
  work: (unit: AsyncStore) => Promise<T>,
) {
  requireThat(store.transactionUnit !== true, 'ROOT_STORE_REQUIRED');
  for (let attempt = 0; ; attempt++)
    try {
      return await store.transaction(work);
    } catch (error) {
      if (attempt >= 2 || !(error instanceof StorageError) || !error.retryable)
        throw error;
    }
}
async function columns(unit: AsyncStore, table: string) {
  const fields = await unit.all<{ column_name: string; data_type: string }>(
    'SELECT column_name,data_type FROM information_schema.columns WHERE table_schema=pg_catalog.current_schema() AND table_name=$1 ORDER BY ordinal_position',
    table,
  );
  requireThat(
    same(fields, expectedColumns.get(table)),
    'POSTGRES_BACKUP_SCHEMA_INVALID',
  );
  const names = fields.map((row) => row.column_name);
  requireThat(
    names.every((name) => /^[a-z][a-z0-9_]*$/.test(name)),
    'POSTGRES_BACKUP_SCHEMA_INVALID',
  );
  return names;
}
export async function verifyPostgresBackupSchema(unit: AsyncStore) {
  const applied = await unit.all<{ version: number; checksum: string }>(
    'SELECT version,checksum FROM plk_pg_migrations ORDER BY version',
  );
  requireThat(same(applied, migrations), 'POSTGRES_BACKUP_MIGRATIONS_MISMATCH');
  const names = (
    await unit.all<{ tablename: string }>(
      'SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=pg_catalog.current_schema()',
    )
  )
    .map((row) => row.tablename)
    .sort();
  requireThat(
    same(names, [...tables, 'plk_pg_migrations'].sort()),
    'POSTGRES_BACKUP_UNMANAGED_TABLES',
  );
  for (const table of tables) await columns(unit, table);
}
/** Controlled layout shared by the offline compatibility importer; callers receive fresh copies. */
export function postgresBackupLayout() {
  return tables.map((name) => ({
    name,
    columns: expectedColumns.get(name)!.map((column) => column.column_name),
  }));
}
function keys(pems: readonly string[]) {
  requireThat(pems.length <= 31, 'BACKUP_TOO_MANY_SIGNING_KEYS');
  const entries = pems.map((pem) => ({ signer: new EnvelopeSigner(pem), pem }));
  requireThat(
    new Set(entries.map((row) => row.signer.kid)).size === entries.length,
    'DUPLICATE_SIGNING_KEY',
  );
  return entries;
}
function validateKeys(
  state: z.infer<typeof stateSchema>,
  pems: readonly string[],
) {
  const keyring = keys(pems),
    policies = state.tables.find(
      (row) => row.name === 'signing_policies',
    )!.rows,
    plans = state.tables.find((row) => row.name === 'signing_rotations')!.rows;
  const publicKeys = state.tables.find(
    (row) => row.name === 'signing_keys',
  )!.rows;
  const needed = [
    ...policies.map((row) => ({
      namespace: row.namespace,
      kid: row.active_kid,
    })),
    ...plans
      .filter((row) => ['scheduled', 'running'].includes(String(row.status)))
      .map((row) => ({ namespace: row.namespace, kid: row.kid })),
  ];
  for (const item of needed) {
    const entry = keyring.find((row) => row.signer.kid === item.kid),
      registered = publicKeys.find(
        (row) => row.namespace === item.namespace && row.kid === item.kid,
      );
    requireThat(
      entry && registered?.public_key === entry.signer.publicKey,
      'POSTGRES_BACKUP_SIGNING_KEY_MISSING',
    );
  }
  return keyring;
}
export interface PostgresBackupOptions {
  password: string;
  privateKeys: readonly string[];
  directory: string;
  /** Every initialized browser namespace needs its independent MFA/session encryption key. */
  portalKeys?: readonly { namespace: string; key: Uint8Array }[];
}
function portalKeyName(namespace: string) {
  return 'portal-' + sha256(namespace).slice(0, 24) + '.key';
}
function validatePortalKeys(
  state: z.infer<typeof stateSchema>,
  input: readonly { namespace: string; key: Uint8Array }[],
) {
  const settings = state.tables.find(
    (table) => table.name === 'portal_settings',
  )!.rows;
  requireThat(
    input.length <= 30 &&
      new Set(input.map((item) => item.namespace)).size === input.length,
    'POSTGRES_BACKUP_PORTAL_KEY_INVALID',
  );
  requireThat(
    same(
      settings.map((row) => String(row.namespace)).sort(),
      input.map((row) => row.namespace).sort(),
    ),
    'POSTGRES_BACKUP_PORTAL_KEY_MISSING',
  );
  return settings.map((row) => {
    const namespace = z
        .string()
        .regex(/^[A-Za-z0-9._-]{1,80}$/)
        .parse(row.namespace),
      entry = input.find((item) => item.namespace === namespace);
    requireThat(
      entry?.key.byteLength === 32 && sha256(entry.key) === row.key_hash,
      'POSTGRES_BACKUP_PORTAL_KEY_INVALID',
    );
    return { namespace, key: Buffer.from(entry.key) };
  });
}

/** A bounded logical snapshot of this framework's exact schema, encrypted with the configured private key material. */
async function capturePostgresBackup(
  store: AsyncStore,
  options: PostgresBackupOptions,
  signal?: AbortSignal,
) {
  const privateKeys = [...options.privateKeys],
    portalKeys = (options.portalKeys ?? []).map((item) => ({
      namespace: item.namespace,
      key: Buffer.from(item.key),
    })),
    password = options.password,
    destination = options.directory;
  const state = await retry(store, async (unit) => {
    await verifyPostgresBackupSchema(unit);
    const captured: z.infer<typeof stateSchema> = {
      formatVersion: 1,
      migrations,
      tables: [],
    };
    let total = 0,
      count = 0;
    for (const table of tables) {
      const names = await columns(unit, table);
      requireThat(
        names.every((name) => /^[a-z][a-z0-9_]*$/.test(name)),
        'POSTGRES_BACKUP_SCHEMA_INVALID',
      );
      const rows: Record<string, SqlValue>[] = [];
      let cursor = '(0,0)';
      for (;;) {
        requireThat(!signal?.aborted, 'POSTGRES_BACKUP_ABORTED');
        const page = await unit.all<Record<string, SqlValue>>(
          `SELECT *,ctid::text AS __plk_cursor FROM ${table} WHERE ctid>$1::tid ORDER BY ctid LIMIT 128`,
          cursor,
        );
        for (const row of page) {
          cursor = String(row.__plk_cursor);
          delete row.__plk_cursor;
          const parsed = z.record(z.string(), scalar).parse(row);
          total += Buffer.byteLength(JSON.stringify(parsed));
          count++;
          requireThat(
            total <= backupMaxBytes - 65536 && count <= 250000,
            'BACKUP_TOO_LARGE',
          );
          rows.push(parsed);
        }
        if (page.length < 128) break;
      }
      captured.tables.push({
        name: table,
        columns: names,
        rows: rows as Record<string, string | number | null>[],
      });
    }
    return stateSchema.parse(captured);
  });
  const material = validateKeys(state, privateKeys),
    files: Record<string, Buffer> = {
      'postgres-state.json': Buffer.from(JSON.stringify(state)),
    };
  for (const entry of material)
    files[`signing-${entry.signer.kid}.pem`] = Buffer.from(entry.pem);
  const portalMaterial = validatePortalKeys(state, portalKeys);
  for (const item of portalMaterial)
    files[portalKeyName(item.namespace)] = item.key;
  requireThat(!signal?.aborted, 'POSTGRES_BACKUP_ABORTED');
  const bundle = encryptBackup(files, password),
    directory = privateDirectory(destination),
    reference = randomUUID(),
    path = join(directory, reference + '.plkbackup');
  writeFileSync(path, bundle, { flag: 'wx', mode: 0o600 });
  protectPrivatePath(path);
  const persisted = readFileSync(path),
    decoded = decryptBackup(persisted, password);
  requireThat(
    same(
      stateSchema.parse(
        JSON.parse(decoded['postgres-state.json']!.toString('utf8')),
      ),
      state,
    ) &&
      portalMaterial.every((item) =>
        decoded[portalKeyName(item.namespace)]?.equals(item.key),
      ) &&
      material.every((entry) =>
        decoded[`signing-${entry.signer.kid}.pem`]!.equals(
          Buffer.from(entry.pem),
        ),
      ),
    'POSTGRES_BACKUP_VERIFICATION_FAILED',
  );
  return { path, sha256: sha256(persisted), reference, state };
}

export async function backupPostgres(
  store: AsyncStore,
  options: PostgresBackupOptions,
  signal?: AbortSignal,
) {
  const { state, ...result } = await capturePostgresBackup(
    store,
    options,
    signal,
  );
  return {
    ...result,
    tables: state.tables.length,
    rows: state.tables.reduce((sum, table) => sum + table.rows.length, 0),
  };
}

/** Host adapter for the scheduled signing worker; the receipt refers to the encrypted archive, not plaintext or a filesystem path. */
export function postgresSigningBackup(
  store: AsyncStore,
  options: PostgresBackupOptions,
) {
  const fixed = {
    ...options,
    privateKeys: [...options.privateKeys],
    portalKeys: (options.portalKeys ?? []).map((item) => ({
      namespace: item.namespace,
      key: Buffer.from(item.key),
    })),
  };
  return async (
    plan: SigningRotationView,
    signal: AbortSignal,
  ): Promise<SigningBackupReceipt> => {
    const result = await capturePostgresBackup(store, fixed, signal),
      policy = result.state.tables
        .find((row) => row.name === 'signing_policies')!
        .rows.find((row) => row.namespace === plan.namespace);
    requireThat(
      policy?.active_kid === plan.previousKid &&
        policy.epoch === plan.epoch &&
        policy.context_hash === plan.contextHash,
      'POSTGRES_BACKUP_SIGNING_POLICY_CHANGED',
    );
    const now = (await store.get<{ now: number }>(
      'SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AS now',
    ))!.now;
    requireThat(!signal.aborted, 'POSTGRES_BACKUP_ABORTED');
    return {
      planId: plan.id,
      namespace: plan.namespace,
      previousKid: plan.previousKid,
      kid: plan.kid,
      epoch: plan.epoch,
      contextHash: plan.contextHash,
      sha256: result.sha256,
      reference: result.reference,
      verifiedAt: now,
    };
  };
}

export interface PostgresRestoreOptions {
  actor: string;
  reason: string;
  /** An explicit operator-approved active key/context for every policy in the archive. No implicit activation of an old key. */
  expectedPolicies: Record<string, { kid: string; contextHash: string }>;
}
/** Restore only into an initialized, empty framework schema. Source backup remains unchanged. Never starts services. */
export async function restorePostgres(
  store: AsyncStore,
  bundle: Uint8Array,
  password: string,
  input: PostgresRestoreOptions,
) {
  const options = z
    .object({
      actor: z.string().trim().min(1).max(128),
      reason: z.string().trim().min(3).max(500),
      expectedPolicies: z.record(
        z.string(),
        z
          .object({
            kid: z.string().regex(/^[a-f0-9]{24}$/),
            contextHash: z.string().regex(/^[a-f0-9]{64}$/),
          })
          .strict(),
      ),
    })
    .strict()
    .parse(input);
  const files = decryptBackup(bundle, password);
  const backupSha256 = sha256(bundle);
  requireThat(files['postgres-state.json'], 'INVALID_POSTGRES_BACKUP');
  const state = stateSchema.parse(
    JSON.parse(files['postgres-state.json'].toString('utf8')),
  );
  requireThat(
    same(state.migrations, migrations) &&
      same(
        state.tables.map((row) => row.name),
        tables,
      ),
    'POSTGRES_BACKUP_MIGRATIONS_MISMATCH',
  );
  const pems = Object.entries(files)
    .filter(([name]) => /^signing-[a-f0-9]{24}\.pem$/.test(name))
    .map(([name, value]) => {
      const signer = new EnvelopeSigner(value.toString('utf8'));
      requireThat(
        name === `signing-${signer.kid}.pem`,
        'INVALID_POSTGRES_BACKUP',
      );
      return value.toString('utf8');
    });
  validateKeys(state, pems);
  const portalMaterial = state.tables
    .find((table) => table.name === 'portal_settings')!
    .rows.map((row) => {
      const namespace = z
          .string()
          .regex(/^[A-Za-z0-9._-]{1,80}$/)
          .parse(row.namespace),
        key = files[portalKeyName(namespace)];
      requireThat(key, 'POSTGRES_BACKUP_PORTAL_KEY_MISSING');
      return { namespace, key };
    });
  validatePortalKeys(state, portalMaterial);
  requireThat(
    Object.keys(files).every(
      (name) =>
        name === 'postgres-state.json' ||
        /^signing-[a-f0-9]{24}\.pem$/.test(name) ||
        portalMaterial.some((item) => portalKeyName(item.namespace) === name),
    ),
    'INVALID_POSTGRES_BACKUP',
  );
  const policies = state.tables.find(
    (row) => row.name === 'signing_policies',
  )!.rows;
  requireThat(
    same(
      policies.map((row) => String(row.namespace)).sort(),
      Object.keys(options.expectedPolicies).sort(),
    ),
    'POSTGRES_RESTORE_POLICY_REVIEW_REQUIRED',
  );
  for (const row of policies) {
    const expected = options.expectedPolicies[String(row.namespace)];
    requireThat(
      expected &&
        expected.kid === row.active_kid &&
        expected.contextHash === row.context_hash,
      'POSTGRES_RESTORE_POLICY_REVIEW_REQUIRED',
    );
  }
  return retry(store, async (unit) => {
    await verifyPostgresBackupSchema(unit);
    for (const table of tables)
      requireThat(
        !(await unit.get(`SELECT 1 FROM ${table} LIMIT 1`)),
        'POSTGRES_RESTORE_TARGET_NOT_EMPTY',
        409,
      );
    const restoredAt = (await unit.get<{ now: number }>(
      'SELECT floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint AS now',
    ))!.now;
    let rows = 0,
      pausedTasks = 0,
      pausedPlans = 0;
    for (const table of state.tables) {
      const names = await columns(unit, table.name);
      requireThat(
        same(names, table.columns),
        'POSTGRES_BACKUP_COLUMNS_MISMATCH',
      );
      if (
        [
          'sessions',
          'invitations',
          'challenges',
          'signing_readiness',
          'portal_sessions',
          'portal_oauth_states',
          'portal_reset_intents',
          'portal_registration_states',
          'bot_actions',
        ].includes(table.name)
      )
        continue;
      for (const original of table.rows) {
        requireThat(
          same(Object.keys(original).sort(), [...names].sort()),
          'POSTGRES_BACKUP_ROW_MISMATCH',
        );
        const row = { ...original };
        if (table.name === 'bot_settings') { row.paused = 1; row.epoch = Number(row.epoch) + 1; }
        if (table.name === 'bot_handoffs') row.revoked_at = restoredAt;
        if (
          table.name === 'task_jobs' &&
          ['pending', 'leased', 'sending'].includes(String(row.state))
        ) {
          row.state = 'uncertain';
          row.lease_token = null;
          row.lease_until = null;
          row.generation = Number(row.generation) + 1;
          row.last_error = 'RESTORE_REVIEW_REQUIRED';
          row.updated_at = restoredAt;
          pausedTasks++;
        }
        if (
          table.name === 'signing_rotations' &&
          ['scheduled', 'running'].includes(String(row.status))
        ) {
          row.status = 'paused';
          row.owner_token = null;
          row.lease_until = null;
          row.revision = Number(row.revision) + 1;
          row.last_error = 'SIGNING_RESTORE_REVIEW_REQUIRED';
          row.updated_at = restoredAt;
          pausedPlans++;
        }
        if (table.name === 'rate_limit_buckets')
          row.current = row.max_requests!;
        for (const value of Object.values(row))
          requireThat(
            typeof value !== 'number' || Number.isSafeInteger(value),
            'UNSAFE_DATABASE_INTEGER',
          );
        await unit.run(
          `INSERT INTO ${table.name}(${names.join(',')}) VALUES(${names.map((_, index) => '$' + (index + 1)).join(',')})`,
          ...names.map((name) => row[name]!),
        );
        rows++;
      }
    }
    await unit.run(
      'INSERT INTO audit VALUES($1,$2,$3,$4,$5,floor(extract(epoch FROM pg_catalog.clock_timestamp())*1000)::bigint)',
      randomUUID(),
      options.actor,
      'backup.restored',
      'postgres',
      JSON.stringify({
        reason: options.reason,
        backupSha256,
        rows,
        pausedTasks,
        pausedPlans,
        ephemeralAuthenticationCleared: true,
      }),
    );
    return {
      tables: tables.length,
      backupSha256,
      rows,
      pausedTasks,
      pausedPlans,
      ephemeralAuthenticationCleared: true,
    };
  });
}
