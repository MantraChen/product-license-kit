import pg, {
  type PoolClient,
  type QueryConfig,
  type QueryResult,
  type QueryResultRow,
} from 'pg';
import { AsyncLocalStorage } from 'node:async_hooks';
import { checkServerIdentity } from 'node:tls';
import {
  type AsyncStore,
  type SqlValue,
  StorageError,
} from '../core/async-store.js';
import { postgresMigrations } from './postgres-schema.js';

export interface PostgresOptions {
  connectionString: string;
  schema?: string;
  /** Custom trusted CA; certificate and hostname validation always remain enabled. */
  ca?: string;
  maxConnections?: number;
  connectionTimeoutMs?: number;
  statementTimeoutMs?: number;
  transactionTimeoutMs?: number;
  migrate?: boolean;
  /** Offline maintenance only. Holds an exclusive schema lease; normal clients hold shared leases. */
  maintenance?: boolean;
}
function check(condition: unknown, code: string): asserts condition {
  if (!condition) throw new StorageError(code);
}
function bounded(
  value: number | undefined,
  fallback: number,
  min: number,
  max: number,
) {
  const result = value ?? fallback;
  check(
    Number.isSafeInteger(result) && result >= min && result <= max,
    'INVALID_POSTGRES_OPTIONS',
  );
  return result;
}
function sanitize(error: unknown, committing = false): StorageError {
  if (error instanceof StorageError) return error;
  const code = error instanceof pg.DatabaseError ? error.code : undefined;
  const transport =
    error instanceof Error && 'code' in error ? error.code : undefined;
  if (
    !committing &&
    typeof transport === 'string' &&
    (transport.startsWith('ERR_TLS_') ||
      [
        'DEPTH_ZERO_SELF_SIGNED_CERT',
        'SELF_SIGNED_CERT_IN_CHAIN',
        'UNABLE_TO_VERIFY_LEAF_SIGNATURE',
        'UNABLE_TO_GET_ISSUER_CERT_LOCALLY',
        'CERT_HAS_EXPIRED',
        'CERT_NOT_YET_VALID',
        'CERT_SIGNATURE_FAILURE',
        'INVALID_CA',
      ].includes(transport))
  )
    return new StorageError('POSTGRES_TLS_FAILED');
  if (code === '40001' || code === '40P01')
    return new StorageError('TRANSACTION_RETRY_REQUIRED', code);
  if (committing && (!code || code.startsWith('08')))
    return new StorageError('TRANSACTION_COMMIT_UNCERTAIN', code);
  return new StorageError(
    code ? 'POSTGRES_QUERY_FAILED' : 'POSTGRES_CONNECTION_FAILED',
    code,
  );
}
function safeInteger(text: string) {
  const value = Number(text);
  check(
    Number.isSafeInteger(value) && BigInt(value) === BigInt(text),
    'UNSAFE_DATABASE_INTEGER',
  );
  return value;
}
function validateQuery(sql: string, values: SqlValue[]) {
  check(
    sql.length > 0 &&
      sql.length <= 65536 &&
      /^\s*(SELECT|INSERT|UPDATE|DELETE|WITH)\b/i.test(sql),
    'INVALID_POSTGRES_QUERY',
  );
  return values.map((value) => {
    if (typeof value === 'number')
      check(Number.isSafeInteger(value), 'INVALID_DATABASE_NUMBER');
    if (typeof value === 'bigint') {
      check(
        value >= -9007199254740991n && value <= 9007199254740991n,
        'INVALID_DATABASE_NUMBER',
      );
      return value.toString();
    }
    return value instanceof Uint8Array ? Buffer.from(value) : value;
  });
}
function handled<T>(promise: Promise<T>): Promise<T> {
  void promise.catch(() => {});
  return promise;
}
class CallbackError {
  constructor(readonly value: unknown) {}
}

interface TransactionRoot {
  client: PoolClient;
  current: PostgresUnit;
  closed: boolean;
  counter: number;
  phase: 'work' | 'commit';
}
/** Scoped unit of work: nested savepoints cannot overlap or escape their callback. */
class PostgresUnit implements AsyncStore {
  readonly transactionUnit = true as const;
  readonly pending = new Set<Promise<unknown>>();
  readonly children = new Set<Promise<unknown>>();
  failure: StorageError | undefined;
  active = true;
  constructor(
    readonly root: TransactionRoot,
    readonly depth = 0,
  ) {}
  private available() {
    check(this.active && !this.root.closed, 'TRANSACTION_SCOPE_CLOSED');
    check(this.root.current === this, 'TRANSACTION_SCOPE_BUSY');
  }
  private query<T>(
    sql: string,
    values: SqlValue[],
    result: (value: QueryResult) => T,
  ): Promise<T> {
    let task: Promise<T>;
    try {
      this.available();
      const config: QueryConfig & { queryMode: string } = {
        text: sql,
        values: validateQuery(sql, values),
        queryMode: 'extended',
      };
      task = this.root.client.query(config).then(result);
    } catch (error) {
      task = Promise.reject(error);
    }
    const tracked = task.catch((error) => {
      const safe = sanitize(error);
      this.failure ??= safe;
      throw safe;
    });
    this.pending.add(tracked);
    void tracked.then(
      () => this.pending.delete(tracked),
      () => this.pending.delete(tracked),
    );
    return handled(tracked);
  }
  get<T>(sql: string, ...values: SqlValue[]) {
    return this.query(sql, values, (result) => result.rows[0] as T | undefined);
  }
  all<T>(sql: string, ...values: SqlValue[]) {
    return this.query(sql, values, (result) => result.rows as T[]);
  }
  run(sql: string, ...values: SqlValue[]) {
    return this.query(sql, values, (result) => ({
      changes: result.rowCount ?? 0,
    }));
  }
  settled() {
    this.available();
    check(
      this.pending.size === 0 && this.children.size === 0,
      'UNAWAITED_TRANSACTION_WORK',
    );
    if (this.failure) throw this.failure;
  }
  transaction<T>(work: (unit: AsyncStore) => T | Promise<T>): Promise<T> {
    let task: Promise<T>;
    try {
      this.available();
      check(this.depth < 16, 'TRANSACTION_NESTING_LIMIT');
      const child = new PostgresUnit(this.root, this.depth + 1),
        name = `plk_${++this.root.counter}`;
      this.root.current = child;
      task = (async () => {
        try {
          await this.root.client.query(`SAVEPOINT ${name}`);
          const result = await work(child);
          child.settled();
          await this.root.client.query(`RELEASE SAVEPOINT ${name}`);
          return result;
        } catch (error) {
          if (
            !this.root.closed &&
            child.pending.size === 0 &&
            child.children.size === 0
          ) {
            try {
              await this.root.client.query(`ROLLBACK TO SAVEPOINT ${name}`);
              await this.root.client.query(`RELEASE SAVEPOINT ${name}`);
            } catch {
              this.failure ??= new StorageError('TRANSACTION_ABORTED');
            }
          } else
            this.failure ??= new StorageError('UNAWAITED_TRANSACTION_WORK');
          throw error;
        } finally {
          child.active = false;
          if (!this.root.closed) this.root.current = this;
        }
      })();
    } catch (error) {
      task = Promise.reject(error);
    }
    this.children.add(task);
    void task.then(
      () => this.children.delete(task),
      () => this.children.delete(task),
    );
    return handled(task);
  }
}

export class PostgresStore implements AsyncStore {
  readonly schema: string;
  readonly serverVersion: string;
  readonly maintenance: boolean;
  private readonly leasedClients = new WeakSet<PoolClient>();
  private maintenanceLeaseAcquired = false;
  private initialized = false;
  private readonly pool: pg.Pool;
  private readonly transactionTimeout: number;
  private closing: Promise<void> | undefined;
  private isClosed = false;
  private connectionErrors = 0;
  private lastConnectionError: string | null = null;
  private readonly transactions = new Set<TransactionRoot>();
  // Detect accidentally using the pool-level facade from a transaction callback, even in an async continuation.
  private readonly context = new AsyncLocalStorage<boolean>();
  private constructor(
    pool: pg.Pool,
    schema: string,
    timeout: number,
    version: string,
    maintenance: boolean,
  ) {
    this.pool = pool;
    this.schema = schema;
    this.transactionTimeout = timeout;
    this.serverVersion = version;
    this.maintenance = maintenance;
    pool.on('connect', (client) => {
      // Also cover bootstrap/migration clients: pg emits a client error in addition to rejecting queries.
      client.on('error', (error) => {
        this.connectionErrors++;
        this.lastConnectionError = sanitize(error).code;
      });
    });
    // Idle clients additionally forward the already-counted error through the pool emitter.
    pool.on('error', () => {});
  }
  static async connect(options: PostgresOptions) {
    let url: URL;
    try {
      url = new URL(options.connectionString);
    } catch {
      throw new StorageError('INVALID_DATABASE_URL');
    }
    check(
      ['postgres:', 'postgresql:'].includes(url.protocol) &&
        !url.search &&
        !url.hash &&
        url.username &&
        url.password &&
        /^\/[A-Za-z_][A-Za-z0-9_-]{0,62}$/.test(url.pathname),
      'INVALID_DATABASE_URL',
    );
    const schema = options.schema ?? 'plk';
    check(
      options.maintenance === undefined ||
        typeof options.maintenance === 'boolean',
      'INVALID_POSTGRES_OPTIONS',
    );
    check(
      !options.maintenance ||
        options.maxConnections === undefined ||
        options.maxConnections === 1,
      'INVALID_POSTGRES_OPTIONS',
    );
    check(
      /^[a-z][a-z0-9_]{0,62}$/.test(schema) &&
        !schema.startsWith('pg_') &&
        !['public', 'information_schema'].includes(schema),
      'INVALID_DATABASE_SCHEMA',
    );
    const local = ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname);
    const host = url.hostname.replace(/^\[|\]$/g, ''),
      port = url.port ? Number(url.port) : 5432;
    check(port >= 1 && port <= 65535, 'INVALID_DATABASE_URL');
    check(
      options.ca === undefined ||
        (typeof options.ca === 'string' &&
          options.ca.trim().length > 0 &&
          options.ca.length <= 1048576),
      'INVALID_POSTGRES_OPTIONS',
    );
    let user: string, password: string;
    try {
      user = decodeURIComponent(url.username);
      password = decodeURIComponent(url.password);
    } catch {
      throw new StorageError('INVALID_DATABASE_URL');
    }
    check(
      !user.includes('\0') && !password.includes('\0'),
      'INVALID_DATABASE_URL',
    );
    const parser = ((oid: number, format: 'text' | 'binary' = 'text') =>
      oid === 20 && format === 'text'
        ? safeInteger
        : pg.types.getTypeParser(oid, format)) as typeof pg.types.getTypeParser;
    const statementTimeout = bounded(
      options.statementTimeoutMs,
      10000,
      100,
      60000,
    );
    const pool = new pg.Pool({
      host,
      port,
      user,
      password,
      database: url.pathname.slice(1),
      ssl:
        local && options.ca === undefined
          ? false
          : {
              rejectUnauthorized: true,
              checkServerIdentity: (_hostname, certificate) =>
                checkServerIdentity(host, certificate),
              ...(options.ca ? { ca: options.ca } : {}),
            },
      enableChannelBinding: true,
      max: options.maintenance ? 1 : bounded(options.maxConnections, 10, 1, 64),
      connectionTimeoutMillis: bounded(
        options.connectionTimeoutMs,
        10000,
        100,
        60000,
      ),
      statement_timeout: statementTimeout,
      query_timeout: statementTimeout + 1000,
      idle_in_transaction_session_timeout: 15000,
      idleTimeoutMillis: options.maintenance ? 0 : 30000,
      allowExitOnIdle: true,
      application_name: 'product-license-kit',
      types: { getTypeParser: parser },
    });
    // Install the idle listener before making any connection.
    const store = new PostgresStore(
      pool,
      schema,
      bounded(options.transactionTimeoutMs, 30000, 100, 120000),
      'pending',
      options.maintenance === true,
    );
    try {
      const client = await store.borrow();
      let version: string;
      try {
        const result = await client.query<{ version: string; number: number }>(
          "SELECT pg_catalog.current_setting('server_version') AS version,pg_catalog.current_setting('server_version_num')::int AS number",
        );
        check(
          result.rows[0] && result.rows[0].number >= 150000,
          'POSTGRES_VERSION_UNSUPPORTED',
        );
        version = result.rows[0]!.version;
      } finally {
        client.release();
      }
      Object.defineProperty(store, 'serverVersion', {
        value: version,
        enumerable: true,
      });
      if (options.migrate === false) await store.verifySchema();
      else await store.migrate();
      store.initialized = true;
      if (!store.maintenance)
        check(
          !(await store.get(
            "SELECT 1 FROM compatibility_imports WHERE status='pending' LIMIT 1",
          )),
          'POSTGRES_IMPORT_REVIEW_REQUIRED',
        );
      return store;
    } catch (error) {
      await store.close();
      throw sanitize(error);
    }
  }
  private async borrow() {
    check(!this.isClosed, 'STORE_CLOSED');
    let client: PoolClient | undefined;
    try {
      client = await this.pool.connect();
      if (!this.leasedClients.has(client)) {
        check(
          !this.maintenance || !this.maintenanceLeaseAcquired,
          'POSTGRES_MAINTENANCE_LOST',
        );
        const fn = this.maintenance
          ? 'pg_try_advisory_lock'
          : 'pg_try_advisory_lock_shared';
        const result = await client.query<{ acquired: boolean }>(
          `SELECT pg_catalog.${fn}(pg_catalog.hashtextextended($1,0)) AS acquired`,
          [`product-license-kit:maintenance:${this.schema}`],
        );
        check(result.rows[0]?.acquired, 'POSTGRES_MAINTENANCE_BUSY');
        if (this.maintenance) this.maintenanceLeaseAcquired = true;
        if (!this.maintenance && this.initialized) {
          await client.query(this.searchPath());
          const pending = await client.query(
            "SELECT 1 FROM compatibility_imports WHERE status='pending' LIMIT 1",
          );
          check(pending.rows.length === 0, 'POSTGRES_IMPORT_REVIEW_REQUIRED');
        }
        this.leasedClients.add(client);
      }
      return client;
    } catch (error) {
      client?.release(true);
      throw sanitize(error);
    }
  }
  // pg_catalog remains implicitly first for lookup, while CREATE targets only the owned schema.
  private searchPath(local = false) {
    return `SET ${local ? 'LOCAL ' : ''}search_path TO "${this.schema}"`;
  }
  private verifyRows(rows: { version: number; checksum: string }[]) {
    check(
      rows.every((row, index) => row.version === index + 1),
      'DATABASE_SCHEMA_DIVERGED',
    );
    check(rows.length <= postgresMigrations.length, 'DATABASE_SCHEMA_TOO_NEW');
    for (const row of rows)
      check(
        row.checksum === postgresMigrations[row.version - 1]!.checksum,
        'DATABASE_SCHEMA_DIVERGED',
      );
  }
  private async verifySchema() {
    const client = await this.borrow();
    try {
      await client.query(this.searchPath());
      const result = await client.query<{ version: number; checksum: string }>(
        'SELECT version,checksum FROM plk_pg_migrations ORDER BY version',
      );
      this.verifyRows(result.rows);
      check(
        result.rows.length === postgresMigrations.length,
        'DATABASE_SCHEMA_MISSING',
      );
    } catch (error) {
      throw sanitize(error);
    } finally {
      client.release();
    }
  }
  private async migrate() {
    const client = await this.borrow();
    let destroy = false;
    try {
      await client.query('BEGIN');
      await client.query(
        'SELECT pg_catalog.pg_advisory_xact_lock(pg_catalog.hashtextextended($1,0))',
        [`product-license-kit:schema:${this.schema}`],
      );
      await client.query(`CREATE SCHEMA IF NOT EXISTS "${this.schema}"`);
      await client.query(this.searchPath(true));
      const tables = await client.query<{ tablename: string }>(
        'SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=$1',
        [this.schema],
      );
      const hasHistory = tables.rows.some(
        (row) => row.tablename === 'plk_pg_migrations',
      );
      check(
        hasHistory || tables.rows.length === 0,
        'UNMANAGED_DATABASE_SCHEMA',
      );
      await client.query(
        'CREATE TABLE IF NOT EXISTS plk_pg_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at BIGINT NOT NULL)',
      );
      const applied = await client.query<{ version: number; checksum: string }>(
        'SELECT version,checksum FROM plk_pg_migrations ORDER BY version',
      );
      this.verifyRows(applied.rows);
      check(
        applied.rows.length > 0 ||
          tables.rows.every((row) => row.tablename === 'plk_pg_migrations'),
        'UNMANAGED_DATABASE_SCHEMA',
      );
      for (const migration of postgresMigrations.slice(applied.rows.length)) {
        await client.query(migration.sql);
        await client.query('INSERT INTO plk_pg_migrations VALUES($1,$2,$3)', [
          migration.version,
          migration.checksum,
          Date.now(),
        ]);
      }
      await client.query('COMMIT');
    } catch (error) {
      try {
        await client.query('ROLLBACK');
      } catch {
        destroy = true;
      }
      throw sanitize(error);
    } finally {
      client.release(destroy);
    }
  }
  private async query<T extends QueryResultRow>(
    sql: string,
    values: SqlValue[],
  ): Promise<QueryResult<T>> {
    check(!this.context.getStore(), 'TRANSACTION_UNIT_REQUIRED');
    const params = validateQuery(sql, values),
      client = await this.borrow();
    let destroy = false,
      sent = false;
    const failed = () => {
      destroy = true;
    };
    client.on('error', failed);
    try {
      await client.query(this.searchPath());
      sent = true;
      return await client.query<T>({
        text: sql,
        values: params,
        queryMode: 'extended',
      } as QueryConfig);
    } catch (error) {
      if (!(error instanceof pg.DatabaseError)) destroy = true;
      if (
        sent &&
        !(error instanceof pg.DatabaseError) &&
        !(error instanceof StorageError)
      )
        throw new StorageError('POSTGRES_RESULT_UNCERTAIN');
      throw sanitize(error);
    } finally {
      client.release(destroy);
      client.off('error', failed);
    }
  }
  get<T>(sql: string, ...values: SqlValue[]): Promise<T | undefined> {
    return handled(
      this.query(sql, values).then((result) => result.rows[0] as T | undefined),
    );
  }
  all<T>(sql: string, ...values: SqlValue[]): Promise<T[]> {
    return handled(
      this.query(sql, values).then((result) => result.rows as T[]),
    );
  }
  run(sql: string, ...values: SqlValue[]) {
    return handled(
      this.query(sql, values).then((result) => ({
        changes: result.rowCount ?? 0,
      })),
    );
  }
  transaction<T>(work: (unit: AsyncStore) => T | Promise<T>): Promise<T> {
    return handled(this.perform(work));
  }
  private async perform<T>(work: (unit: AsyncStore) => T | Promise<T>) {
    check(!this.context.getStore(), 'TRANSACTION_UNIT_REQUIRED');
    const client = await this.borrow();
    const root: TransactionRoot = {
      client,
      current: null as unknown as PostgresUnit,
      closed: false,
      counter: 0,
      phase: 'work',
    };
    const unit = new PostgresUnit(root);
    root.current = unit;
    this.transactions.add(root);
    let rejectFailure!: (error: StorageError) => void;
    const failure = handled(
      new Promise<never>((_resolve, reject) => {
        rejectFailure = reject;
      }),
    );
    const disconnected = () =>
      rejectFailure(
        new StorageError(
          root.phase === 'commit'
            ? 'TRANSACTION_COMMIT_UNCERTAIN'
            : 'POSTGRES_CONNECTION_FAILED',
        ),
      );
    client.on('error', disconnected);
    const timer = setTimeout(
      () =>
        rejectFailure(
          new StorageError(
            root.phase === 'commit'
              ? 'TRANSACTION_COMMIT_UNCERTAIN'
              : 'TRANSACTION_TIMEOUT',
          ),
        ),
      this.transactionTimeout,
    );
    let destroy = false;
    try {
      await Promise.race([
        client.query('BEGIN ISOLATION LEVEL SERIALIZABLE'),
        failure,
      ]);
      await Promise.race([client.query(this.searchPath(true)), failure]);
      const result = await Promise.race([
        this.context.run(true, async () => {
          try {
            return await work(unit);
          } catch (error) {
            throw new CallbackError(error);
          }
        }),
        failure,
      ]);
      unit.settled();
      root.phase = 'commit';
      const committed = await Promise.race([client.query('COMMIT'), failure]);
      check(committed.command === 'COMMIT', 'TRANSACTION_ABORTED');
      return result;
    } catch (error) {
      const original = error instanceof CallbackError ? error.value : error;
      const safe =
        error instanceof CallbackError &&
        !(original instanceof pg.DatabaseError)
          ? original
          : sanitize(original, root.phase === 'commit');
      const code = safe instanceof StorageError ? safe.code : '';
      root.closed = true;
      destroy =
        (root.phase === 'commit' && code === 'TRANSACTION_COMMIT_UNCERTAIN') ||
        unit.pending.size > 0 ||
        unit.children.size > 0 ||
        root.current !== unit ||
        [
          'TRANSACTION_TIMEOUT',
          'POSTGRES_CONNECTION_FAILED',
          'UNAWAITED_TRANSACTION_WORK',
        ].includes(code);
      if (!destroy) {
        try {
          await client.query('ROLLBACK');
        } catch {
          destroy = true;
        }
      }
      throw safe;
    } finally {
      root.closed = true;
      unit.active = false;
      clearTimeout(timer);
      this.transactions.delete(root);
      client.release(destroy);
      client.off('error', disconnected);
    }
  }
  stats() {
    return {
      total: this.pool.totalCount,
      idle: this.pool.idleCount,
      waiting: this.pool.waitingCount,
      transactions: this.transactions.size,
      connectionErrors: this.connectionErrors,
      lastConnectionError: this.lastConnectionError,
    };
  }
  close() {
    if (!this.closing) {
      this.isClosed = true;
      this.closing = this.pool.end();
    }
    return this.closing;
  }
}
