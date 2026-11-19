import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import pg from 'pg';
import { PostgresStore, type PostgresOptions } from '../../src/adapters/postgres.js';
import { type AsyncStore, StorageError } from '../../src/core/async-store.js';
import { DomainError } from '../../src/core/model.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1', 'Use scripts/test-postgres.mjs; no default database is selected.');
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
function deferred<T = void>() { let resolve!: (value: T) => void; const promise = new Promise<T>(done => { resolve = done; }); return { promise, resolve }; }
async function fixture(t: TestContext, overrides: Partial<PostgresOptions> = {}, open = true) {
  const schema = `plk_test_${randomUUID().replaceAll('-', '')}`, stores: PostgresStore[] = [];
  assert.match(schema, /^plk_test_[a-f0-9]{32}$/);
  await admin.query(`CREATE SCHEMA "${schema}"`);
  const options = { connectionString: connection!, schema, ...overrides };
  t.after(async () => { await Promise.all(stores.map(store => store.close())); await admin.query(`DROP SCHEMA "${schema}" CASCADE`); });
  const connect = async (changes: Partial<PostgresOptions> = {}) => { const store = await PostgresStore.connect({ ...options, ...changes }); stores.push(store); return store; };
  const store = open ? await connect() : undefined;
  return { schema, connect, store: store!, raw: (sql: string, values?: unknown[]) => admin.query(sql.replaceAll('@schema', `"${schema}"`), values) };
}
async function account(store: AsyncStore, id = randomUUID()) {
  await store.run('INSERT INTO accounts VALUES($1,$2,$3,$4)', id, 'local', randomUUID(), Date.now()); return id;
}

test('PostgreSQL bootstraps one checksummed schema across concurrent processes and preserves records on reopen', async t => {
  const f = await fixture(t, {}, false);
  const worker = () => new Promise<{ pid: number; migrations: number }>((done, fail) => {
    const child = spawn(process.execPath, [fileURLToPath(new URL('./migrate-worker.js', import.meta.url))], {
      windowsHide: true, env: { ...process.env, PLK_POSTGRES_TEST_SCHEMA: f.schema }, stdio: ['ignore', 'pipe', 'pipe'],
    });
    let output = '';
    child.stdout.on('data', data => { output += data; }); child.stderr.resume();
    child.once('error', fail); child.once('close', code => {
      if (code !== 0) return fail(new Error('POSTGRES_MIGRATION_WORKER_FAILED'));
      try { done(JSON.parse(output)); } catch { fail(new Error('INVALID_MIGRATION_WORKER_RESULT')); }
    });
  });
  const workers = await Promise.all([worker(), worker()]);
  assert.equal(new Set(workers.map(row => row.pid)).size, 2);
  assert.ok(workers.every(row => row.pid !== process.pid && row.migrations === 6));
  const [a, b] = await Promise.all([f.connect(), f.connect()]);
  const id = await account(a);
  assert.equal((await b.get<{ id: string }>('SELECT id FROM accounts WHERE id=$1', id))?.id, id);
  assert.equal((await b.get<{ n: number }>('SELECT count(*) AS n FROM plk_pg_migrations'))?.n, 6);
  const names = await f.raw('SELECT tablename FROM pg_catalog.pg_tables WHERE schemaname=$1', [f.schema]);
  assert.equal(names.rows.length, 41);
  assert.equal((await f.connect({ migrate: false })).serverVersion, a.serverVersion);
  t.diagnostic(JSON.stringify({ serverVersion: a.serverVersion, tables: names.rows.length, migrations: 6 }));
});

test('parameters remain data and bigint values retain exact safe integers without changing driver-global parsers', async t => {
  const f = await fixture(t), marker = "person'); DROP TABLE accounts; --", id = randomUUID();
  await f.store.run('INSERT INTO accounts VALUES($1,$2,$3,$4)', id, 'local', marker, 9007199254740991n);
  assert.equal((await f.store.get<{ subject: string; created_at: number }>('SELECT * FROM accounts WHERE id=$1', id))?.created_at, 9007199254740991);
  assert.equal((await f.store.all<{ subject: string }>('SELECT subject FROM accounts'))[0]!.subject, marker);
  const binary = await f.store.get<{ value: Buffer }>('SELECT $1::bytea AS value', new Uint8Array([1, 2, 3]));
  assert.deepEqual(binary?.value, Buffer.from([1, 2, 3]));
  await assert.rejects(f.store.get('SELECT 9007199254740992::bigint'), { code: 'UNSAFE_DATABASE_INTEGER' });
  for (const value of [NaN, Infinity, 1.5, 9007199254740992, 9007199254740992n])
    await assert.rejects(f.store.get('SELECT $1::bigint', value), { code: 'INVALID_DATABASE_NUMBER' });
  assert.equal(pg.types.getTypeParser(20)('9007199254740991'), '9007199254740991');
});

test('an asynchronous transaction atomically commits account and outbox resources while timers keep running', async t => {
  const f = await fixture(t); let ticks = 0; const timer = setInterval(() => { ticks++; }, 5);
  try {
    const id = await f.store.transaction(async tx => {
      const id = await account(tx); await tx.get('SELECT pg_catalog.pg_sleep(0.05)');
      const event = randomUUID();
      await tx.run('INSERT INTO outbox(id,topic,account_id,created_at) VALUES($1,$2,$3,$4)', event, 'account.registered', id, Date.now());
      await tx.run('INSERT INTO outbox_resources VALUES($1,$2,$3)', event, 'account', id); return id;
    });
    assert.ok(ticks >= 2);
    assert.equal((await f.store.get<{ n: number }>('SELECT count(*) AS n FROM outbox_resources WHERE resource_id=$1', id))?.n, 1);
    assert.equal(f.store.stats().transactions, 0);
  } finally { clearInterval(timer); }
});

test('business errors preserve their identity and roll back all transaction writes', async t => {
  const f = await fixture(t), id = randomUUID(), expected = new DomainError('SYNTHETIC_BUSINESS_REJECTION', 409);
  await assert.rejects(f.store.transaction(async tx => { await account(tx, id); throw expected; }), error => error === expected);
  assert.equal(await f.store.get('SELECT id FROM accounts WHERE id=$1', id), undefined);
});

test('nested savepoints roll back independently and a caught SQL error still prevents a false commit', async t => {
  const f = await fixture(t), id = await account(f.store);
  await f.store.transaction(async tx => {
    await tx.run('INSERT INTO credits VALUES($1,$2,$3)', id, 'desktop', 1);
    await assert.rejects(tx.transaction(async child => {
      await child.run('UPDATE credits SET balance=balance+100 WHERE account_id=$1', id); throw new Error('synthetic nested rollback');
    }), /synthetic nested rollback/);
    await assert.rejects(tx.transaction(async child => {
      try { await child.run('INSERT INTO credits VALUES($1,$2,$3)', id, 'desktop', 10); } catch { /* Boundary must still roll back. */ }
    }), { code: 'POSTGRES_QUERY_FAILED', postgresCode: '23505' });
    await tx.run('UPDATE credits SET balance=balance+2 WHERE account_id=$1', id);
  });
  assert.equal((await f.store.get<{ balance: number }>('SELECT balance FROM credits WHERE account_id=$1', id))?.balance, 3);
  await assert.rejects(f.store.transaction(async tx => {
    await tx.run('UPDATE credits SET balance=4 WHERE account_id=$1', id);
    try { await tx.run('INSERT INTO credits VALUES($1,$2,$3)', id, 'desktop', 5); } catch { /* Cannot make COMMIT return success. */ }
  }), { code: 'POSTGRES_QUERY_FAILED' });
  assert.equal((await f.store.get<{ balance: number }>('SELECT balance FROM credits WHERE account_id=$1', id))?.balance, 3);
});

test('transaction units bind one backend, block pool-facade escapes, and expire after commit', async t => {
  const f = await fixture(t), other = await f.connect(); let expired!: AsyncStore;
  const id = await f.store.transaction(async tx => {
    expired = tx; const id = await account(tx);
    const pid = await tx.get<{ pid: number }>('SELECT pg_catalog.pg_backend_pid() AS pid');
    await tx.transaction(async child => assert.equal((await child.get<{ pid: number }>('SELECT pg_catalog.pg_backend_pid() AS pid'))?.pid, pid?.pid));
    await assert.rejects(f.store.get('SELECT id FROM accounts'), { code: 'TRANSACTION_UNIT_REQUIRED' });
    assert.equal(await other.get('SELECT id FROM accounts WHERE id=$1', id), undefined); return id;
  });
  await assert.rejects(expired.get('SELECT 1'), { code: 'TRANSACTION_SCOPE_CLOSED' });
  assert.ok(await other.get('SELECT id FROM accounts WHERE id=$1', id));
});

test('parallel savepoint branches cannot run parent statements inside a child scope', async t => {
  const f = await fixture(t), id = randomUUID(), childEntered = deferred(), continueChild = deferred();
  const result = f.store.transaction(async tx => {
    await account(tx, id);
    const child = tx.transaction(async nested => { childEntered.resolve(); await continueChild.promise; await nested.get('SELECT 1'); });
    await childEntered.promise;
    await assert.rejects(tx.get('SELECT 1'), { code: 'TRANSACTION_SCOPE_BUSY' });
    await assert.rejects(tx.transaction(() => 1), { code: 'TRANSACTION_SCOPE_BUSY' });
    continueChild.resolve(); await child;
  });
  await assert.rejects(result, { code: 'TRANSACTION_SCOPE_BUSY' });
  assert.equal(await f.store.get('SELECT id FROM accounts WHERE id=$1', id), undefined);
});

test('serializable competing workers spend a balance once and return explicit retry without rerunning callbacks', async t => {
  const f = await fixture(t), other = await f.connect(), id = await account(f.store), barrier = deferred();
  await f.store.run('INSERT INTO credits VALUES($1,$2,$3)', id, 'desktop', 1);
  let readers = 0, calls = 0;
  const spend = (store: PostgresStore) => store.transaction(async tx => {
    calls++; assert.equal((await tx.get<{ balance: number }>('SELECT balance FROM credits WHERE account_id=$1', id))?.balance, 1);
    if (++readers === 2) barrier.resolve(); await barrier.promise;
    await tx.run('UPDATE credits SET balance=balance-1 WHERE account_id=$1', id);
  });
  const results = await Promise.allSettled([spend(f.store), spend(other)]);
  assert.equal(results.filter(result => result.status === 'fulfilled').length, 1);
  const rejected = results.find(result => result.status === 'rejected') as PromiseRejectedResult;
  assert.equal(rejected.reason.code, 'TRANSACTION_RETRY_REQUIRED'); assert.equal(rejected.reason.retryable, true); assert.equal(calls, 2);
  assert.equal((await f.store.get<{ balance: number }>('SELECT balance FROM credits WHERE account_id=$1', id))?.balance, 0);
});

test('timeouts destroy the session and late continuations cannot reuse a returned transaction', async t => {
  const f = await fixture(t, { transactionTimeoutMs: 120 }), release = deferred(), late = deferred<string>(), id = randomUUID();
  await assert.rejects(f.store.transaction(async tx => {
    await account(tx, id); await release.promise;
    try { await tx.run('UPDATE accounts SET subject=$1 WHERE id=$2', 'late-mutation', id); late.resolve('unexpected'); }
    catch (error) { late.resolve((error as StorageError).code); }
  }), { code: 'TRANSACTION_TIMEOUT' });
  release.resolve(); assert.equal(await late.promise, 'TRANSACTION_SCOPE_CLOSED');
  assert.equal(await f.store.get('SELECT id FROM accounts WHERE id=$1', id), undefined);
  assert.equal(f.store.stats().transactions, 0);
});

test('unawaited SQL is never silently committed and multi-statement transaction control is rejected', async t => {
  const f = await fixture(t); let ignored!: Promise<unknown>;
  await assert.rejects(f.store.transaction(tx => { ignored = tx.get('SELECT pg_catalog.pg_sleep(0.3)'); return 'too early'; }), { code: 'UNAWAITED_TRANSACTION_WORK' });
  await assert.rejects(ignored);
  await assert.rejects(f.store.run('COMMIT'), { code: 'INVALID_POSTGRES_QUERY' });
  await assert.rejects(f.store.get('SELECT 1; COMMIT; SELECT 2'), { code: 'POSTGRES_QUERY_FAILED', postgresCode: '42601' });
  assert.equal((await f.store.get<{ ok: number }>('SELECT 1 AS ok'))?.ok, 1);
});

test('a lost COMMIT response is reported as uncertain and never blindly retried', async t => {
  const f = await fixture(t), id = randomUUID(); let armed = true, callbacks = 0;
  const original = pg.Client.prototype.query;
  const mock = t.mock.method(pg.Client.prototype, 'query', function(this: pg.Client, ...args: unknown[]) {
    const result = Reflect.apply(original, this, args) as Promise<pg.QueryResult>;
    if (armed && args[0] === 'COMMIT') return result.then(() => { armed = false; throw new Error('synthetic lost reply with private marker'); });
    return result;
  } as pg.Client['query']);
  try {
    await assert.rejects(f.store.transaction(async tx => { callbacks++; await account(tx, id); }), error => {
      assert.ok(error instanceof StorageError); assert.equal(error.code, 'TRANSACTION_COMMIT_UNCERTAIN');
      assert.equal(error.retryable, false); assert.ok(!error.message.includes('private marker')); return true;
    });
  } finally { mock.mock.restore(); }
  assert.equal(callbacks, 1); assert.ok(await f.store.get('SELECT id FROM accounts WHERE id=$1', id));
});

test('schema checksum drift, future versions and unmanaged schemas are refused without deleting records', async t => {
  const f = await fixture(t), id = await account(f.store);
  await f.raw("UPDATE @schema.plk_pg_migrations SET checksum=repeat('0',64)");
  await assert.rejects(f.connect(), { code: 'DATABASE_SCHEMA_DIVERGED' });
  assert.ok(await f.store.get('SELECT id FROM accounts WHERE id=$1', id));
  const newer = await fixture(t);
  await newer.raw("INSERT INTO @schema.plk_pg_migrations VALUES(7,repeat('a',64),1)");
  await assert.rejects(newer.connect(), { code: 'DATABASE_SCHEMA_TOO_NEW' });
  const unmanaged = await fixture(t, {}, false);
  await unmanaged.raw('CREATE TABLE @schema.foreign_data(value TEXT)'); await unmanaged.raw("INSERT INTO @schema.foreign_data VALUES('keep')");
  await assert.rejects(unmanaged.connect(), { code: 'UNMANAGED_DATABASE_SCHEMA' });
  assert.equal((await unmanaged.raw('SELECT value FROM @schema.foreign_data')).rows[0].value, 'keep');
});

test('statement cancellation rolls back cleanly, preserves safe error codes and returns the connection', async t => {
  const f = await fixture(t, { statementTimeoutMs: 100, transactionTimeoutMs: 2000 }), id = randomUUID();
  await assert.rejects(f.store.transaction(async tx => { await account(tx, id); await tx.get('SELECT pg_catalog.pg_sleep(0.4)'); }), { code: 'POSTGRES_QUERY_FAILED', postgresCode: '57014' });
  assert.equal(await f.store.get('SELECT id FROM accounts WHERE id=$1', id), undefined);
  assert.equal((await f.store.get<{ ok: number }>('SELECT 1 AS ok'))?.ok, 1);
  await f.store.close(); await f.store.close(); await assert.rejects(f.store.get('SELECT 1'), { code: 'STORE_CLOSED' });
});

test('configuration validation rejects insecure DSN overrides and invalid schemas before connecting', async () => {
  for (const connectionString of ['postgresql://user:private-password@remote.example/test?sslmode=disable', 'https://user:private-password@remote.example/test', 'postgresql://remote.example/test'])
    await assert.rejects(PostgresStore.connect({ connectionString }), error => error instanceof StorageError && !error.message.includes('private-password'));
  for (const schema of ['public', 'pg_catalog', 'pg_hostile', 'information_schema', 'a";DROP SCHEMA public'])
    await assert.rejects(PostgresStore.connect({ connectionString: connection!, schema }), { code: 'INVALID_DATABASE_SCHEMA' });
  await assert.rejects(PostgresStore.connect({ connectionString: connection!, maxConnections: 0 }), { code: 'INVALID_POSTGRES_OPTIONS' });
  await assert.rejects(PostgresStore.connect({ connectionString: connection!, ca: '' }), { code: 'INVALID_POSTGRES_OPTIONS' });
  const zeroPort = new URL(connection!); zeroPort.port = '0';
  await assert.rejects(PostgresStore.connect({ connectionString: zeroPort.href }), { code: 'INVALID_DATABASE_URL' });
});

test('TLS validates the explicit CA and IP/DNS identity without changing operating-system trust', async t => {
  const ca = readFileSync(process.env.PLK_TEST_POSTGRES_CA_FILE!, 'utf8');
  const f = await fixture(t, { ca });
  assert.equal((await f.store.get<{ ssl: boolean }>('SELECT ssl FROM pg_catalog.pg_stat_ssl WHERE pid=pg_catalog.pg_backend_pid()'))?.ssl, true);
  const wrongName = new URL(connection!); wrongName.hostname = 'localhost';
  await assert.rejects(f.connect({ connectionString: wrongName.href }), { code: 'POSTGRES_TLS_FAILED' });
});

test('runtime roles can verify an existing schema without migration privileges and cannot write without grants', async t => {
  const f = await fixture(t), id = await account(f.store), role = `plk_reader_${randomUUID().replaceAll('-', '')}`, password = randomUUID() + randomUUID();
  assert.match(role, /^plk_reader_[a-f0-9]{32}$/);
  await admin.query(`CREATE ROLE "${role}" LOGIN PASSWORD ${pg.escapeLiteral(password)}`);
  await f.raw(`GRANT USAGE ON SCHEMA @schema TO "${role}"`);
  await f.raw(`GRANT SELECT ON ALL TABLES IN SCHEMA @schema TO "${role}"`);
  const url = new URL(connection!); url.username = role; url.password = password;
  const reader = await f.connect({ connectionString: url.href, migrate: false });
  assert.ok(await reader.get('SELECT id FROM accounts WHERE id=$1', id));
  await assert.rejects(account(reader), { code: 'POSTGRES_QUERY_FAILED', postgresCode: '42501' });
  await reader.close();
  // Drop only this fixture's grants/role. It owns no application objects.
  await f.raw(`REVOKE ALL ON ALL TABLES IN SCHEMA @schema FROM "${role}"`);
  await f.raw(`REVOKE ALL ON SCHEMA @schema FROM "${role}"`);
  await admin.query(`DROP ROLE "${role}"`);
});

test('losing an active backend fails its transaction, expires the unit and permits a fresh connection', async t => {
  const f = await fixture(t), ready = deferred<number>(), release = deferred(), late = deferred<string>();
  const operation = f.store.transaction(async tx => {
    ready.resolve((await tx.get<{ pid: number }>('SELECT pg_catalog.pg_backend_pid() AS pid'))!.pid);
    await release.promise;
    try { await tx.get('SELECT 1'); late.resolve('unexpected'); } catch (error) { late.resolve((error as StorageError).code); }
  });
  const pid = await ready.promise;
  assert.equal(f.store.stats().transactions, 1);
  await admin.query('SELECT pg_catalog.pg_terminate_backend($1)', [pid]);
  await assert.rejects(operation, error => error instanceof StorageError && ['POSTGRES_CONNECTION_FAILED', 'POSTGRES_QUERY_FAILED'].includes(error.code));
  release.resolve(); assert.equal(await late.promise, 'TRANSACTION_SCOPE_CLOSED');
  assert.equal((await f.store.get<{ ok: number }>('SELECT 1 AS ok'))?.ok, 1);
});

test('idle backend errors are counted once and never turn into an unhandled process error', async t => {
  const f = await fixture(t);
  const pid = (await f.store.get<{ pid: number }>('SELECT pg_catalog.pg_backend_pid() AS pid'))!.pid;
  await admin.query('SELECT pg_catalog.pg_terminate_backend($1)', [pid]);
  const deadline = Date.now() + 2000;
  while (f.store.stats().connectionErrors === 0 && Date.now() < deadline) await new Promise(done => setTimeout(done, 10));
  assert.equal(f.store.stats().connectionErrors, 1);
  assert.equal(f.store.stats().transactions, 0);
  assert.equal((await f.store.get<{ ok: number }>('SELECT 1 AS ok'))?.ok, 1);
});

test('a lost autocommit statement response is also uncertain and its effects are not silently repeated', async t => {
  const f = await fixture(t), id = randomUUID(); let armed = true;
  const original = pg.Client.prototype.query;
  const mock = t.mock.method(pg.Client.prototype, 'query', function(this: pg.Client, ...args: unknown[]) {
    const result = Reflect.apply(original, this, args) as Promise<pg.QueryResult>;
    const query = args[0] as pg.QueryConfig | string;
    if (armed && typeof query === 'object' && query.text.startsWith('INSERT INTO accounts'))
      return result.then(() => { armed = false; throw new Error('synthetic response lost'); });
    return result;
  } as pg.Client['query']);
  try { await assert.rejects(account(f.store, id), { code: 'POSTGRES_RESULT_UNCERTAIN', retryable: false }); }
  finally { mock.mock.restore(); }
  assert.equal((await f.store.get<{ n: number }>('SELECT count(*) AS n FROM accounts WHERE id=$1', id))?.n, 1);
});
