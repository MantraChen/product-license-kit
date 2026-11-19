import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { createServer } from 'node:http';
import { setTimeout as delay } from 'node:timers/promises';
import pg from 'pg';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { PostgresRateLimiter } from '../../src/adapters/postgres-rate-limit.js';
import {
  PostgresTaskQueue,
  type TaskLease,
} from '../../src/adapters/postgres-tasks.js';
import {
  PostgresNotificationWorker,
  notificationQueueNamespace,
} from '../../src/adapters/postgres-notifications.js';
import { postgresMigrations } from '../../src/adapters/postgres-schema.js';
import { NotificationNotSentError } from '../../src/core/model.js';
import { StorageError, type AsyncStore } from '../../src/core/async-store.js';
import { EnvelopeSigner } from '../../src/core/crypto.js';
import { LocalIdentityProvider } from '../../src/adapters/local-identity.js';
import { AsyncFramework } from '../../src/async-service.js';
import { createApp } from '../../src/http/app.js';
import { catalog, key, keyPair } from '../helpers.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(
  connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1',
  'Use scripts/test-postgres.mjs.',
);
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
async function fixture(t: TestContext, legacy = false) {
  const schema = `plk_coord_${randomUUID().replaceAll('-', '')}`;
  if (legacy) {
    const client = await admin.connect();
    try {
      await client.query('BEGIN');
      await client.query(`CREATE SCHEMA "${schema}"`);
      await client.query(`SET LOCAL search_path TO "${schema}"`);
      await client.query(postgresMigrations[0].sql);
      await client.query(
        'CREATE TABLE plk_pg_migrations(version INTEGER PRIMARY KEY,checksum TEXT NOT NULL,applied_at BIGINT NOT NULL)',
      );
      await client.query('INSERT INTO plk_pg_migrations VALUES(1,$1,1)', [
        postgresMigrations[0].checksum,
      ]);
      const accountId = randomUUID();
      await client.query('INSERT INTO accounts VALUES($1,$2,$3,$4)', [
        accountId,
        'local',
        'legacy',
        1,
      ]);
      await client.query(
        'INSERT INTO outbox(id,topic,account_id,created_at,attempts) VALUES($1,$2,$3,$4,$5)',
        [randomUUID(), 'account.registered', accountId, 1, 3],
      );
      await client.query('COMMIT');
    } catch (error) {
      await client.query('ROLLBACK');
      throw error;
    } finally {
      client.release();
    }
  }
  const store = await PostgresStore.connect({
    connectionString: connection!,
    schema,
  });
  t.after(async () => {
    await store.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
  });
  const queue = new PostgresTaskQueue(store, {
    namespace: 'test',
    leaseMs: 200,
  });
  return { schema, store, queue };
}
async function business(store: AsyncStore) {
  const people = [{ subject: 'synthetic-person', proof: key() + key() }];
  const framework = await AsyncFramework.create({
    store,
    catalog: catalog(),
    signer: new EnvelopeSigner(keyPair().privateKey),
    providers: [new LocalIdentityProvider(people)],
    issuer: 'test',
  });
  const invitation = await framework.issueInvitation(
      'local',
      people[0]!.subject,
    ),
    session = await framework.register(invitation.ticket, people[0]!.proof);
  return { framework, people, session };
}
function worker(
  schema: string,
  mode: string,
  env: Record<string, string> = {},
) {
  return new Promise<Record<string, unknown>>((done, fail) => {
    const child = spawn(
      process.execPath,
      [
        fileURLToPath(new URL('./coordination-worker.js', import.meta.url)),
        mode,
      ],
      {
        windowsHide: true,
        env: { ...process.env, PLK_TEST_COORD_SCHEMA: schema, ...env },
        stdio: ['ignore', 'pipe', 'pipe'],
      },
    );
    let output = '';
    child.stdout.on('data', (data) => {
      output += data;
    });
    child.stderr.resume();
    child.once('error', fail);
    child.once('close', (code) => {
      if (code !== 0)
        return fail(new Error(`COORDINATION_WORKER_FAILED:${code}`));
      try {
        done(JSON.parse(output));
      } catch {
        fail(new Error('INVALID_COORDINATION_WORKER_RESULT'));
      }
    });
  });
}

test('migration two is additive, preserves old outbox and refuses to invent historical delivery tasks', async (t) => {
  const f = await fixture(t, true);
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM plk_pg_migrations',
      )
    )?.n,
    6,
  );
  assert.equal(
    (await f.store.get<{ attempts: number }>('SELECT attempts FROM outbox'))
      ?.attempts,
    3,
  );
  const reconnected = await PostgresStore.connect({
    connectionString: connection!,
    schema: f.schema,
  });
  try {
    assert.equal(
      (await reconnected.get<{ n: number }>('SELECT count(*) AS n FROM outbox'))
        ?.n,
      1,
    );
    assert.equal(
      (
        await reconnected.get<{ n: number }>(
          'SELECT count(*) AS n FROM task_jobs',
        )
      )?.n,
      0,
    );
  } finally {
    await reconnected.close();
  }
});

test('separate Node processes share one fixed-window budget and only store HMAC keys', async (t) => {
  const f = await fixture(t),
    secret = key() + key(),
    env = {
      PLK_TEST_RATE_SECRET: secret,
      PLK_TEST_COORD_START_AT: String(Date.now() + 700),
    };
  const results = await Promise.all([
    worker(f.schema, 'limit', env),
    worker(f.schema, 'limit', env),
  ]);
  assert.equal(new Set(results.map((row) => row.pid)).size, 2);
  assert.equal(
    results.reduce((n, row) => n + Number(row.allowed), 0),
    12,
  );
  const rows = await f.store.all<{ bucket_key: string; current: number }>(
    'SELECT * FROM rate_limit_buckets',
  );
  assert.equal(rows.length, 1);
  assert.match(rows[0]!.bucket_key, /^[a-f0-9]{64}$/);
  assert.equal(rows[0]!.current, 13);
  assert.equal(JSON.stringify(rows).includes('127.0.0.1'), false);
  assert.equal(JSON.stringify(rows).includes(secret), false);
});

test('rate windows use database time, reject inconsistent policy and support non-mutating reads and cleanup', async (t) => {
  const f = await fixture(t),
    limiter = new PostgresRateLimiter(f.store, {
      namespace: 'test',
      secret: key() + key(),
    });
  assert.equal((await limiter.read('subject', 100, 2)).current, 0);
  assert.equal((await limiter.increment('subject', 100, 2)).current, 1);
  const now = Date.now;
  try {
    Date.now = () => 1;
    assert.equal((await limiter.increment('subject', 100, 2)).current, 2);
  } finally {
    Date.now = now;
  }
  await assert.rejects(limiter.increment('subject', 100, 3), {
    code: 'RATE_LIMIT_POLICY_MISMATCH',
  });
  await assert.rejects(limiter.read('subject', 100, 3), {
    code: 'RATE_LIMIT_POLICY_MISMATCH',
  });
  assert.equal((await limiter.read('subject', 100, 2)).current, 2);
  await delay(120);
  assert.deepEqual(await limiter.read('subject', 100, 2), {
    current: 0,
    ttl: 0,
  });
  assert.equal((await limiter.increment('subject', 100, 2)).current, 1);
  await delay(120);
  assert.equal(await limiter.cleanup(), 1);
});

test('two Fastify instances share global and per-route auth limits, ignore spoofed forwarding and fail closed', async (t) => {
  const f = await fixture(t),
    h = await business(f.store),
    secret = key() + key(),
    adminToken = key() + key();
  const apps = await Promise.all(
    [0, 1].map(() =>
      createApp(h.framework, {
        adminToken,
        rateLimitMax: 3,
        sharedRateLimiter: new PostgresRateLimiter(f.store, {
          namespace: 'http',
          secret,
        }),
      }),
    ),
  );
  t.after(() => Promise.all(apps.map((app) => app.close())));
  const statuses = [];
  for (let n = 0; n < 5; n++)
    statuses.push(
      (
        await apps[n % 2]!.inject({
          url: '/v1/catalog',
          headers: { 'x-forwarded-for': `198.51.100.${n}` },
        })
      ).statusCode,
    );
  assert.deepEqual(statuses, [200, 200, 200, 429, 429]);
  assert.equal(
    (
      await apps[0]!.inject({
        url: '/v1/catalog',
        remoteAddress: '203.0.113.2',
      })
    ).statusCode,
    200,
  );
  const auth = [];
  for (let n = 0; n < 11; n++)
    auth.push(
      (
        await apps[n % 2]!.inject({
          method: 'POST',
          url: '/v1/auth/login',
          payload: { provider: 'local', proof: 'wrong-proof' },
        })
      ).statusCode,
    );
  assert.deepEqual(auth, [...Array(10).fill(401), 429]);
  const broken: AsyncStore = {
    ...f.store,
    get: async () => {
      throw new StorageError('POSTGRES_CONNECTION_FAILED');
    },
    all: f.store.all.bind(f.store),
    run: f.store.run.bind(f.store),
    transaction: f.store.transaction.bind(f.store),
  };
  const unavailable = await createApp(h.framework, {
    adminToken,
    sharedRateLimiter: new PostgresRateLimiter(broken, {
      namespace: 'http',
      secret,
    }),
  });
  t.after(() => unavailable.close());
  const response = await unavailable.inject({ url: '/v1/catalog' });
  assert.equal(response.statusCode, 503);
  assert.equal(response.json().error, 'STORAGE_UNAVAILABLE');
});

test('task enqueue is idempotent, conflicts do not overwrite payloads and host rollback removes both effects', async (t) => {
  const f = await fixture(t),
    input = { key: 'operation', payload: { artifact: 'ref-1' } };
  const first = await f.queue.enqueue(input),
    replay = await f.queue.enqueue(input);
  assert.equal(replay.id, first.id);
  assert.equal(replay.replayed, true);
  await assert.rejects(
    f.queue.enqueue({ ...input, payload: { artifact: 'changed' } }),
    {
      code: 'TASK_KEY_CONFLICT',
    },
  );
  assert.deepEqual((await f.queue.get('operation'))?.payload, input.payload);
  await assert.rejects(
    f.store.transaction(async (unit) => {
      await new PostgresTaskQueue(unit, { namespace: 'test' }).enqueue({
        key: 'rolled-back',
        payload: {},
      });
      throw new Error('host rollback');
    }),
    /host rollback/,
  );
  assert.equal(await f.queue.get('rolled-back'), undefined);
});

test('independent processes consume twenty tasks once, with durable fencing generations', async (t) => {
  const f = await fixture(t);
  for (let n = 0; n < 20; n++)
    await f.queue.enqueue({ key: `job-${n}`, payload: { n } });
  const env = { PLK_TEST_COORD_START_AT: String(Date.now() + 700) },
    results = await Promise.all([
      worker(f.schema, 'tasks', env),
      worker(f.schema, 'tasks', env),
    ]);
  assert.equal(new Set(results.map((row) => row.pid)).size, 2);
  const ids = results.flatMap((row) => row.completed as string[]);
  assert.equal(ids.length, 20);
  assert.equal(new Set(ids).size, 20);
  const rows = await f.store.all<{ state: string; generation: number }>(
    'SELECT state,generation FROM task_jobs',
  );
  assert.ok(
    rows.every((row) => row.state === 'succeeded' && row.generation === 1),
  );
});

test('process death before external work permits takeover and rejects every stale-token mutation', async (t) => {
  const f = await fixture(t);
  await f.queue.enqueue({ key: 'recover', payload: {} });
  const old = (await worker(f.schema, 'crash')).lease as TaskLease;
  await delay(230);
  const current = (await f.queue.claim())!;
  assert.equal(current.id, old.id);
  assert.equal(current.generation, old.generation + 1);
  assert.notEqual(current.token, old.token);
  await assert.rejects(f.queue.heartbeat(old), { code: 'TASK_LEASE_LOST' });
  await assert.rejects(f.queue.beginExternal(old), { code: 'TASK_LEASE_LOST' });
  await assert.rejects(f.queue.complete(old), { code: 'TASK_LEASE_LOST' });
  await assert.rejects(
    f.queue.fail(old, 'SYNTHETIC_FAILURE', { retryable: true }),
    {
      code: 'TASK_LEASE_LOST',
    },
  );
  await f.queue.complete(current);
  assert.equal((await f.queue.get('recover'))?.state, 'succeeded');
});

test('process death after entering external phase is quarantined, requires confirmed retry and records operator generation', async (t) => {
  const f = await fixture(t);
  await f.queue.enqueue({ key: 'unknown', payload: {} });
  const old = (await worker(f.schema, 'send-crash')).lease as TaskLease;
  await delay(230);
  assert.equal(await f.queue.claim(), undefined);
  const row = (await f.queue.get('unknown'))!;
  assert.equal(row.state, 'uncertain');
  const review = {
    outcome: 'retry' as const,
    reason: 'receiver confirmed no acceptance',
    actor: 'operator-1',
    generation: old.generation,
  };
  await assert.rejects(f.queue.resolve('unknown', review), {
    code: 'TASK_RETRY_REQUIRES_CONFIRMED_NOT_SENT',
  });
  await f.queue.resolve('unknown', { ...review, confirmedNotSent: true });
  const next = (await f.queue.claim())!;
  assert.equal(next.generation, old.generation + 1);
  const uncertain = await f.queue.fail(
    await f.queue.beginExternal(next),
    'AMBIGUOUS_RESULT',
  );
  assert.equal(uncertain.state, 'uncertain');
  await assert.rejects(
    f.queue.resolve('unknown', { ...review, outcome: 'succeeded' }),
    {
      code: 'TASK_NOT_REVIEWABLE',
    },
  );
  await f.queue.resolve('unknown', {
    ...review,
    outcome: 'succeeded',
    generation: next.generation,
    result: { receipt: 'synthetic' },
  });
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM task_job_reviews',
      )
    )?.n,
    2,
  );
});

test('retry backoff, attempt exhaustion, TTL and cursor scope survive independent queue objects', async (t) => {
  const f = await fixture(t);
  await f.queue.enqueue({ key: 'retry', payload: {}, maxAttempts: 2 });
  const lease = (await f.queue.claim())!;
  assert.equal(
    (await f.queue.fail(lease, 'KNOWN_REJECTION', { retryable: true })).state,
    'pending',
  );
  assert.equal(await f.queue.claim(), undefined);
  await f.store.run("UPDATE task_jobs SET next_at=0 WHERE task_key='retry'");
  const next = (await f.queue.claim())!;
  assert.equal(next.attempts, 2);
  assert.equal(
    (await f.queue.fail(next, 'KNOWN_REJECTION', { retryable: true })).state,
    'dead',
  );
  await f.queue.enqueue({ key: 'expired', payload: {} });
  await f.store.run(
    "UPDATE task_jobs SET expires_at=0 WHERE task_key='expired'",
  );
  assert.equal(await f.queue.claim(), undefined);
  assert.equal((await f.queue.get('expired'))?.state, 'expired');
  const page = await f.queue.list({ limit: 1 });
  assert.ok(page.nextCursor);
  assert.equal(page.items.length, 1);
  assert.equal(
    (await f.queue.list({ limit: 1, cursor: page.nextCursor! })).items.length,
    1,
  );
  const foreign = new PostgresTaskQueue(f.store, { namespace: 'other' });
  await assert.rejects(foreign.list({ cursor: page.nextCursor! }), {
    code: 'INVALID_TASK_CURSOR',
  });
  assert.equal('token' in page.items[0]!, false);
});

test('two notification processes deliver ten committed resource events once through a real loopback receiver', async (t) => {
  const f = await fixture(t),
    h = await business(f.store);
  for (let n = 0; n < 9; n++)
    await h.framework.setEntitlementAccess(
      h.session.accountId,
      'tool-1',
      'stable',
      'synthetic event',
      key(),
    );
  const received: string[] = [];
  const receiver = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    const event = JSON.parse(body) as {
      id: string;
      resource: { kind: string; id: string };
    };
    assert.ok(event.resource);
    received.push(event.id);
    await delay(15);
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  await new Promise<void>((done) => receiver.listen(0, '127.0.0.1', done));
  t.after(
    () =>
      new Promise<void>((done, fail) =>
        receiver.close((error) => (error ? fail(error) : done())),
      ),
  );
  const address = receiver.address();
  assert.ok(address && typeof address === 'object');
  const env = {
    PLK_TEST_NOTIFICATION_RECEIVER: `http://127.0.0.1:${address.port}/notice`,
    PLK_TEST_COORD_START_AT: String(Date.now() + 700),
  };
  const results = await Promise.all([
    worker(f.schema, 'notifications', env),
    worker(f.schema, 'notifications', env),
  ]);
  t.diagnostic(JSON.stringify({ workers: results, received: received.length }));
  assert.equal(
    results.reduce((n, row) => n + Number(row.delivered), 0),
    10,
  );
  assert.equal(received.length, 10);
  assert.equal(new Set(received).size, 10);
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM outbox WHERE delivered_at IS NOT NULL',
      )
    )?.n,
    10,
  );
});

test('bounded task routing claims only selected keys and releases unstarted leases without consuming retry attempts', async (t) => {
  const f = await fixture(t),
    queue = new PostgresTaskQueue(f.store, {
      namespace: 'routes',
      leaseMs: 10000,
    }),
    other = new PostgresTaskQueue(f.store, {
      namespace: 'foreign',
      leaseMs: 10000,
    }),
    selected = "route'); DROP TABLE task_jobs; --";
  await queue.enqueue({ key: 'unrelated', payload: { value: 1 } });
  await queue.enqueue({ key: selected, payload: { value: 2 } });
  await other.enqueue({ key: selected, payload: { value: 3 } });
  assert.equal(await queue.claim({ keys: [] }), undefined);
  assert.equal((await queue.get('unrelated'))!.generation, 0);
  await assert.rejects(
    queue.claim({ keys: Array.from({ length: 101 }, (_, i) => String(i)) }),
  );
  const lease = (await queue.claim({ keys: [selected, selected] }))!;
  assert.equal(lease.key, selected);
  assert.equal(lease.attempts, 1);
  await assert.rejects(
    f.store.transaction(async (unit) => {
      await queue.release(lease, unit);
      throw new Error('synthetic release rollback');
    }),
    /synthetic release rollback/,
  );
  assert.equal((await queue.get(selected))!.state, 'leased');
  const released = await queue.release(lease);
  assert.equal(released.state, 'pending');
  assert.equal(released.attempts, 0);
  await assert.rejects(queue.release(lease), { code: 'TASK_LEASE_LOST' });
  const current = (await queue.claim({ keys: [selected] }))!;
  assert.equal(current.generation, lease.generation + 1);
  assert.equal(current.attempts, 1);
  await assert.rejects(queue.complete(lease), { code: 'TASK_LEASE_LOST' });
  const sending = await queue.beginExternal(current);
  await assert.rejects(queue.release(sending), { code: 'TASK_LEASE_LOST' });
  await queue.complete(sending);
  assert.equal((await queue.get('unrelated'))!.generation, 0);
  assert.equal((await other.get(selected))!.generation, 0);
});

test('two provider-specific notification processes route committed business events without competing for other identities', async (t) => {
  const f = await fixture(t),
    h = await business(f.store),
    framework = await AsyncFramework.create({
      store: f.store,
      catalog: h.framework.catalog,
      signer: h.framework.signer,
      issuer: h.framework.issuer,
      providers: [
        ...h.framework.providers.values(),
        {
          name: 'synthetic-other',
          verify: async (subject) => ({ provider: 'synthetic-other', subject }),
        },
      ],
    });
  for (let index = 0; index < 9; index++)
    await framework.registerVerifiedIdentity(
      {
        provider: index < 4 ? 'local' : 'synthetic-other',
        subject: 'routed-' + index,
      },
      {
        source: 'synthetic',
        reference: 'route-' + index,
        reason: 'independent notification routes',
      },
    );
  const received: {
    id: string;
    identity: { provider: string; subject: string };
    pid: number;
  }[] = [];
  const receiver = createServer(async (request, response) => {
    let body = '';
    for await (const chunk of request) body += chunk;
    received.push(JSON.parse(body));
    response.writeHead(200, { 'Content-Type': 'application/json' });
    response.end('{}');
  });
  await new Promise<void>((done) => receiver.listen(0, '127.0.0.1', done));
  t.after(
    () =>
      new Promise<void>((done, fail) =>
        receiver.close((error) => (error ? fail(error) : done())),
      ),
  );
  const address = receiver.address();
  assert.ok(address && typeof address === 'object');
  const env = {
      PLK_TEST_NOTIFICATION_RECEIVER: `http://127.0.0.1:${address.port}/notice`,
      PLK_TEST_COORD_START_AT: String(Date.now() + 700),
    },
    results = await Promise.all(
      ['local', 'synthetic-other'].map((provider) =>
        worker(f.schema, 'notifications', {
          ...env,
          PLK_TEST_NOTIFICATION_PROVIDERS: JSON.stringify([provider]),
        }),
      ),
    );
  assert.equal(new Set(results.map((row) => row.pid)).size, 2);
  assert.equal(received.length, 10);
  assert.equal(new Set(received.map((row) => row.id)).size, 10);
  for (const [index, provider] of ['local', 'synthetic-other'].entries()) {
    assert.equal(results[index]!.delivered, 5);
    assert.equal(results[index]!.failed, 0);
    assert.equal(
      received.filter(
        (row) =>
          row.pid === results[index]!.pid && row.identity.provider === provider,
      ).length,
      5,
    );
  }
  assert.equal(
    (await f.store.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM outbox WHERE delivered_at IS NOT NULL AND attempts=1',
    ))!.n,
    10,
  );
});

test('identity changes during notification preparation hand off the unstarted lease without sending to a stale recipient', async (t) => {
  for (const target of [
    { provider: 'synthetic-other', subject: 'new-route' },
    { provider: 'local', subject: 'new-local-subject' },
  ]) {
    const f = await fixture(t),
      h = await business(f.store);
    let changed = false,
      calls = 0;
    const notifications = new PostgresNotificationWorker(f.store, {
        providers: ['local'],
        accountEnabled: async (accountId) => {
          if (!changed) {
            changed = true;
            await f.store.run(
              'UPDATE accounts SET provider=$2,subject=$3 WHERE id=$1',
              accountId,
              target.provider,
              target.subject,
            );
          }
          return true;
        },
      }),
      result = await notifications.run(
        {
          send: async () => {
            calls++;
          },
        },
        1,
      );
    assert.deepEqual(result, {
      delivered: 0,
      failed: 0,
      skipped: 1,
      uncertain: 0,
    });
    assert.equal(calls, 0);
    const event = (await f.store.get<{
        id: string;
        attempts: number;
        delivered_at: number | null;
      }>('SELECT * FROM outbox WHERE account_id=$1', h.session.accountId))!,
      task = (await notifications.queue.get(event.id))!;
    assert.equal(event.attempts, 0);
    assert.equal(event.delivered_at, null);
    assert.equal(task.state, 'pending');
    assert.equal(task.attempts, 0);
    assert.equal(task.generation, 1);
    assert.equal(
      (
        await new PostgresNotificationWorker(f.store, {
          providers: [target.provider],
        }).run(
          {
            send: async (_event, identity) => {
              calls++;
              assert.deepEqual(identity, target);
            },
          },
          1,
        )
      ).delivered,
      1,
    );
    assert.equal(calls, 1);
  }
});

test('a provider change between task selection and event loading leaves the task available to the new route', async (t) => {
  const f = await fixture(t),
    h = await business(f.store);
  let changed = false;
  const wrapped: AsyncStore = {
    all: f.store.all.bind(f.store),
    run: f.store.run.bind(f.store),
    transaction: f.store.transaction.bind(f.store),
    get: async (sql, ...values) => {
      if (!changed && sql.includes('SELECT o.*,a.provider,a.subject')) {
        changed = true;
        await f.store.run(
          'UPDATE accounts SET provider=$2,subject=$3 WHERE id=$1',
          h.session.accountId,
          'synthetic-other',
          'new-route',
        );
      }
      return f.store.get(sql, ...values);
    },
  };
  const worker = new PostgresNotificationWorker(wrapped, {
    providers: ['local'],
  });
  assert.deepEqual(
    await worker.run(
      { send: async () => assert.fail('foreign route must not send') },
      1,
    ),
    { delivered: 0, failed: 0, skipped: 1, uncertain: 0 },
  );
  const event = (await f.store.get<{ id: string }>('SELECT id FROM outbox'))!;
  assert.equal((await worker.queue.get(event.id))!.attempts, 0);
  assert.equal(
    (
      await new PostgresNotificationWorker(f.store, {
        providers: ['synthetic-other'],
      }).run(
        {
          send: async (_event, identity) =>
            assert.equal(identity.subject, 'new-route'),
        },
        1,
      )
    ).delivered,
    1,
  );
});

test('changing identity routes cannot automatically replay an ambiguous send or replace explicit operator review', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  const own = new PostgresNotificationWorker(f.store, { providers: ['local'] }),
    foreign = new PostgresNotificationWorker(f.store, { providers: ['kook'] });
  await own.run(
    {
      send: async () => {
        throw new Error('synthetic receipt lost');
      },
    },
    1,
  );
  const task = (await own.queue.list({ state: 'uncertain' })).items[0]!,
    input = {
      outcome: 'succeeded' as const,
      generation: task.generation,
      actor: 'synthetic-operator',
      reason: 'verified synthetic receipt',
    };
  const account = (await f.store.get<{ account_id: string }>(
    'SELECT account_id FROM outbox WHERE id=$1',
    task.key,
  ))!.account_id;
  await f.store.run(
    'UPDATE accounts SET provider=$2,subject=$3 WHERE id=$1',
    account,
    'kook',
    '100001',
  );
  assert.equal(
    (
      await foreign.run(
        {
          send: async () =>
            assert.fail('an ambiguous prior send cannot be rerouted'),
        },
        1,
      )
    ).delivered,
    0,
  );
  assert.equal(
    (
      await own.run(
        {
          send: async () =>
            assert.fail('an ambiguous prior send cannot be repeated'),
        },
        1,
      )
    ).delivered,
    0,
  );
  assert.equal((await own.queue.get(task.key))!.state, 'uncertain');
  assert.equal(
    (await f.store.get<{ delivered_at: number | null }>(
      'SELECT delivered_at FROM outbox WHERE id=$1',
      task.key,
    ))!.delivered_at,
    null,
  );
  await own.resolve(task.key, input);
  assert.equal((await own.queue.get(task.key))!.state, 'succeeded');
});

test('a scoped notification worker needs no account update privilege to prepare and deliver its route', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  const role = 'plk_notice_' + randomUUID().replaceAll('-', ''),
    password = randomUUID() + randomUUID();
  await admin.query(`CREATE ROLE "${role}" LOGIN PASSWORD '${password}'`);
  await admin.query(`GRANT USAGE ON SCHEMA "${f.schema}" TO "${role}"`);
  await admin.query(
    `GRANT SELECT ON ALL TABLES IN SCHEMA "${f.schema}" TO "${role}"`,
  );
  await admin.query(
    `GRANT UPDATE ON "${f.schema}".task_jobs,"${f.schema}".outbox TO "${role}"`,
  );
  let restricted: PostgresStore | undefined;
  t.after(async () => {
    await restricted?.close();
    await admin.query(`DROP OWNED BY "${role}"`);
    await admin.query(`DROP ROLE "${role}"`);
  });
  const url = new URL(connection!);
  url.username = role;
  url.password = password;
  restricted = await PostgresStore.connect({
    connectionString: url.href,
    schema: f.schema,
    migrate: false,
  });
  assert.equal(
    (await restricted.get<{ allowed: boolean }>(
      "SELECT has_table_privilege(current_user,'accounts','UPDATE') AS allowed",
    ))!.allowed,
    false,
  );
  const result = await new PostgresNotificationWorker(restricted, {
    providers: ['local'],
  }).run(
    {
      send: async (_event, identity) =>
        assert.equal(identity.provider, 'local'),
    },
    1,
  );
  assert.equal(result.delivered, 1);
  assert.equal(result.failed, 0);
});

test('notification rejection retries after backoff while ambiguous sends never automatically repeat', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  const worker = new PostgresNotificationWorker(f.store);
  let calls = 0;
  const rejected = await worker.run({
    async send() {
      calls++;
      throw new NotificationNotSentError('RECEIVER_REJECTED');
    },
  });
  assert.equal(rejected.failed, 1);
  assert.equal(
    (
      await worker.run({
        async send() {
          calls++;
        },
      })
    ).delivered,
    0,
  );
  await f.store.run("UPDATE task_jobs SET next_at=0 WHERE state='pending'");
  assert.equal(
    (
      await worker.run({
        async send() {
          calls++;
        },
      })
    ).delivered,
    1,
  );
  assert.equal(calls, 2);
  const event = randomUUID(),
    account = (await f.store.get<{ id: string }>('SELECT id FROM accounts'))!
      .id;
  await f.store.run(
    'INSERT INTO outbox(id,topic,account_id,created_at) VALUES($1,$2,$3,$4)',
    event,
    'account.registered',
    account,
    Date.now(),
  );
  const queue = new PostgresTaskQueue(f.store, {
    namespace: notificationQueueNamespace,
  });
  await queue.enqueue({ key: event, payload: { eventId: event } });
  const unknown = await worker.run({
    async send() {
      calls++;
      throw new Error('lost provider response');
    },
  });
  assert.equal(unknown.uncertain, 1);
  assert.equal((await queue.get(event))?.state, 'uncertain');
  assert.equal(
    (
      await worker.run({
        async send() {
          assert.fail('no replay');
        },
      })
    ).delivered,
    0,
  );
});

test('heartbeat keeps a slow sender owned beyond the initial lease and a send timeout stays uncertain', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  const worker = new PostgresNotificationWorker(f.store, {
      leaseMs: 1000,
      sendTimeoutMs: 8000,
    }),
    queue = new PostgresTaskQueue(f.store, {
      namespace: notificationQueueNamespace,
      leaseMs: 1000,
    });
  let started!: () => void;
  let release!: () => void;
  const held = new Promise<void>((done) => {
    release = done;
  });
  const sending = new Promise<void>((done) => {
    started = done;
  });
  const running = worker.run({
    async send() {
      started();
      await held;
    },
  });
  await Promise.race([
    sending,
    running.then(() => {
      throw new Error('SENDER_ENDED_BEFORE_START');
    }),
  ]);
  let outcome: Awaited<ReturnType<typeof worker.run>> | undefined;
  try {
    const initial = (await f.store.get<{ lease_until: number }>(
      "SELECT lease_until FROM task_jobs WHERE state='sending'",
    ))!;
    let clock = 0;
    const deadline = performance.now() + 5000;
    // Hold the real sender across the database's original lease boundary, rather than racing two short sleeps.
    while (clock <= initial.lease_until + 100 && performance.now() < deadline) {
      await delay(50);
      clock = (await f.store.get<{ now: number }>(
        'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now',
      ))!.now;
    }
    assert.ok(clock > initial.lease_until + 100);
    const renewed = await f.store.get<{ lease_until: number }>(
      "SELECT lease_until FROM task_jobs WHERE state='sending'",
    );
    assert.ok(
      renewed &&
        renewed.lease_until > initial.lease_until &&
        renewed.lease_until > clock,
    );
    assert.equal(await queue.claim(), undefined);
  } finally {
    release();
    outcome = await running;
  }
  assert.equal(outcome.delivered, 1);
  const h = await AsyncFramework.create({
    store: f.store,
    catalog: catalog(),
    signer: new EnvelopeSigner(keyPair().privateKey),
    providers: [],
    issuer: 'test',
  });
  const account = (await f.store.get<{ id: string }>(
    'SELECT id FROM accounts',
  ))!.id;
  await h.setEntitlementAccess(
    account,
    'tool-1',
    'stable',
    'timeout event',
    key(),
  );
  const timed = await new PostgresNotificationWorker(f.store, {
    leaseMs: 1000,
    sendTimeoutMs: 100,
  }).run({
    async send() {
      await delay(200);
    },
  });
  assert.equal(timed.uncertain, 1);
  assert.equal((await queue.list({ state: 'uncertain' })).items.length, 1);
});

test('lost acknowledgement after actual commit does not re-deliver the accepted notification', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  let transactions = 0,
    calls = 0;
  const wrapped: AsyncStore = {
    get: f.store.get.bind(f.store),
    all: f.store.all.bind(f.store),
    run: f.store.run.bind(f.store),
    transaction: async (work) => {
      const result = await f.store.transaction(work);
      if (++transactions === 2)
        throw new StorageError('TRANSACTION_COMMIT_UNCERTAIN');
      return result;
    },
  };
  const worker = new PostgresNotificationWorker(wrapped),
    result = await worker.run({
      async send() {
        calls++;
      },
    });
  assert.equal(result.failed, 1);
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM outbox WHERE delivered_at IS NOT NULL',
      )
    )?.n,
    1,
  );
  assert.equal(
    (
      await worker.run({
        async send() {
          calls++;
        },
      })
    ).delivered,
    0,
  );
  assert.equal(calls, 1);
});

test('failed receipt transaction quarantines acceptance; audited manual resolution atomically completes the outbox', async (t) => {
  const f = await fixture(t);
  await business(f.store);
  let transactions = 0,
    calls = 0;
  const wrapped: AsyncStore = {
    get: f.store.get.bind(f.store),
    all: f.store.all.bind(f.store),
    run: f.store.run.bind(f.store),
    transaction: (work) =>
      f.store.transaction(async (unit) => {
        const result = await work(unit);
        if (++transactions === 2)
          throw new Error('synthetic acknowledgement rollback');
        return result;
      }),
  };
  const worker = new PostgresNotificationWorker(wrapped);
  assert.equal(
    (
      await worker.run({
        async send() {
          calls++;
        },
      })
    ).uncertain,
    1,
  );
  const tasks = await worker.queue.list({ state: 'uncertain' }),
    job = tasks.items[0]!;
  assert.equal(calls, 1);
  assert.equal(job.state, 'uncertain');
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM outbox WHERE delivered_at IS NOT NULL',
      )
    )?.n,
    0,
  );
  await worker.resolve(job.key, {
    outcome: 'succeeded',
    actor: 'operator-1',
    reason: 'verified synthetic platform receipt',
    generation: job.generation,
    result: { receipt: 'synthetic-1' },
  });
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM outbox WHERE delivered_at IS NOT NULL',
      )
    )?.n,
    1,
  );
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM task_job_reviews',
      )
    )?.n,
    1,
  );
  assert.equal(
    (
      await worker.run({
        async send() {
          calls++;
        },
      })
    ).delivered,
    0,
  );
  assert.equal(calls, 1);
});

test('operator review insertion failure rolls back resolution and disabled accounts never reach the sink', async (t) => {
  const f = await fixture(t),
    h = await business(f.store);
  const queue = new PostgresTaskQueue(f.store, {
    namespace: notificationQueueNamespace,
  });
  const lease = (await queue.claim())!;
  await queue.fail(await queue.beginExternal(lease), 'AMBIGUOUS_RESULT');
  const wrapped: AsyncStore = {
    get: f.store.get.bind(f.store),
    all: f.store.all.bind(f.store),
    run: f.store.run.bind(f.store),
    transaction: (work) =>
      f.store.transaction((unit) =>
        work({
          transactionUnit: true,
          get: unit.get.bind(unit),
          all: unit.all.bind(unit),
          transaction: unit.transaction.bind(unit),
          run: (sql, ...values) => {
            if (sql.startsWith('INSERT INTO task_job_reviews'))
              throw new Error('synthetic audit rollback');
            return unit.run(sql, ...values);
          },
        }),
      ),
  };
  const worker = new PostgresNotificationWorker(wrapped);
  await assert.rejects(
    worker.resolve(lease.key, {
      outcome: 'succeeded',
      actor: 'operator-1',
      reason: 'synthetic receipt checked',
      generation: lease.generation,
    }),
    /synthetic audit rollback/,
  );
  assert.equal((await queue.get(lease.key))?.state, 'uncertain');
  assert.equal(
    (
      await f.store.get<{ n: number }>(
        'SELECT count(*) AS n FROM outbox WHERE delivered_at IS NOT NULL',
      )
    )?.n,
    0,
  );
  await h.framework.setAccountActive(
    h.session.accountId,
    false,
    'disabled before notification',
  );
  const result = await new PostgresNotificationWorker(f.store).run({
    async send() {
      assert.fail('disabled recipient');
    },
  });
  assert.equal(result.delivered, 0);
  assert.equal(result.failed, 1);
});
