import { setTimeout as delay } from 'node:timers/promises';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { PostgresRateLimiter } from '../../src/adapters/postgres-rate-limit.js';
import { PostgresTaskQueue } from '../../src/adapters/postgres-tasks.js';
import { PostgresNotificationWorker } from '../../src/adapters/postgres-notifications.js';

const connectionString = process.env.PLK_TEST_POSTGRES_URL,
  schema = process.env.PLK_TEST_COORD_SCHEMA,
  mode = process.argv[2];
if (
  process.env.PLK_TEST_POSTGRES_SCOPED !== '1' ||
  !connectionString ||
  !schema ||
  !/^plk_coord_[a-f0-9]{32}$/.test(schema)
)
  throw new Error('SCOPED_COORDINATION_FIXTURE_REQUIRED');
const store = await PostgresStore.connect({
  connectionString,
  schema,
  maxConnections: 2,
});
try {
  const start = Number(process.env.PLK_TEST_COORD_START_AT);
  if (Number.isFinite(start))
    await delay(Math.max(0, Math.min(2000, start - Date.now())));
  if (mode === 'limit') {
    const limiter = new PostgresRateLimiter(store, {
      namespace: 'test',
      secret: process.env.PLK_TEST_RATE_SECRET!,
    });
    let allowed = 0;
    for (let n = 0; n < 20; n++)
      if (
        (await limiter.increment('127.0.0.1', 60000, 12, 'worker')).current <=
        12
      )
        allowed++;
    console.log(JSON.stringify({ pid: process.pid, allowed }));
  } else if (mode === 'tasks' || mode === 'crash' || mode === 'send-crash') {
    const queue = new PostgresTaskQueue(store, {
        namespace: 'test',
        leaseMs: 200,
      }),
      completed: string[] = [];
    for (;;) {
      let lease = await queue.claim();
      if (!lease) break;
      if (mode === 'send-crash') lease = await queue.beginExternal(lease);
      if (mode !== 'tasks') {
        console.log(JSON.stringify({ pid: process.pid, lease }));
        process.exit(0);
      }
      await delay(5);
      await queue.complete(lease, { pid: process.pid });
      completed.push(lease.id);
    }
    console.log(JSON.stringify({ pid: process.pid, completed }));
  } else if (mode === 'notifications') {
    const url = process.env.PLK_TEST_NOTIFICATION_RECEIVER!;
    if (!/^http:\/\/127\.0\.0\.1:\d+\/notice$/.test(url))
      throw new Error('LOOPBACK_RECEIVER_REQUIRED');
    const providers = process.env.PLK_TEST_NOTIFICATION_PROVIDERS;
    const result = await new PostgresNotificationWorker(
      store,
      providers ? { providers: JSON.parse(providers) } : {},
    ).run(
      {
        async send(event, identity) {
          const response = await fetch(url, {
            method: 'POST',
            body: JSON.stringify({
              id: event.id,
              resource: event.resource,
              identity,
              pid: process.pid,
            }),
            headers: { 'Content-Type': 'application/json' },
            redirect: 'error',
            signal: AbortSignal.timeout(3000),
          });
          if (!response.ok) throw new Error('SYNTHETIC_RECEIVER_FAILED');
        },
      },
      100,
    );
    console.log(JSON.stringify({ pid: process.pid, ...result }));
  } else throw new Error('INVALID_COORDINATION_WORKER');
} finally {
  await store.close();
}
