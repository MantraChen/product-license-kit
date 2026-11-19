import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { SqliteStore } from '../src/adapters/sqlite.js';
import { SqliteTaskQueue } from '../src/adapters/sqlite-tasks.js';

test('SQLite migration eight preserves existing task-independent domain records and repeated opens', () => {
  const directory = mkdtempSync(join(tmpdir(), 'plk-sqlite-tasks-')),
    path = join(directory, 'test.sqlite');
  let store = new SqliteStore(path);
  try {
    store.run(
      'INSERT INTO accounts VALUES(?,?,?,?)',
      'a',
      'local',
      'person',
      1,
    );
    store.close();
    store = new SqliteStore(path);
    assert.equal(
      store.get<{ n: number }>('SELECT count(*) n FROM accounts')?.n,
      1,
    );
    assert.equal(
      store.get<{ n: number }>(
        'SELECT count(*) n FROM plk_migrations WHERE version=8',
      )?.n,
      1,
    );
  } finally {
    store.close();
    const exact = realpathSync(directory);
    assert.equal(
      dirname(exact).toLowerCase(),
      realpathSync(tmpdir()).toLowerCase(),
    );
    assert.ok(exact.toLowerCase().includes('plk-sqlite-tasks-'));
    rmSync(exact, { recursive: true });
  }
});
test('SQLite task commands atomically commit with domain effects and use one immutable result', () => {
  const s = new SqliteStore(':memory:'),
    q = new SqliteTaskQueue(s, { namespace: 'test' });
  try {
    assert.throws(
      () =>
        s.transaction(() => {
          q.enqueue({ key: 'rollback', payload: {} });
          throw Error('rollback');
        }),
      /rollback/,
    );
    assert.equal(q.get('rollback'), undefined);
    const first = q.enqueue({ key: 'one', payload: { id: 'resource' } });
    assert.equal(
      q.enqueue({ key: 'one', payload: { id: 'resource' } }).id,
      first.id,
    );
    assert.throws(
      () => q.enqueue({ key: 'one', payload: { id: 'different' } }),
      /TASK_KEY_CONFLICT/,
    );
    const lease = q.claim()!;
    q.complete(lease, { id: 'file' });
    assert.equal(q.get('one')?.state, 'succeeded');
    assert.equal(q.claim(), undefined);
    assert.throws(() => q.complete(lease), /TASK_LEASE_LOST/);
  } finally {
    s.close();
  }
});
test('SQLite lease generations fence stale mutations and external phase expiry requires audited review', () => {
  const s = new SqliteStore(':memory:'),
    q = new SqliteTaskQueue(s, { namespace: 'test', leaseMs: 100 });
  try {
    q.enqueue({ key: 'one', payload: {} });
    const old = q.claim()!;
    s.run('UPDATE task_jobs SET lease_until=0');
    const current = q.claim()!;
    assert.equal(current.generation, old.generation + 1);
    for (const mutation of [
      () => q.heartbeat(old),
      () => q.beginExternal(old),
      () => q.complete(old),
      () => q.fail(old, 'KNOWN_FAILURE'),
    ])
      assert.throws(mutation, /TASK_LEASE_LOST/);
    q.beginExternal(current);
    s.run('UPDATE task_jobs SET lease_until=0');
    assert.equal(q.claim(), undefined);
    assert.equal(q.get('one')?.state, 'uncertain');
    const review = {
      outcome: 'retry' as const,
      actor: 'operator',
      reason: 'receiver confirmed no acceptance',
      generation: current.generation,
    };
    assert.throws(
      () => q.resolve('one', review),
      /TASK_RETRY_REQUIRES_CONFIRMED_NOT_SENT/,
    );
    q.resolve('one', { ...review, confirmedNotSent: true });
    assert.equal(
      s.get<{ n: number }>('SELECT count(*) n FROM task_job_reviews')?.n,
      1,
    );
    assert.equal(q.claim()!.generation, current.generation + 1);
  } finally {
    s.close();
  }
});
test('SQLite bounded retries, database-time expiry and namespace-bound cursors persist', () => {
  const s = new SqliteStore(':memory:'),
    q = new SqliteTaskQueue(s, { namespace: 'test' });
  try {
    q.enqueue({ key: 'one', payload: {}, maxAttempts: 1 });
    q.fail(q.claim()!, 'KNOWN_REJECTION', { retryable: true });
    assert.equal(q.get('one')?.state, 'dead');
    q.enqueue({ key: 'two', payload: {} });
    s.run("UPDATE task_jobs SET expires_at=0 WHERE task_key='two'");
    assert.equal(q.claim(), undefined);
    assert.equal(q.get('two')?.state, 'expired');
    const page = q.list({ limit: 1 });
    assert.ok(page.nextCursor);
    assert.equal(q.list({ cursor: page.nextCursor! }).items.length, 1);
    assert.throws(
      () =>
        new SqliteTaskQueue(s, { namespace: 'other' }).list({
          cursor: page.nextCursor!,
        }),
      /INVALID_TASK_CURSOR/,
    );
  } finally {
    s.close();
  }
});
test('independent SQLite worker processes each complete a claimed task once', async () => {
  const directory = mkdtempSync(join(tmpdir(), 'plk-sqlite-tasks-')),
    path = join(directory, 'test.sqlite'),
    s = new SqliteStore(path),
    q = new SqliteTaskQueue(s, { namespace: 'process' });
  try {
    for (let index = 0; index < 12; index++)
      q.enqueue({ key: String(index), payload: { index } });
    const module = fileURLToPath(
        new URL('../src/adapters/sqlite-tasks.js', import.meta.url),
      ),
      store = fileURLToPath(
        new URL('../src/adapters/sqlite.js', import.meta.url),
      );
    const script = `import {pathToFileURL} from 'node:url';const {SqliteStore}=await import(pathToFileURL(process.argv[1]));const {SqliteTaskQueue}=await import(pathToFileURL(process.argv[2]));const s=new SqliteStore(process.argv[3]);const q=new SqliteTaskQueue(s,{namespace:'process'});let ids=[];for(;;){const l=q.claim();if(!l)break;await new Promise(r=>setTimeout(r,5));q.complete(l);ids.push(l.id);}s.close();console.log(JSON.stringify({pid:process.pid,ids}));`;
    const start = () =>
      new Promise<{ pid: number; ids: string[] }>((done, fail) => {
        const child = spawn(
          process.execPath,
          ['--input-type=module', '-e', script, store, module, path],
          { windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
        );
        let output = '';
        child.stdout.on('data', (value) => {
          output += value;
        });
        child.stderr.resume();
        child.once('error', fail);
        child.once('close', (code) => {
          if (code !== 0) return fail(Error('SQLITE_TASK_WORKER_FAILED'));
          try {
            done(JSON.parse(output));
          } catch {
            fail(Error('INVALID_TASK_WORKER_RESULT'));
          }
        });
      });
    const results = await Promise.all([start(), start()]);
    assert.equal(new Set(results.map((row) => row.pid)).size, 2);
    const ids = results.flatMap((row) => row.ids);
    assert.equal(ids.length, 12);
    assert.equal(new Set(ids).size, 12);
  } finally {
    s.close();
    const exact = realpathSync(directory);
    assert.equal(
      dirname(exact).toLowerCase(),
      realpathSync(tmpdir()).toLowerCase(),
    );
    assert.ok(exact.toLowerCase().includes('plk-sqlite-tasks-'));
    rmSync(exact, { recursive: true });
  }
});
