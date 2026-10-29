import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, rmdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { SqliteStore } from '../src/adapters/sqlite.js';

test('SQLite persists transactions across reconnect and rolls back failed writes', () => {
  const directory = mkdtempSync(join(tmpdir(), 'plk-storage-test-'));
  const path = join(directory, 'test.sqlite');
  let store: SqliteStore | undefined;
  try {
    store = new SqliteStore(path);
    store.transaction(() => store!.run('INSERT INTO accounts VALUES (?,?,?,?)', 'a', 'local', 'verified-a', 1));
    assert.throws(() => store!.transaction(() => {
      store!.run('INSERT INTO accounts VALUES (?,?,?,?)', 'b', 'local', 'verified-b', 1);
      throw new Error('simulated failure');
    }), /simulated failure/);
    store.close(); store = new SqliteStore(path);
    assert.equal(store.all('SELECT * FROM accounts').length, 1);
    assert.equal(store.get<{ id: string }>('SELECT id FROM accounts')!.id, 'a');
    assert.throws(() => store!.run('INSERT INTO credits VALUES (?,?,?)', 'missing', 'group', 1), /FOREIGN KEY/);
  } finally {
    store?.close();
    // Only remove the three known synthetic files in the freshly created test directory.
    for (const suffix of ['', '-wal', '-shm']) rmSync(path + suffix, { force: true });
    rmdirSync(directory);
  }
});
