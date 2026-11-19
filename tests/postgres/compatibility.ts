import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { DatabaseSync } from 'node:sqlite';
import { randomUUID } from 'node:crypto';
import {
  mkdtempSync,
  readFileSync,
  rmSync,
  existsSync,
  writeFileSync,
} from 'node:fs';
import { spawn } from 'node:child_process';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { realpathSync } from 'node:fs';
import { setTimeout as delay } from 'node:timers/promises';
import { SqliteStore } from '../../src/adapters/sqlite.js';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { postgresMigrations } from '../../src/adapters/postgres-schema.js';
import { Framework } from '../../src/service.js';
import { AsyncFramework } from '../../src/async-service.js';
import { LocalIdentityProvider } from '../../src/adapters/local-identity.js';
import {
  inspectSqliteMigration,
  migrateSqliteToPostgres,
  reviewSqliteCutover,
} from '../../src/security/sqlite-postgres.js';
import { sqliteCutoverPath } from '../../src/security/sqlite-cutover.js';
import { decryptBackup } from '../../src/security/backup.js';
import { acquireServiceLock } from '../../src/security/process-lock.js';
import {
  EnvelopeSigner,
  sha256,
  verifyEnvelope,
} from '../../src/core/crypto.js';
import { signChallenge } from '../../src/sdk/client.js';
import { catalog, key, keyPair } from '../helpers.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(
  connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1',
  'Use scripts/test-postgres.mjs.',
);
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
async function fixture(t: TestContext, version: 6 | 7 | 8 = 8) {
  const root = mkdtempSync(join(tmpdir(), 'plk-compat-test-')),
    database = join(root, 'framework.sqlite'),
    schema = 'plk_compat_' + randomUUID().replaceAll('-', '');
  const stores: PostgresStore[] = [];
  t.after(async () => {
    await Promise.all(stores.map((store) => store.close()));
    await admin.query(`DROP SCHEMA IF EXISTS "${schema}" CASCADE`);
    const exact = realpathSync(root),
      parent = realpathSync(tmpdir());
    assert.equal(dirname(exact).toLowerCase(), parent.toLowerCase());
    assert.ok(
      exact
        .toLowerCase()
        .startsWith(join(parent, 'plk-compat-test-').toLowerCase()),
    );
    rmSync(exact, { recursive: true });
  });
  const pair = keyPair(),
    signer = new EnvelopeSigner(pair.privateKey),
    device = keyPair(),
    proof = key() + key();
  const providers = [
      new LocalIdentityProvider([{ subject: 'synthetic-owner', proof }]),
    ],
    store = new SqliteStore(database);
  const framework = new Framework({
    store,
    signer,
    providers,
    catalog: catalog(),
    issuer: 'compat-test',
  });
  const invitation = framework.issueInvitation('local', 'synthetic-owner'),
    registration = await framework.register(invitation.ticket, proof);
  const accountId = registration.accountId,
    order = framework.createOrder(accountId, 'buy-tool-1', key());
  framework.confirmPayment(order.orderId, {
    method: 'synthetic',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  const challenge = framework.enrollmentChallenge(
    accountId,
    'desktop',
    device.publicKey,
    { schema: 'test-v1', digest: sha256('synthetic') },
  );
  const binding = framework.activate(
    accountId,
    challenge.challengeId,
    signChallenge(challenge.message, device.privateKey),
    key(),
  );
  const reservation = framework.reserveDistribution(
    accountId,
    'tool-1',
    'release-one',
    key(),
  );
  const manifest = framework.finalizeDistribution(
    reservation.distributionId,
    sha256('artifact'),
  ).manifest;
  store.run(
    'UPDATE distributions SET finalized_at=finalized_at+1 WHERE id=?',
    reservation.distributionId,
  );
  store.run(
    'INSERT INTO credits VALUES(?,?,?)',
    accountId,
    'desktop',
    9007199254740990,
  );
  store.run(
    'INSERT INTO binding_resets VALUES(?,?,?,?)',
    accountId,
    'desktop',
    1,
    123,
  );
  store.run(
    'INSERT INTO task_jobs VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    'old-task',
    'synthetic',
    'old-key',
    '{}',
    sha256('{}'),
    'sending',
    1,
    3,
    9,
    'old-holder',
    Date.now() + 60000,
    Date.now(),
    Date.now() + 86400000,
    Date.now(),
    Date.now(),
    null,
    null,
    null,
  );
  // Historical failed/succeeded task reviews remain exact, while active jobs are fenced.
  store.run(
    'INSERT INTO task_job_reviews VALUES(?,?,?,?,?,?,?)',
    'old-task',
    8,
    'reviewer',
    'retry',
    'earlier review',
    sha256('{}'),
    123,
  );
  store.close();
  if (version < 8) {
    const db = new DatabaseSync(database);
    db.exec(
      'DROP TABLE task_job_reviews; DROP TABLE task_jobs; DELETE FROM plk_migrations WHERE version=8',
    );
    if (version === 6)
      db.exec(
        'DROP TABLE outbox_resources; DELETE FROM plk_migrations WHERE version=7; DROP INDEX orders_account_cursor; DROP INDEX audit_cursor; DROP INDEX distributions_account_cursor',
      );
    db.close();
  }
  const options = {
    database,
    issuer: 'compat-test',
    catalog: catalog(),
    privateKey: pair.privateKey,
  };
  const connect = async (maintenance = true) => {
    const target = await PostgresStore.connect({
      connectionString: connection!,
      schema,
      maintenance,
    });
    stores.push(target);
    return target;
  };
  const apply = (
    target: PostgresStore,
    expectedPlanHash = inspectSqliteMigration(options).planHash,
  ) =>
    migrateSqliteToPostgres(target, {
      ...options,
      expectedPlanHash,
      actor: 'synthetic-owner',
      reason: 'isolated compatibility test',
      backupDirectory: join(root, 'backups'),
      backupPassword: 'synthetic-compatibility-password',
    });
  return {
    root,
    database,
    schema,
    options,
    connect,
    apply,
    accountId,
    order,
    binding,
    device,
    signer,
    manifest,
    reservation,
    providers,
  };
}

for (const version of [6, 7, 8] as const)
  test(`SQLite v${version} dry-run and offline cutover preserve paid rights, device proof and immutable artifacts`, async (t) => {
    const f = await fixture(t, version),
      original = readFileSync(f.database),
      plan = inspectSqliteMigration(f.options);
    assert.equal(plan.sourceVersion, version);
    assert.deepEqual(readFileSync(f.database), original);
    assert.ok(plan.clearedAuthenticationRows > 0);
    assert.ok(plan.heldNotifications > 0);
    assert.equal(JSON.stringify(plan).includes(f.accountId), false);
    assert.equal(JSON.stringify(plan).includes('PRIVATE KEY'), false);
    const target = await f.connect(),
      result = await f.apply(target, plan.planHash);
    assert.equal(result.planHash, plan.planHash);
    assert.equal(result.pausedTasks, version === 8 ? 1 : 0);
    assert.throws(() => new SqliteStore(f.database), {
      code: 'SQLITE_CUTOVER_REVIEW_REQUIRED',
    });
    assert.equal(
      JSON.parse(readFileSync(sqliteCutoverPath(f.database), 'utf8')).status,
      'completed',
    );
    const db = new DatabaseSync(f.database, { readOnly: true });
    assert.equal(
      db.prepare('SELECT status FROM orders WHERE id=?').get(f.order.orderId)
        ?.status,
      'paid',
    );
    db.close();
    assert.equal(
      (await target.get<{ balance: number }>('SELECT balance FROM credits'))!
        .balance,
      9007199254740990,
    );
    assert.equal(
      (await target.get<{ reset_at: number }>(
        'SELECT reset_at FROM binding_resets',
      ))!.reset_at,
      123,
    );
    assert.equal(
      (await target.get<{ manifest: string }>(
        'SELECT manifest FROM distributions',
      ))!.manifest,
      f.manifest,
    );
    assert.equal(
      (await target.get<{ n: number }>(
        'SELECT count(*)::int AS n FROM sessions',
      ))!.n,
      0,
    );
    assert.equal(
      (await target.get<{ n: number }>(
        'SELECT count(*)::int AS n FROM outbox WHERE delivered_at IS NULL',
      ))!.n,
      plan.heldNotifications,
    );
    if (version === 8) {
      const job = await target.get<{
        state: string;
        generation: number;
        lease_token: null;
      }>('SELECT * FROM task_jobs');
      assert.equal(job!.state, 'uncertain');
      assert.equal(job!.generation, 10);
      assert.equal(job!.lease_token, null);
    }
    const archive = decryptBackup(
      readFileSync(result.backupPath),
      'synthetic-compatibility-password',
    );
    assert.equal(sha256(readFileSync(result.backupPath)), result.backupSha256);
    assert.equal(archive['signing.pem']!.toString(), f.options.privateKey);
    assert.ok(archive['source.sqlite']!.length > 0);
    await target.close();
    const runtime = await f.connect(false),
      asyncFramework = await AsyncFramework.create({
        store: runtime,
        signer: f.signer,
        providers: f.providers,
        catalog: f.options.catalog,
        issuer: f.options.issuer,
      });
    const challenge = await asyncFramework.licenseChallenge(
      f.binding.deviceId,
      'tool-1',
    );
    const license = await asyncFramework.issueLicense(
      challenge.challengeId,
      signChallenge(challenge.message, f.device.privateKey),
    );
    const claims = verifyEnvelope(
      license.token,
      f.signer.publicKey,
      'plk-license',
    ) as { sub: string; device: string };
    assert.equal(claims.sub, f.accountId);
    assert.equal(claims.device, f.binding.deviceId);
    assert.equal(
      (
        await asyncFramework.finalizeDistribution(
          f.reservation.distributionId,
          sha256('artifact'),
        )
      ).manifest,
      f.manifest,
    );
  });

test('maintenance session excludes running runtimes, other migrators, and fresh runtime startup', async (t) => {
  const f = await fixture(t),
    runtime = await f.connect(false);
  await assert.rejects(f.connect(), { code: 'POSTGRES_MAINTENANCE_BUSY' });
  await runtime.close();
  const maintenance = await f.connect();
  await assert.rejects(f.connect(false), { code: 'POSTGRES_MAINTENANCE_BUSY' });
  await assert.rejects(f.connect(), { code: 'POSTGRES_MAINTENANCE_BUSY' });
  await maintenance.close();
  const after = await f.connect(false);
  assert.ok(await after.get('SELECT 1'));
});

test('migrations four through six preserve previous checksums and existing signing policy data', async (t) => {
  assert.equal(postgresMigrations[4].checksum, 'ed06de288901d6c95529250833ad89ba6ca22728199804790fb69abf2ef9e301');
  assert.equal(
    postgresMigrations[3].checksum,
    'd127b236affaea91095bc5a4f713873ef75a141cdcd4f40a46ad911637d71a0f',
  );
  assert.equal(
    postgresMigrations[2].checksum,
    '83232e5dca86b8df717d37416aa61fde93ff0b0ad774bfe0c04c99d53319ed89',
  );
  const f = await fixture(t),
    target = await f.connect();
  await target.run(
    'INSERT INTO signing_keys VALUES($1,$2,$3,1)',
    'existing',
    f.signer.kid,
    f.signer.publicKey,
  );
  await target.run(
    'INSERT INTO signing_policies VALUES($1,$2,7,$3,$4,1)',
    'existing',
    f.signer.kid,
    sha256('existing'),
    '["node-one"]',
  );
  await target.close();
  await admin.query(`DROP TABLE "${f.schema}".portal_registration_states,"${f.schema}".bot_notification_owners,"${f.schema}".bot_actions,"${f.schema}".bot_handoffs,"${f.schema}".bot_messages,"${f.schema}".bot_settings`);
  await admin.query(
    `DROP TABLE "${f.schema}".portal_reset_intents,"${f.schema}".portal_sessions,"${f.schema}".portal_oauth_states,"${f.schema}".portal_operators,"${f.schema}".portal_recovery,"${f.schema}".portal_mfa,"${f.schema}".portal_settings,"${f.schema}".compatibility_imports`,
  );
  await admin.query(
    `DELETE FROM "${f.schema}".plk_pg_migrations WHERE version>=4`,
  );
  const reopened = await f.connect(false),
    policy = await reopened.get<{ active_kid: string; epoch: number }>(
      'SELECT * FROM signing_policies',
    );
  assert.equal(policy!.active_kid, f.signer.kid);
  assert.equal(policy!.epoch, 7);
  assert.equal(
    (await reopened.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM plk_pg_migrations',
    ))!.n,
    6,
  );
});

test('an idle runtime reconnect cannot bypass a durable pending import, and a lost maintenance session cannot reacquire ownership', async (t) => {
  const f = await fixture(t),
    runtime = await f.connect(false),
    pid = (await runtime.get<{ pid: number }>(
      'SELECT pg_backend_pid() AS pid',
    ))!.pid;
  await admin.query('SELECT pg_terminate_backend($1)', [pid]);
  await delay(50);
  const maintenance = await f.connect();
  await maintenance.run(
    "INSERT INTO compatibility_imports VALUES('synthetic',$1,$1,'pending',$1,'owner','fault simulation',1,NULL)",
    sha256('synthetic'),
  );
  const ownerPid = (await maintenance.get<{ pid: number }>(
    'SELECT pg_backend_pid() AS pid',
  ))!.pid;
  await admin.query('SELECT pg_terminate_backend($1)', [ownerPid]);
  await delay(50);
  await assert.rejects(maintenance.get('SELECT 1'), {
    code: 'POSTGRES_MAINTENANCE_LOST',
  });
  await assert.rejects(runtime.get('SELECT 1'), {
    code: 'POSTGRES_IMPORT_REVIEW_REQUIRED',
  });
});

test('source writer reservation excludes direct SQLite mutations throughout asynchronous target work', async (t) => {
  const f = await fixture(t),
    target = await f.connect(),
    plan = inspectSqliteMigration(f.options),
    real = target.transaction.bind(target);
  let blocked = 0;
  target.transaction = async (work) => {
    const other = new DatabaseSync(f.database);
    other.exec('PRAGMA busy_timeout=10');
    try {
      assert.throws(() => other.exec('UPDATE credits SET balance=0'), /locked/);
      blocked++;
    } finally {
      other.close();
    }
    return real(work);
  };
  await f.apply(target, plan.planHash);
  assert.equal(blocked, 2);
  assert.equal(
    (await target.get<{ balance: number }>('SELECT balance FROM credits'))!
      .balance,
    9007199254740990,
  );
});

test('changed dry-run and occupied target leave source unsealed', async (t) => {
  const f = await fixture(t),
    plan = inspectSqliteMigration(f.options),
    target = await f.connect();
  const db = new DatabaseSync(f.database);
  db.prepare('UPDATE credits SET balance=balance-1').run();
  db.close();
  await assert.rejects(f.apply(target, plan.planHash), {
    code: 'SQLITE_MIGRATION_PLAN_CHANGED',
  });
  assert.equal(existsSync(sqliteCutoverPath(f.database)), false);
  await target.run(
    "INSERT INTO accounts VALUES('occupied','local','occupied',1)",
  );
  await assert.rejects(f.apply(target), {
    code: 'SQLITE_MIGRATION_TARGET_NOT_EMPTY',
  });
  assert.equal(existsSync(sqliteCutoverPath(f.database)), false);
});

test('unsupported versions, product tables, changed columns and invalid signed manifests are refused in review', async (t) => {
  const f = await fixture(t);
  const db = new DatabaseSync(f.database);
  db.exec('CREATE TABLE exa_product_data(id TEXT)');
  assert.throws(() => inspectSqliteMigration(f.options), {
    code: 'SQLITE_MIGRATION_SCHEMA_UNSUPPORTED',
  });
  db.exec('DROP TABLE exa_product_data');
  db.exec('INSERT INTO plk_migrations VALUES(9,1)');
  assert.throws(() => inspectSqliteMigration(f.options), {
    code: 'SQLITE_MIGRATION_VERSION_UNSUPPORTED',
  });
  db.exec('DELETE FROM plk_migrations WHERE version=9');
  db.exec('ALTER TABLE accounts ADD COLUMN accidental TEXT');
  assert.throws(() => inspectSqliteMigration(f.options), {
    code: 'SQLITE_MIGRATION_SCHEMA_UNSUPPORTED',
  });
  db.exec('ALTER TABLE accounts DROP COLUMN accidental');
  // Rebuilding an altered schema is intentionally unsupported; use another fixture to check signatures.
  db.close();
  const other = await fixture(t),
    tamper = new DatabaseSync(other.database);
  tamper.prepare("UPDATE distributions SET manifest=manifest||'x'").run();
  tamper.close();
  assert.throws(() => inspectSqliteMigration(other.options), {
    code: 'SQLITE_MIGRATION_MANIFEST_INVALID',
  });
});

test('SQLite service lock prevents migration and exact live data is never changed', async (t) => {
  const f = await fixture(t),
    target = await f.connect(),
    plan = inspectSqliteMigration(f.options),
    release = acquireServiceLock(join(f.root, 'framework.lock'));
  try {
    await assert.rejects(f.apply(target, plan.planHash), {
      code: 'SERVICE_MUST_BE_STOPPED',
    });
  } finally {
    release();
  }
  assert.equal(existsSync(sqliteCutoverPath(f.database)), false);
  assert.equal(
    inspectSqliteMigration(f.options).sourceDigest,
    plan.sourceDigest,
  );
});

test('import SQL failure rolls back every business row and seals both sides for explicit review', async (t) => {
  const f = await fixture(t),
    target = await f.connect();
  await admin.query(
    `CREATE FUNCTION "${f.schema}".reject_import() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'synthetic'; END $$`,
  );
  await admin.query(
    `CREATE TRIGGER reject_import BEFORE INSERT ON "${f.schema}".audit FOR EACH ROW EXECUTE FUNCTION "${f.schema}".reject_import()`,
  );
  await assert.rejects(f.apply(target), { code: 'POSTGRES_QUERY_FAILED' });
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM accounts',
    ))!.n,
    0,
  );
  assert.equal(
    (await target.get<{ status: string }>(
      'SELECT status FROM compatibility_imports',
    ))!.status,
    'pending',
  );
  assert.throws(() => new SqliteStore(f.database), {
    code: 'SQLITE_CUTOVER_REVIEW_REQUIRED',
  });
  await target.close();
  await assert.rejects(f.connect(false), {
    code: 'POSTGRES_IMPORT_REVIEW_REQUIRED',
  });
});

test('lost COMMIT acknowledgement cannot replay the import or start the old SQLite service', async (t) => {
  const f = await fixture(t),
    target = await f.connect(),
    real = target.transaction.bind(target);
  let calls = 0;
  // First transaction checks emptiness; the second commits the import before the simulated lost response.
  target.transaction = async (work) => {
    const result = await real(work);
    if (++calls === 2) throw new Error('synthetic lost commit acknowledgement');
    return result;
  };
  await assert.rejects(f.apply(target), /synthetic lost commit/);
  assert.equal(
    (await target.get<{ status: string }>(
      'SELECT status FROM compatibility_imports',
    ))!.status,
    'completed',
  );
  assert.equal(
    JSON.parse(readFileSync(sqliteCutoverPath(f.database), 'utf8')).status,
    'pending',
  );
  const review = await reviewSqliteCutover(target, f.options);
  assert.equal(review.committed, true);
  assert.equal(review.sourceRemainsSealed, true);
  assert.throws(() => inspectSqliteMigration(f.options), {
    code: 'SQLITE_CUTOVER_REVIEW_REQUIRED',
  });
  assert.equal(
    (await target.get<{ n: number }>(
      "SELECT count(*)::int AS n FROM audit WHERE action='compatibility.sqlite-imported'",
    ))!.n,
    1,
  );
});

test('operator CLI reviews without a target connection, applies the reviewed hash and reports committed status with private configuration', async (t) => {
  const f = await fixture(t),
    configPath = join(f.root, 'private-config.json');
  writeFileSync(join(f.root, 'signing.pem'), f.options.privateKey);
  writeFileSync(
    join(f.root, 'catalog.json'),
    JSON.stringify(f.options.catalog),
  );
  writeFileSync(
    join(f.root, 'backup-password.txt'),
    'synthetic-compatibility-password\r\n',
  );
  const config = {
    database: 'framework.sqlite',
    issuer: f.options.issuer,
    catalogFile: 'catalog.json',
    signingKeyFile: 'signing.pem',
    backupDirectory: 'backups',
    backupPasswordFile: 'backup-password.txt',
    actor: 'owner',
    reason: 'isolated CLI cutover',
    postgres: { connectionString: connection!, schema: f.schema },
  };
  writeFileSync(configPath, JSON.stringify(config));
  const run = (...args: string[]) =>
    new Promise<string>((done, fail) => {
      const child = spawn(
        process.execPath,
        ['examples/sqlite-postgres.mjs', ...args],
        {
          env: { ...process.env, PLK_SQLITE_MIGRATION_CONFIG_FILE: configPath },
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let output = '',
        error = '';
      child.stdout.on('data', (part) => (output += part));
      child.stderr.on('data', (part) => (error += part));
      child.once('error', fail);
      child.once('close', (code) => {
        if (
          (output + error).includes(connection!) ||
          (output + error).includes(f.options.privateKey)
        ) {
          fail(new Error('CLI_PRIVATE_DATA_EXPOSED'));
          return;
        }
        code === 0 ? done(output) : fail(new Error('CLI_FAILED:' + error));
      });
    });
  const plan = JSON.parse(await run('--review')) as { planHash: string };
  const initialized = await f.connect();
  await initialized.close();
  const applied = JSON.parse(await run('--apply', plan.planHash)) as {
    planHash: string;
  };
  assert.equal(applied.planHash, plan.planHash);
  const status = JSON.parse(await run('--status')) as {
    committed: boolean;
    sourceRemainsSealed: boolean;
  };
  assert.equal(status.committed, true);
  assert.equal(status.sourceRemainsSealed, true);
});
