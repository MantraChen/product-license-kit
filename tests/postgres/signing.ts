import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import pg from 'pg';
import { randomUUID } from 'node:crypto';
import { spawn } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { protectPrivatePath } from '../../src/security/private-storage.js';
import {
  mkdtempSync,
  rmSync,
  readFileSync,
  writeFileSync,
  readdirSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { existsSync } from 'node:fs';
import { createServer } from 'node:net';
import { setTimeout as delay } from 'node:timers/promises';
import { PostgresStore } from '../../src/adapters/postgres.js';
import {
  PostgresSigningCoordinator,
  type PostgresSigningOptions,
  type SigningRotationView,
} from '../../src/adapters/postgres-signing.js';
import {
  postgresSigningBackup,
  backupPostgres,
  restorePostgres,
} from '../../src/security/postgres-backup.js';
import { decryptBackup, encryptBackup } from '../../src/security/backup.js';
import { AsyncFramework } from '../../src/async-service.js';
import {
  EnvelopeSigner,
  sha256,
  verifyEnvelope,
} from '../../src/core/crypto.js';
import { LocalIdentityProvider } from '../../src/adapters/local-identity.js';
import { createApp } from '../../src/http/app.js';
import { catalog, key, keyPair } from '../helpers.js';
import { activate } from '../contracts/domain.js';
import type { AsyncStore, SqlValue } from '../../src/core/async-store.js';
import { StorageError } from '../../src/core/async-store.js';
import { postgresMigrations } from '../../src/adapters/postgres-schema.js';
import { SigningKeyRing } from '../../src/security/signing-keyring.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(
  connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1',
  'Use scripts/test-postgres.mjs.',
);
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
async function fixture(t: TestContext) {
  const schema = 'plk_signing_' + randomUUID().replaceAll('-', ''),
    root = mkdtempSync(join(tmpdir(), 'plk-signing-'));
  const store = await PostgresStore.connect({
      connectionString: connection!,
      schema,
    }),
    current = keyPair(),
    next = keyPair();
  const primary = new EnvelopeSigner(current.privateKey),
    candidate = new EnvelopeSigner(next.privateKey),
    contextHash = sha256('synthetic-deployment'),
    namespace = 'signing-tests',
    password = 'synthetic-restore-password-20261118';
  t.after(async () => {
    await store.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
    rmSync(root, { recursive: true, force: true });
  });
  const make = (overrides: Partial<PostgresSigningOptions> = {}) =>
    new PostgresSigningCoordinator(store, {
      namespace,
      contextHash,
      primary,
      additionalKeys: [candidate],
      enabled: true,
      createBackup: postgresSigningBackup(store, {
        password,
        privateKeys: [current.privateKey, next.privateKey],
        directory: join(root, 'backups'),
      }),
      ...overrides,
    });
  const controller = make(),
    a = make({ nodeId: 'node-a', enabled: false }),
    b = make({ nodeId: 'node-b', enabled: false });
  await controller.initialize({
    activeKid: primary.kid,
    requiredNodes: ['node-b', 'node-a'],
    actor: 'synthetic-owner',
    reason: 'isolated deployment',
  });
  const now = async () =>
    (await store.get<{ now: number }>(
      'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now',
    ))!.now;
  const schedule = async () => {
    const at = await now();
    return controller.schedule({
      publicKey: candidate.publicKey,
      notBefore: at + 1200,
      expiresAt: at + 60000,
      actor: 'synthetic-owner',
      reason: 'two key clients verified locally',
      clientsReady: true,
    });
  };
  const due = async (plan: SigningRotationView) => {
    await store.run(
      'UPDATE signing_rotations SET not_before=$1 WHERE id=$2',
      (await now()) - 1,
      plan.id,
    );
  };
  const ready = async (plan: SigningRotationView) => {
    await a.acknowledge(plan.id);
    await b.acknowledge(plan.id);
  };
  const options = {
    store,
    catalog: catalog(),
    signer: primary,
    additionalSigningKeys: [candidate],
    signingContextHash: contextHash,
    providers: [
      new LocalIdentityProvider([{ subject: 'person', proof: key() + key() }]),
    ],
    issuer: namespace,
  };
  return {
    schema,
    root,
    store,
    current,
    next,
    primary,
    candidate,
    contextHash,
    namespace,
    password,
    make,
    controller,
    a,
    b,
    now,
    schedule,
    due,
    ready,
    options,
  };
}

test('PostgreSQL signing policy preserves both earlier migration checksums and requires exact, fresh private-key readiness', async (t) => {
  const f = await fixture(t);
  assert.throws(() => f.make(JSON.parse('{"enabled":"false"}')), {
    name: 'ZodError',
  });
  await assert.rejects(
    AsyncFramework.create({ ...f.options, signingContextHash: '' }),
    { code: 'INVALID_SIGNING_CONTEXT' },
  );
  assert.equal(
    postgresMigrations[0].checksum,
    '98de281788c8b9eedf8b71c0114e432986121fc3e854d35f2c5ab54c8ff90e66',
  );
  assert.equal(
    postgresMigrations[1].checksum,
    'a0cf887e046051febcb04a9decfbdf6c7632993d0e20ce301ebc1df10239b70c',
  );
  const plan = await f.schedule();
  await f.due(plan);
  await f.controller.tick();
  assert.equal((await f.controller.status(plan.id))!.status, 'scheduled');
  await f.a.acknowledge(plan.id);
  await f.controller.tick();
  assert.equal((await f.controller.status(plan.id))!.status, 'scheduled');
  await assert.rejects(
    f.make({ nodeId: 'node-b', additionalKeys: [] }).acknowledge(plan.id),
    { code: 'SIGNING_KEY_UNAVAILABLE' },
  );
  await f.b.acknowledge(plan.id);
  await f.store.run(
    "UPDATE signing_readiness SET proof=replace(proof,substr(proof,1,1),'x') WHERE node_id='node-b'",
  );
  await assert.rejects(f.controller.tick(), {
    code: 'SIGNING_READINESS_INVALID',
  });
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.primary.kid,
  );
  await f.b.acknowledge(plan.id);
  await f.store.run(
    "UPDATE signing_readiness SET expires_at=1 WHERE node_id='node-b'",
  );
  await f.controller.tick();
  assert.equal((await f.controller.status(plan.id))!.status, 'scheduled');
  assert.equal(readdirSync(f.root).length, 0);
  await f.b.acknowledge(plan.id);
  await admin.query(
    `ALTER TABLE "${f.schema}".accounts ADD COLUMN unsupported_host_column TEXT`,
  );
  await assert.rejects(f.controller.tick(), {
    code: 'POSTGRES_BACKUP_SCHEMA_INVALID',
  });
  assert.equal((await f.controller.status(plan.id))!.status, 'paused');
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.primary.kid,
  );
});

test('an API role can lock the signing policy using one update column without permission to activate a key', async (t) => {
  const f = await fixture(t),
    plan = await f.schedule(),
    role = 'plk_signnode_' + randomUUID().replaceAll('-', ''),
    password = key() + key();
  await admin.query(
    `CREATE ROLE "${role}" LOGIN PASSWORD ${pg.escapeLiteral(password)}`,
  );
  let limited: PostgresStore | undefined;
  try {
    await admin.query(`GRANT USAGE ON SCHEMA "${f.schema}" TO "${role}"`);
    await admin.query(
      `GRANT SELECT ON ALL TABLES IN SCHEMA "${f.schema}" TO "${role}"`,
    );
    for (const table of ['signing_policies', 'signing_rotations'])
      await admin.query(
        `GRANT UPDATE(updated_at) ON "${f.schema}".${table} TO "${role}"`,
      );
    await admin.query(
      `GRANT INSERT,UPDATE ON "${f.schema}".signing_readiness TO "${role}"`,
    );
    const url = new URL(connection!);
    url.username = role;
    url.password = password;
    limited = await PostgresStore.connect({
      connectionString: url.href,
      schema: f.schema,
      migrate: false,
    });
    const selected = await limited.transaction((unit) =>
      new SigningKeyRing(f.primary, [f.candidate]).active(
        unit,
        f.namespace,
        f.contextHash,
      ),
    );
    assert.equal(selected.kid, f.primary.kid);
    const coordinator = new PostgresSigningCoordinator(limited, {
      namespace: f.namespace,
      contextHash: f.contextHash,
      primary: f.primary,
      additionalKeys: [f.candidate],
      nodeId: 'node-a',
    });
    await coordinator.acknowledge(plan.id);
    await assert.rejects(
      limited.run(
        'UPDATE signing_policies SET active_kid=$1 WHERE namespace=$2',
        f.candidate.kid,
        f.namespace,
      ),
      { code: 'POSTGRES_QUERY_FAILED', postgresCode: '42501' },
    );
    assert.equal(
      (await f.store.get<{ active_kid: string }>(
        'SELECT active_kid FROM signing_policies',
      ))!.active_kid,
      f.primary.kid,
    );
  } finally {
    await limited?.close();
    for (const table of ['signing_policies', 'signing_rotations'])
      await admin.query(
        `REVOKE UPDATE(updated_at) ON "${f.schema}".${table} FROM "${role}"`,
      );
    await admin.query(
      `REVOKE ALL ON ALL TABLES IN SCHEMA "${f.schema}" FROM "${role}"`,
    );
    await admin.query(`REVOKE ALL ON SCHEMA "${f.schema}" FROM "${role}"`);
    await admin.query(`DROP ROLE "${role}"`);
  }
});

test('two controllers activate once after a real encrypted backup; live HTTP and issuance use the database-selected signer', async (t) => {
  const f = await fixture(t);
  const proof = key() + key(),
    configured = {
      ...f.options,
      providers: [
        new LocalIdentityProvider([{ subject: 'live-person', proof }]),
      ],
    },
    live = await AsyncFramework.create(configured);
  const invitation = await live.issueInvitation('local', 'live-person'),
    registered = await live.register(invitation.ticket, proof),
    order = await live.createOrder(registered.accountId, 'buy-tool-1', key());
  await live.confirmPayment(order.orderId, {
    method: 'manual-bank',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  const device = await activate(live, registered.accountId),
    app = await createApp(live, { adminToken: 'A'.repeat(40) });
  t.after(() => app.close());
  const originalBindings = (await live.profile(registered.accountId)).bindings;
  assert.equal((await app.inject('/v1/signing-key')).json().kid, f.primary.kid);
  const firstChallenge = await live.licenseChallenge(
    device.binding.deviceId,
    'tool-1',
  );
  const { signChallenge } = await import('../../src/sdk/client.js');
  const first = await live.issueLicense(
    firstChallenge.challengeId,
    signChallenge(firstChallenge.message, device.pair.privateKey),
  );
  verifyEnvelope(first.token, f.primary.publicKey, 'plk-license');
  const plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  await Promise.all([f.controller.tick(), f.make().tick()]);
  assert.equal((await f.controller.status(plan.id))!.status, 'completed');
  assert.equal(readdirSync(join(f.root, 'backups')).length, 1);
  assert.equal(
    (await f.store.get<{ n: number }>(
      "SELECT count(*) n FROM audit WHERE action='signing.completed'",
    ))!.n,
    1,
  );
  assert.equal(
    (await app.inject('/v1/signing-key')).json().kid,
    f.candidate.kid,
  );
  const second = await live.licenseChallenge(device.binding.deviceId, 'tool-1'),
    issued = await live.issueLicense(
      second.challengeId,
      signChallenge(second.message, device.pair.privateKey),
    );
  verifyEnvelope(issued.token, f.candidate.publicKey, 'plk-license');
  const stale = await AsyncFramework.create({
    ...configured,
    additionalSigningKeys: [],
  });
  await assert.rejects(stale.currentSigningKey(), {
    code: 'SIGNING_KEY_UNAVAILABLE',
  });
  const noContext = await AsyncFramework.create({
    ...configured,
    signingContextHash: sha256('different'),
  });
  await assert.rejects(noContext.currentSigningKey(), {
    code: 'SIGNING_CONTEXT_CHANGED',
  });
  const reserved = await live.reserveDistribution(
      registered.accountId,
      'tool-1',
      key(),
      key(),
    ),
    artifact = await live.finalizeDistribution(
      reserved.distributionId,
      sha256('new artifact'),
    );
  verifyEnvelope(artifact.manifest, f.candidate.publicKey, 'plk-distribution');
  assert.deepEqual(
    (await live.profile(registered.accountId)).bindings,
    originalBindings,
  );
});

test(
  'the reference PostgreSQL service runs scheduled rotation through authenticated HTTP and shared worker coordination',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      probe = createServer();
    await new Promise<void>((done) => probe.listen(0, '127.0.0.1', done));
    const address = probe.address();
    assert.ok(address && typeof address === 'object');
    const port = address.port;
    await new Promise<void>((done) => probe.close(() => done()));
    const config = join(f.root, 'server.json');
    for (const [name, content] of [
      ['current.pem', f.current.privateKey],
      ['next.pem', f.next.privateKey],
      ['password.key', f.password],
      ['limit.key', key() + key()],
      [
        'identities.json',
        JSON.stringify([{ subject: 'reference-person', proof: key() + key() }]),
      ],
    ]) {
      const path = join(f.root, name!);
      writeFileSync(path, content!, { mode: 0o600 });
      protectPrivatePath(path);
    }
    writeFileSync(
      config,
      JSON.stringify({
        connectionString: connection,
        schema: f.schema,
        caFile: process.env.PLK_TEST_POSTGRES_CA_FILE,
        host: '127.0.0.1',
        port,
        nodeEnv: 'development',
        issuer: f.namespace,
        nodeId: 'node-a',
        contextHash: f.contextHash,
        adminToken: 'A'.repeat(40),
        rateLimitSecretFile: 'limit.key',
        catalogPath: resolve('examples/catalog.json'),
        keyFiles: ['current.pem', 'next.pem'],
        localIdentityPath: 'identities.json',
        rotationEnabled: true,
        backup: {
          directory: 'reference-backups',
          passwordFile: 'password.key',
        },
      }),
      { mode: 0o600 },
    );
    protectPrivatePath(config);
    const child = spawn(
      process.execPath,
      [resolve('examples/postgres-server.mjs')],
      {
        windowsHide: true,
        env: { ...process.env, PLK_POSTGRES_CONFIG_FILE: config },
        stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
      },
    );
    child.stdout?.resume();
    child.stderr?.resume();
    let ended = false;
    const exited = new Promise<void>((done, fail) => {
      child.once('error', fail);
      child.once('close', () => {
        ended = true;
        done();
      });
    });
    const origin = `http://127.0.0.1:${port}`,
      headers = {
        authorization: 'Bearer ' + 'A'.repeat(40),
        'content-type': 'application/json',
      };
    try {
      let ready = false;
      const deadline = Date.now() + 15000;
      while (!ended && Date.now() < deadline) {
        try {
          if (
            (
              await fetch(origin + '/health', {
                signal: AbortSignal.timeout(500),
              })
            ).ok
          ) {
            ready = true;
            break;
          }
        } catch {}
        await delay(100);
      }
      assert.ok(ready, 'REFERENCE_SERVER_NOT_READY');
      assert.equal((await fetch(origin + '/v1/admin/signing')).status, 401);
      const at = await f.now(),
        response = await fetch(origin + '/v1/admin/signing/rotations', {
          method: 'POST',
          headers,
          body: JSON.stringify({
            publicKey: f.candidate.publicKey,
            notBefore: at + 2000,
            expiresAt: at + 20000,
            actor: 'synthetic-api-owner',
            reason: 'reference worker and HTTP verification',
            clientsReady: true,
          }),
        });
      assert.equal(response.status, 200);
      const plan = (await response.json()) as SigningRotationView;
      await f.b.acknowledge(plan.id);
      await f.make({ enabled: false }).tick();
      assert.equal((await f.controller.status(plan.id))!.status, 'scheduled');
      assert.throws(
        () =>
          new PostgresSigningCoordinator(f.store, {
            namespace: f.namespace,
            contextHash: f.contextHash,
            primary: f.primary,
            enabled: true,
          }),
        { code: 'SIGNING_BACKUP_REQUIRED' },
      );
      const readyProof = (await f.store.get<{ proof: string }>(
        'SELECT proof FROM signing_readiness WHERE plan_id=$1 AND node_id=$2',
        plan.id,
        'node-b',
      ))!.proof;
      assert.throws(
        () => verifyEnvelope(readyProof, f.candidate.publicKey, 'plk-license'),
        { code: 'INVALID_ENVELOPE_HEADER' },
      );
      let completed = false;
      while (!ended && Date.now() < deadline) {
        const state = await f.controller.status(plan.id);
        if (state?.status === 'completed') {
          completed = true;
          break;
        }
        await delay(100);
      }
      assert.ok(completed, 'REFERENCE_ROTATION_DID_NOT_COMPLETE');
      assert.equal(
        (
          (await (await fetch(origin + '/v1/signing-key')).json()) as {
            kid: string;
          }
        ).kid,
        f.candidate.kid,
      );
      const status = await (
        await fetch(origin + '/v1/admin/signing', { headers })
      ).text();
      for (const value of [
        'PRIVATE KEY',
        f.password,
        'owner_token',
        'nonce',
        'postgresql://',
      ])
        assert.ok(!status.includes(value));
      assert.equal(readdirSync(join(f.root, 'reference-backups')).length, 1);
      const invalid = await fetch(origin + '/v1/admin/signing/rotations', {
        method: 'POST',
        headers,
        body: JSON.stringify({
          publicKey: f.next.privateKey,
          notBefore: (await f.now()) + 2000,
          expiresAt: (await f.now()) + 20000,
          actor: 'synthetic-api-owner',
          reason: 'reject private signing material',
          clientsReady: true,
        }),
      });
      assert.equal(invalid.status, 400);
      assert.equal(
        ((await invalid.json()) as { error: string }).error,
        'SIGNING_PUBLIC_KEY_REQUIRED',
      );
    } finally {
      if (child.connected) child.send({ type: 'shutdown' });
      await Promise.race([exited, delay(10000)]);
      if (!ended) {
        child.kill();
        await exited;
      }
      assert.ok(ended);
    }
  },
);

test('independent controller processes share one activation and one encrypted backup', async (t) => {
  const f = await fixture(t),
    plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  const config = join(f.root, 'worker.json');
  writeFileSync(
    config,
    JSON.stringify({
      schema: f.schema,
      namespace: f.namespace,
      contextHash: f.contextHash,
      current: f.current.privateKey,
      next: f.next.privateKey,
      directory: join(f.root, 'backups'),
      password: f.password,
      planId: plan.id,
    }),
    { mode: 0o600 },
  );
  protectPrivatePath(config);
  const worker = (nodeId: string) =>
    new Promise<{ pid: number; status: string }>((done, fail) => {
      const child = spawn(
        process.execPath,
        [fileURLToPath(new URL('./signing-worker.js', import.meta.url))],
        {
          windowsHide: true,
          env: {
            ...process.env,
            PLK_SIGNING_TEST_CONFIG: config,
            PLK_SIGNING_TEST_NODE: nodeId,
          },
          stdio: ['ignore', 'pipe', 'pipe'],
        },
      );
      let output = '';
      child.stdout.on('data', (data) => (output += data));
      child.stderr.resume();
      child.once('error', fail);
      child.once('close', (code) => {
        if (code !== 0) fail(new Error('SIGNING_WORKER_FAILED'));
        else
          try {
            done(JSON.parse(output));
          } catch {
            fail(new Error('INVALID_WORKER_RESULT'));
          }
      });
    });
  const results = await Promise.all([worker('node-a'), worker('node-b')]);
  assert.equal(new Set(results.map((row) => row.pid)).size, 2);
  assert.equal((await f.controller.status(plan.id))!.status, 'completed');
  assert.equal(readdirSync(join(f.root, 'backups')).length, 1);
  t.diagnostic(
    JSON.stringify({
      controllers: results.map((row) => row.pid),
      activations: 1,
      encryptedBackups: 1,
    }),
  );
});

test(
  'an in-flight issuance holds the old policy until commit and subsequent transactions select the new key',
  { timeout: 30000 },
  async (t) => {
    const f = await fixture(t),
      proof = key() + key();
    let release!: () => void,
      entered!: () => void,
      prepared!: () => void,
      held = false;
    const hold = new Promise<void>((done) => (release = done)),
      ready = new Promise<void>((done) => (entered = done)),
      backedUp = new Promise<void>((done) => (prepared = done));
    const wrap = (base: AsyncStore): AsyncStore => ({
      ...(base.transactionUnit ? { transactionUnit: true as const } : {}),
      get: async <T>(sql: string, ...values: SqlValue[]) => {
        const row = await base.get<T>(sql, ...values);
        if (
          !held &&
          sql.includes('FROM signing_policies') &&
          sql.includes('FOR SHARE')
        ) {
          held = true;
          entered();
          await hold;
        }
        return row;
      },
      all: <T>(sql: string, ...values: SqlValue[]) =>
        base.all<T>(sql, ...values),
      run: (sql, ...values) => base.run(sql, ...values),
      transaction: (work) => base.transaction((unit) => work(wrap(unit))),
    });
    const framework = await AsyncFramework.create({
        ...f.options,
        store: wrap(f.store),
        providers: [new LocalIdentityProvider([{ subject: 'issuer', proof }])],
      }),
      invite = await framework.issueInvitation('local', 'issuer'),
      account = await framework.register(invite.ticket, proof),
      order = await framework.createOrder(
        account.accountId,
        'buy-tool-1',
        key(),
      );
    await framework.confirmPayment(order.orderId, {
      method: 'manual-bank',
      reference: key(),
      amount: order.offer.amount,
      currency: order.offer.currency,
    });
    const device = await activate(framework, account.accountId),
      challenge = await framework.licenseChallenge(
        device.binding.deviceId,
        'tool-1',
      ),
      { signChallenge } = await import('../../src/sdk/client.js');
    const plan = await f.schedule();
    await f.ready(plan);
    await f.due(plan);
    const issuance = framework.issueLicense(
      challenge.challengeId,
      signChallenge(challenge.message, device.pair.privateKey),
    );
    void issuance.catch(() => {});
    await ready;
    const actual = postgresSigningBackup(f.store, {
        password: f.password,
        privateKeys: [f.current.privateKey, f.next.privateKey],
        directory: join(f.root, 'backups'),
      }),
      controller = f.make({
        createBackup: async (p, signal) => {
          const receipt = await actual(p, signal);
          prepared();
          return receipt;
        },
      }),
      rotation = controller.tick();
    void rotation.catch(() => {});
    try {
      await Promise.race([
        backedUp,
        rotation.then(() => {
          throw new Error('BACKUP_NOT_REACHED');
        }),
      ]);
      await delay(100);
      assert.equal((await f.controller.status(plan.id))!.status, 'running');
      assert.equal(
        (await f.store.get<{ active_kid: string }>(
          'SELECT active_kid FROM signing_policies',
        ))!.active_kid,
        f.primary.kid,
      );
      release();
      const issued = await issuance;
      verifyEnvelope(issued.token, f.primary.publicKey, 'plk-license');
      await rotation;
      const next = await framework.licenseChallenge(
          device.binding.deviceId,
          'tool-1',
        ),
        token = await framework.issueLicense(
          next.challengeId,
          signChallenge(next.message, device.pair.privateKey),
        );
      verifyEnvelope(token.token, f.candidate.publicKey, 'plk-license');
    } finally {
      release();
      await issuance.catch(() => {});
      await rotation.catch(() => {});
    }
  },
);

test('window expiration while backup is in progress retains the verified archive and keeps the old active key', async (t) => {
  const f = await fixture(t),
    plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  let continueWork!: () => void, prepared!: () => void;
  const wait = new Promise<void>((done) => (continueWork = done)),
    started = new Promise<void>((done) => (prepared = done));
  const actual = postgresSigningBackup(f.store, {
    password: f.password,
    privateKeys: [f.current.privateKey, f.next.privateKey],
    directory: join(f.root, 'backups'),
  });
  const controller = f.make({
      createBackup: async (p, signal) => {
        const receipt = await actual(p, signal);
        prepared();
        await wait;
        return receipt;
      },
    }),
    running = controller.tick();
  void running.catch(() => {});
  await Promise.race([
    started,
    running.then(() => {
      throw new Error('BACKUP_NOT_REACHED');
    }),
  ]);
  await f.store.run(
    'UPDATE signing_rotations SET expires_at=1 WHERE id=$1',
    plan.id,
  );
  continueWork();
  await assert.rejects(running, { code: 'SIGNING_LEASE_LOST' });
  assert.equal((await controller.status(plan.id))!.status, 'paused');
  assert.equal(
    (await controller.status(plan.id))!.backup?.reference,
    readdirSync(join(f.root, 'backups'))[0]!.replace('.plkbackup', ''),
  );
  assert.equal(readdirSync(join(f.root, 'backups')).length, 1);
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.primary.kid,
  );
});

test(
  'a long verified backup renews the signing lease and another controller cannot take it over',
  { timeout: 20000 },
  async (t) => {
    const f = await fixture(t),
      plan = await f.schedule();
    await f.ready(plan);
    await f.due(plan);
    let complete!: () => void, prepared!: () => void;
    const hold = new Promise<void>((done) => (complete = done)),
      ready = new Promise<void>((done) => (prepared = done));
    const actual = postgresSigningBackup(f.store, {
        password: f.password,
        privateKeys: [f.current.privateKey, f.next.privateKey],
        directory: join(f.root, 'backups'),
      }),
      controller = f.make({
        leaseMs: 3000,
        backupTimeoutMs: 12000,
        createBackup: async (p, signal) => {
          const receipt = await actual(p, signal);
          prepared();
          await hold;
          return receipt;
        },
      }),
      running = controller.tick();
    void running.catch(() => {});
    try {
      await Promise.race([
        ready,
        running.then(() => {
          throw new Error('BACKUP_NOT_REACHED');
        }),
      ]);
      await delay(3500);
      const live = (await f.store.get<{
          updated_at: number;
          lease_until: number;
        }>(
          'SELECT updated_at,lease_until FROM signing_rotations WHERE id=$1',
          plan.id,
        ))!,
        now = await f.now();
      assert.ok(now > live.updated_at + 3000);
      assert.ok(live.lease_until > now);
      await f.make().tick();
      assert.equal((await f.controller.status(plan.id))!.status, 'running');
      complete();
      await running;
      assert.equal((await f.controller.status(plan.id))!.status, 'completed');
      assert.equal(readdirSync(join(f.root, 'backups')).length, 1);
    } finally {
      complete();
      await running.catch(() => {});
    }
  },
);

test('backup timeout, a stale owner and expired plans never activate or retry external backup work', async (t) => {
  const f = await fixture(t);
  let called = 0;
  const slow = f.make({
    leaseMs: 300,
    backupTimeoutMs: 100,
    createBackup: async () => {
      called++;
      await delay(250);
      throw new Error('late backup failure');
    },
  });
  const plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  await assert.rejects(slow.tick(), { code: 'SIGNING_BACKUP_TIMEOUT' });
  assert.equal((await f.controller.status(plan.id))!.status, 'paused');
  await f.controller.tick();
  assert.equal(called, 1);
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.primary.kid,
  );
  const expired = await f.schedule();
  await f.store.run(
    'UPDATE signing_rotations SET not_before=1,expires_at=2 WHERE id=$1',
    expired.id,
  );
  await f.controller.tick();
  assert.equal((await f.controller.status(expired.id))!.status, 'expired');
  const stranded = await f.schedule();
  await f.store.run(
    "UPDATE signing_rotations SET status='running',owner_token=$1,lease_until=1 WHERE id=$2",
    randomUUID(),
    stranded.id,
  );
  await f.controller.tick();
  assert.equal(
    (await f.controller.status(stranded.id))!.lastError,
    'SIGNING_LEASE_EXPIRED',
  );
  await delay(260);
  assert.equal(called, 1);
});

test('activation audit failure rolls back the policy and a lost commit acknowledgement never repeats the backup', async (t) => {
  const f = await fixture(t),
    plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  await admin.query(
    `CREATE FUNCTION "${f.schema}".reject_rotation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='signing.completed' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$`,
  );
  await admin.query(
    `CREATE TRIGGER reject_rotation BEFORE INSERT ON "${f.schema}".audit FOR EACH ROW EXECUTE FUNCTION "${f.schema}".reject_rotation()`,
  );
  await assert.rejects(f.controller.tick());
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.primary.kid,
  );
  assert.equal((await f.controller.status(plan.id))!.status, 'paused');
  await admin.query(`DROP TRIGGER reject_rotation ON "${f.schema}".audit`);
  const next = await f.schedule();
  await f.ready(next);
  await f.due(next);
  let lost = false;
  const proxy: AsyncStore = {
    get: <T>(sql: string, ...values: SqlValue[]) =>
      f.store.get<T>(sql, ...values),
    all: <T>(sql: string, ...values: SqlValue[]) =>
      f.store.all<T>(sql, ...values),
    run: (sql, ...values) => f.store.run(sql, ...values),
    transaction: async (work) => {
      let completes = false;
      const result = await f.store.transaction((unit) =>
        work({
          ...unit,
          transactionUnit: true,
          get: <T>(sql: string, ...values: SqlValue[]) =>
            unit.get<T>(sql, ...values),
          all: <T>(sql: string, ...values: SqlValue[]) =>
            unit.all<T>(sql, ...values),
          run: (sql, ...values) => {
            if (sql.includes("status='completed'")) completes = true;
            return unit.run(sql, ...values);
          },
          transaction: unit.transaction.bind(unit),
        }),
      );
      if (completes && !lost) {
        lost = true;
        throw new StorageError('TRANSACTION_COMMIT_UNCERTAIN');
      }
      return result;
    },
  };
  const controller = new PostgresSigningCoordinator(proxy, {
    namespace: f.namespace,
    contextHash: f.contextHash,
    primary: f.primary,
    enabled: true,
    createBackup: postgresSigningBackup(f.store, {
      password: f.password,
      privateKeys: [f.current.privateKey, f.next.privateKey],
      directory: join(f.root, 'uncertain-backups'),
    }),
  });
  await assert.rejects(controller.tick(), {
    code: 'TRANSACTION_COMMIT_UNCERTAIN',
  });
  assert.equal((await controller.status(next.id))!.status, 'completed');
  await controller.tick();
  assert.equal(readdirSync(join(f.root, 'uncertain-backups')).length, 1);
  assert.equal(
    (await f.store.get<{ active_kid: string }>(
      'SELECT active_kid FROM signing_policies',
    ))!.active_kid,
    f.candidate.kid,
  );
});

test('encrypted PostgreSQL restore preserves paid rights, fences unfinished work and refuses occupied targets, altered bytes and implicit key rollback', async (t) => {
  const f = await fixture(t),
    proof = key() + key(),
    framework = await AsyncFramework.create({
      ...f.options,
      providers: [
        new LocalIdentityProvider([{ subject: 'restore-person', proof }]),
      ],
    });
  const expectedDirectory = join(f.root, 'captured-destination'),
    backupOptions = {
      password: f.password,
      privateKeys: [f.current.privateKey, f.next.privateKey],
      directory: expectedDirectory,
    };
  const snapshotting = backupPostgres(f.store, backupOptions);
  backupOptions.directory = join(f.root, 'unexpected-destination');
  const independent = await snapshotting;
  assert.ok(independent.path.startsWith(expectedDirectory));
  assert.ok(!existsSync(backupOptions.directory));
  assert.ok(!('state' in independent));
  const invitation = await framework.issueInvitation('local', 'restore-person'),
    registered = await framework.register(invitation.ticket, proof),
    order = await framework.createOrder(
      registered.accountId,
      'buy-tool-1',
      key(),
    );
  await framework.confirmPayment(order.orderId, {
    method: 'manual-bank',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  const plan = await f.schedule();
  await f.ready(plan);
  await f.due(plan);
  await f.controller.tick();
  const completed = (await f.controller.status(plan.id))!,
    path = join(f.root, 'backups', completed.backup!.reference + '.plkbackup'),
    bundle = readFileSync(path);
  assert.equal(sha256(bundle), completed.backup!.sha256);
  assert.ok(!bundle.includes(Buffer.from(f.current.privateKey)));
  const targetSchema = 'plk_restore_' + randomUUID().replaceAll('-', ''),
    target = await PostgresStore.connect({
      connectionString: connection!,
      schema: targetSchema,
    });
  t.after(async () => {
    await target.close();
    await admin.query(`DROP SCHEMA "${targetSchema}" CASCADE`);
  });
  const options = {
    actor: 'restore-operator',
    reason: 'isolated verified recovery',
    expectedPolicies: {
      [f.namespace]: { kid: f.primary.kid, contextHash: f.contextHash },
    },
  };
  await assert.rejects(
    restorePostgres(target, bundle, f.password, {
      ...options,
      expectedPolicies: {
        [f.namespace]: { kid: f.candidate.kid, contextHash: f.contextHash },
      },
    }),
    { code: 'POSTGRES_RESTORE_POLICY_REVIEW_REQUIRED' },
  );
  const damaged = Buffer.from(bundle);
  damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  await assert.rejects(restorePostgres(target, damaged, f.password, options), {
    code: 'BACKUP_AUTH_FAILED',
  });
  const result = await restorePostgres(target, bundle, f.password, options);
  assert.equal(result.pausedPlans, 1);
  assert.ok(result.pausedTasks > 0);
  assert.equal(
    (await target.get<{ n: number }>(
      "SELECT count(*) n FROM orders WHERE status='paid'",
    ))!.n,
    1,
  );
  for (const table of [
    'sessions',
    'invitations',
    'challenges',
    'signing_readiness',
  ])
    assert.equal(
      (await target.get<{ n: number }>(`SELECT count(*) n FROM ${table}`))!.n,
      0,
    );
  assert.equal(
    (await target.get<{ status: string }>(
      'SELECT status FROM signing_rotations WHERE id=$1',
      plan.id,
    ))!.status,
    'paused',
  );
  assert.equal(
    (await target.get<{ n: number }>(
      "SELECT count(*) n FROM task_jobs WHERE state IN ('pending','sending','leased')",
    ))!.n,
    0,
  );
  await assert.rejects(restorePostgres(target, bundle, f.password, options), {
    code: 'POSTGRES_RESTORE_TARGET_NOT_EMPTY',
  });
  const decoded = decryptBackup(bundle, f.password);
  assert.ok(decoded['postgres-state.json']);
  const state = JSON.parse(decoded['postgres-state.json']!.toString('utf8'));
  state.migrations[0].checksum = '0'.repeat(64);
  decoded['postgres-state.json'] = Buffer.from(JSON.stringify(state));
  await assert.rejects(
    restorePostgres(
      target,
      encryptBackup(decoded, f.password),
      f.password,
      options,
    ),
    { code: 'POSTGRES_BACKUP_MIGRATIONS_MISMATCH' },
  );
});
