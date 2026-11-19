import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomUUID } from 'node:crypto';
import pg from 'pg';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { AsyncFramework } from '../../src/async-service.js';
import { LocalIdentityProvider } from '../../src/adapters/local-identity.js';
import { EnvelopeSigner } from '../../src/core/crypto.js';
import { sha256 } from '../../src/core/crypto.js';
import { StorageError, type AsyncStore } from '../../src/core/async-store.js';
import { createApp } from '../../src/http/app.js';
import { catalog, key, keyPair } from '../helpers.js';
import { domainContract, enrollment, activate } from '../contracts/domain.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1', 'Use scripts/test-postgres.mjs.');
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
async function fixture(t: TestContext) {
  const schema = `plk_domain_${randomUUID().replaceAll('-', '')}`;
  const store = await PostgresStore.connect({ connectionString: connection!, schema });
  t.after(async () => {
    await store.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
  });
  let now = Date.parse('2027-01-15T02:30:00Z');
  const people = [1, 2, 3].map((n) => ({ subject: `test-person-${n}`, proof: key() + key() }));
  const options = {
    store,
    catalog: catalog(),
    signer: new EnvelopeSigner(keyPair().privateKey),
    providers: [new LocalIdentityProvider(people)],
    issuer: 'test-issuer',
    now: () => now,
  };
  const framework = await AsyncFramework.create(options);
  const register = async (index = 0, f = framework) => {
    const person = people[index]!,
      invitation = await f.issueInvitation('local', person.subject);
    return f.register(invitation.ticket, person.proof);
  };
  return {
    store,
    framework,
    options,
    people,
    register,
    setTime: (value: number) => {
      now = value;
    },
  };
}
domainContract('PostgreSQL domain contract', fixture);

test('concurrent domain commands and payments have one durable result across separate framework instances', async (t) => {
  const h = await fixture(t),
    a = await h.register(),
    b = await AsyncFramework.create(h.options),
    command = key();
  const orders = await Promise.all([
    h.framework.createOrder(a.accountId, 'buy-tool-1', command),
    b.createOrder(a.accountId, 'buy-tool-1', command),
  ]);
  assert.deepEqual(orders[0], orders[1]);
  const order = orders[0]!,
    payment = { method: 'bank', reference: key(), amount: order.offer.amount, currency: 'CNY' };
  const paid = await Promise.all([
    h.framework.confirmPayment(order.orderId, payment),
    b.confirmPayment(order.orderId, payment),
  ]);
  assert.deepEqual(paid.map((row) => row.replayed).sort(), [false, true]);
  assert.equal(
    (await h.store.get<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='payment.confirmed'"))?.n,
    1,
  );
  const creditKey = key();
  const credits = await Promise.all([
    h.framework.grantCredits(a.accountId, 'desktop', 1, 'concurrent grant', creditKey),
    b.grantCredits(a.accountId, 'desktop', 1, 'concurrent grant', creditKey),
  ]);
  assert.deepEqual(credits, [{ balance: 1 }, { balance: 1 }]);
  const first = await activate(h.framework, a.accountId),
    attempts = [await enrollment(h.framework, a.accountId), await enrollment(b, a.accountId)];
  const results = await Promise.allSettled(
    attempts.map((attempt, i) =>
      [h.framework, b][i]!.activate(a.accountId, attempt.challenge.challengeId, attempt.signature, key()),
    ),
  );
  assert.equal(results.filter((row) => row.status === 'fulfilled').length, 1);
  const failure = results.find((row) => row.status === 'rejected') as PromiseRejectedResult;
  assert.equal(failure.reason.code, 'REBIND_COOLDOWN');
  const state = await h.framework.deviceResetStatus(a.accountId, 'desktop');
  assert.equal(state.credits, 0);
  assert.equal(state.generation, first.binding.generation + 1);
});

test('one receipt cannot fulfill two concurrent orders or reserve an exception and fulfill an order', async (t) => {
  const h = await fixture(t),
    a = await h.register();
  const orders = [
    await h.framework.createOrder(a.accountId, 'buy-tool-1', key()),
    await h.framework.createOrder(a.accountId, 'buy-tool-1', key()),
  ];
  const payment = { method: 'bank', reference: key(), amount: 5000, currency: 'CNY' };
  const results = await Promise.allSettled(
    orders.map((order) => h.framework.confirmPayment(order.orderId, payment)),
  );
  assert.equal(results.filter((row) => row.status === 'fulfilled').length, 1);
  assert.equal(
    (results.find((row) => row.status === 'rejected') as PromiseRejectedResult).reason.code,
    'PAYMENT_REFERENCE_REUSED',
  );
  const other = await h.register(1),
    target = await h.framework.createOrder(other.accountId, 'buy-tool-1', key());
  const next = { ...payment, reference: key() };
  const race = await Promise.allSettled([
    h.framework.confirmPayment(target.orderId, next),
    h.framework.recordPaymentException(target.orderId, next, 'concurrent reservation'),
  ]);
  assert.equal(race.filter((row) => row.status === 'fulfilled').length, 1);
  assert.equal(
    (race.find((row) => row.status === 'rejected') as PromiseRejectedResult).reason.code,
    'PAYMENT_REFERENCE_REUSED',
  );
});

test('a shared invitation is consumed once after parallel external verification', async (t) => {
  const h = await fixture(t),
    person = h.people[0]!,
    invite = await h.framework.issueInvitation('local', person.subject);
  const result = await Promise.allSettled([
    h.framework.register(invite.ticket, person.proof),
    h.framework.register(invite.ticket, person.proof),
  ]);
  assert.equal(result.filter((row) => row.status === 'fulfilled').length, 1);
  assert.equal(
    (result.find((row) => row.status === 'rejected') as PromiseRejectedResult).reason.code,
    'INVALID_INVITATION',
  );
  assert.equal((await h.store.get<{ n: number }>('SELECT count(*) AS n FROM accounts'))?.n, 1);
  assert.equal((await h.store.get<{ n: number }>('SELECT count(*) AS n FROM sessions'))?.n, 1);
});

test('host-owned transactions compose async business effects and roll back without retrying external I/O', async (t) => {
  const h = await fixture(t),
    a = await h.register(),
    error = new Error('host rollback');
  await assert.rejects(
    h.store.transaction(async (unit) => {
      await assert.rejects(AsyncFramework.create({ ...h.options, store: unit }), {
        code: 'ROOT_STORE_REQUIRED',
      });
      const scoped = h.framework.using(unit);
      await scoped.grantCredits(a.accountId, 'desktop', 2, 'host transaction', key());
      await scoped.createOrder(a.accountId, 'buy-tool-1', key());
      await assert.rejects(scoped.login('local', h.people[0]!.proof), { code: 'EXTERNAL_IO_IN_TRANSACTION' });
      await assert.rejects(
        scoped.dispatchNotifications({
          async send() {
            assert.fail('no network I/O');
          },
        }),
        { code: 'EXTERNAL_IO_IN_TRANSACTION' },
      );
      throw error;
    }),
    (thrown) => thrown === error,
  );
  assert.equal((await h.framework.profile(a.accountId)).credits.length, 0);
  assert.equal((await h.framework.orders(a.accountId)).length, 0);
});

test('database-only retries roll back first attempts, verify identity once and refuse uncertain replay', async (t) => {
  const h = await fixture(t);
  let fail = false,
    retries = 0,
    verifies = 0,
    uncertain = false;
  const wrapped: AsyncStore = {
    get: h.store.get.bind(h.store),
    all: h.store.all.bind(h.store),
    run: h.store.run.bind(h.store),
    transaction: (work) =>
      h.store.transaction(async (unit) => {
        const result = await work(unit);
        if (fail) {
          fail = false;
          retries++;
          throw new StorageError('TRANSACTION_RETRY_REQUIRED', '40001');
        }
        if (uncertain) {
          uncertain = false;
          throw new StorageError('TRANSACTION_COMMIT_UNCERTAIN');
        }
        return result;
      }),
  };
  const provider = {
    name: 'local',
    async verify() {
      verifies++;
      return { provider: 'local', subject: h.people[0]!.subject };
    },
  };
  const f = await AsyncFramework.create({ ...h.options, store: wrapped, providers: [provider] });
  const invite = await f.issueInvitation('local', h.people[0]!.subject);
  fail = true;
  const a = await f.register(invite.ticket, 'synthetic-proof');
  assert.equal(verifies, 1);
  assert.equal(retries, 1);
  assert.equal(
    (await h.store.get<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='account.registered'"))
      ?.n,
    1,
  );
  fail = true;
  const order = await f.createOrder(a.accountId, 'buy-tool-1', key());
  assert.equal(retries, 2);
  assert.equal((await f.orders(a.accountId)).length, 1);
  assert.ok(order.orderId);
  uncertain = true;
  await assert.rejects(f.grantCredits(a.accountId, 'desktop', 1, 'uncertain injected', key()), {
    code: 'TRANSACTION_COMMIT_UNCERTAIN',
  });
  assert.equal((await f.profile(a.accountId)).credits.length, 0);
  assert.equal(retries, 2);
});

test('HTTP exposes sanitized retry and uncertain storage status without leaking SQL or credentials', async (t) => {
  const h = await fixture(t),
    app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(() => app.close());
  const original = h.framework.authenticate.bind(h.framework);
  for (const code of [
    'TRANSACTION_RETRY_REQUIRED',
    'TRANSACTION_COMMIT_UNCERTAIN',
    'POSTGRES_RESULT_UNCERTAIN',
    'POSTGRES_QUERY_FAILED',
  ]) {
    h.framework.authenticate = async () => {
      throw new StorageError(code, '40001');
    };
    const response = await app.inject({ url: '/v1/me', headers: { authorization: `Bearer ${key()}` } });
    assert.equal(response.statusCode, 503);
    assert.equal(response.json().retryable, code === 'TRANSACTION_RETRY_REQUIRED');
    assert.equal(response.json().error, code.includes('UNCERTAIN') ? code : 'STORAGE_UNAVAILABLE');
    assert.equal(response.headers['retry-after'], code === 'TRANSACTION_RETRY_REQUIRED' ? '1' : undefined);
    assert.equal(response.body.includes('40001'), false);
  }
  h.framework.authenticate = original;
});

test('async calls snapshot mutable evidence, payment, fingerprint, resolution and catalog before yielding', async (t) => {
  const h = await fixture(t),
    a = await h.register(),
    source = catalog();
  const f = await AsyncFramework.create({ ...h.options, catalog: source });
  source.offers[0]!.amount = 1;
  assert.equal(f.catalog.offers[0]!.amount, 5000);
  assert.ok(Object.isFrozen(f.catalog.offers));
  const evidence = {
    source: 'snapshot',
    reference: 'original-proof',
    reason: 'original evidence',
    betaAccess: false,
  };
  const imported = f.importEntitlement(a.accountId, 'tool-1', evidence);
  evidence.reference = 'mutated';
  evidence.betaAccess = true;
  await imported;
  assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'beta'), false);
  assert.equal(
    (await h.store.get<{ reference: string }>('SELECT reference FROM entitlement_imports'))?.reference,
    'original-proof',
  );
  const fingerprint = { schema: 'test-v1', digest: sha256('original') },
    pair = keyPair();
  const enrolled = f.enrollmentChallenge(a.accountId, 'desktop', pair.publicKey, fingerprint);
  fingerprint.digest = sha256('mutated');
  const challenge = await enrolled;
  assert.equal(JSON.parse(challenge.message)[5].fingerprint.digest, sha256('original'));
  const order = await f.createOrder(a.accountId, 'buy-addon-1', key());
  const payment = {
    method: 'bank',
    reference: 'original-payment',
    amount: order.offer.amount,
    currency: 'CNY',
  };
  const paid = f.confirmPayment(order.orderId, payment);
  payment.reference = 'mutated';
  payment.amount = 1;
  await paid;
  assert.equal(
    (
      await h.store.get<{ payment_reference: string }>(
        'SELECT payment_reference FROM orders WHERE id=$1',
        order.orderId,
      )
    )?.payment_reference,
    'original-payment',
  );
  const extra = await f.recordPaymentException(
    order.orderId,
    { method: 'bank', reference: 'extra-payment', amount: 2000, currency: 'CNY' },
    'extra receipt',
  );
  const resolution = {
    action: 'refund' as const,
    refundReference: 'original-refund',
    reason: 'original resolution',
  };
  const resolved = f.resolvePaymentException(extra.id, resolution);
  resolution.refundReference = 'mutated';
  await resolved;
  assert.equal(
    JSON.parse(
      (await h.store.get<{ resolution: string }>(
        'SELECT resolution FROM payment_exceptions WHERE id=$1',
        extra.id,
      ))!.resolution,
    ).refundReference,
    'original-refund',
  );
});

test('outbox resource failures roll back all payment effects and current host policy blocks replay', async (t) => {
  const h = await fixture(t),
    a = await h.register();
  let rejectResource = false,
    active = true;
  const wrapped: AsyncStore = {
    get: h.store.get.bind(h.store),
    all: h.store.all.bind(h.store),
    run: h.store.run.bind(h.store),
    transaction: (work) =>
      h.store.transaction(async (unit) => {
        const wrap = (current: AsyncStore): AsyncStore => ({
          transactionUnit: true,
          get: current.get.bind(current),
          all: current.all.bind(current),
          run: (sql, ...values) => {
            if (rejectResource && sql.startsWith('INSERT INTO outbox_resources'))
              throw new Error('synthetic resource failure');
            return current.run(sql, ...values);
          },
          transaction: (callback) => current.transaction((child) => callback(wrap(child))),
        });
        return work(wrap(unit));
      }),
  };
  const f = await AsyncFramework.create({ ...h.options, store: wrapped, accountEnabled: () => active });
  const command = key(),
    order = await f.createOrder(a.accountId, 'buy-tool-1', command);
  const payment = { method: 'bank', reference: key(), amount: 5000, currency: 'CNY' };
  rejectResource = true;
  await assert.rejects(f.confirmPayment(order.orderId, payment), /synthetic resource failure/);
  assert.equal((await f.orderLifecycle(order.orderId)).status, 'pending');
  assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'stable'), false);
  assert.equal(
    (await h.store.get<{ n: number }>("SELECT count(*) AS n FROM audit WHERE action='payment.confirmed'"))?.n,
    0,
  );
  rejectResource = false;
  await f.confirmPayment(order.orderId, payment);
  const old = await activate(f, a.accountId),
    challenge = await f.licenseChallenge(old.binding.deviceId, 'tool-1');
  active = false;
  await assert.rejects(f.createOrder(a.accountId, 'buy-tool-1', command), { code: 'ACCOUNT_DISABLED' });
  await assert.rejects(f.issueLicense(challenge.challengeId, 'A'.repeat(86)), { code: 'ACCOUNT_DISABLED' });
});

test('async initialization backfills only missing pending deadlines and rejects incompatible persisted catalog data', async (t) => {
  const h = await fixture(t),
    a = await h.register();
  const order = await h.framework.createOrder(a.accountId, 'buy-tool-1', key());
  await h.store.run('DELETE FROM order_deadlines WHERE order_id=$1', order.orderId);
  const reopened = await AsyncFramework.create(h.options);
  assert.equal((await reopened.orderLifecycle(order.orderId)).expiresAt, order.expiresAt);
  await AsyncFramework.create(h.options);
  assert.equal((await h.store.get<{ n: number }>('SELECT count(*) AS n FROM order_deadlines'))?.n, 1);
  await h.store.run('INSERT INTO entitlements VALUES($1,$2,NULL,1)', a.accountId, 'removed-edition');
  await assert.rejects(AsyncFramework.create(h.options), { code: 'CATALOG_REMOVES_EXISTING_ENTITLEMENT' });
  await h.store.run(
    'DELETE FROM entitlements WHERE account_id=$1 AND edition_id=$2',
    a.accountId,
    'removed-edition',
  );
  await reopened.setEntitlementAccess(a.accountId, 'tool-1', 'stable', 'test compatibility', key());
  await activate(reopened, a.accountId);
  await h.store.run('DELETE FROM entitlements WHERE account_id=$1', a.accountId);
  const next = catalog();
  next.groups = next.groups.filter((row) => row.id === 'studio');
  next.products = next.products.filter((row) => row.groupId === 'studio');
  next.editions = next.editions.filter((row) => row.productId === 'sample-studio');
  next.offers = next.offers.filter((row) => row.id === 'buy-studio-1');
  await assert.rejects(AsyncFramework.create({ ...h.options, catalog: next }), {
    code: 'CATALOG_REMOVES_EXISTING_DEVICE_GROUP',
  });
});
