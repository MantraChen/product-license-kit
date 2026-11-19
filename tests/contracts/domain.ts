import test, { type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { Framework } from '../../src/service.js';
import { AsyncFramework } from '../../src/async-service.js';
import { NotificationNotSentError } from '../../src/core/model.js';
import { sha256, verifyEnvelope } from '../../src/core/crypto.js';
import { createApp } from '../../src/http/app.js';
import { signChallenge } from '../../src/sdk/client.js';
import { key, keyPair } from '../helpers.js';

export interface DomainFixture {
  framework: Framework | AsyncFramework;
  people: { subject: string; proof: string }[];
  setTime(value: number): void;
}
export type DomainFactory = (t: TestContext) => Promise<DomainFixture>;
async function register(h: DomainFixture, index = 0) {
  const person = h.people[index]!;
  const invitation = await h.framework.issueInvitation('local', person.subject);
  return h.framework.register(invitation.ticket, person.proof);
}
async function buy(f: DomainFixture['framework'], accountId: string, offerId = 'buy-tool-1') {
  const order = await f.createOrder(accountId, offerId, key());
  await f.confirmPayment(order.orderId, {
    method: 'bank',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  return order;
}
export async function enrollment(f: DomainFixture['framework'], accountId: string, pair = keyPair()) {
  const challenge = await f.enrollmentChallenge(accountId, 'desktop', pair.publicKey, {
    schema: 'test-v1',
    digest: sha256('synthetic'),
  });
  return { pair, challenge, signature: signChallenge(challenge.message, pair.privateKey) };
}
export async function activate(f: DomainFixture['framework'], accountId: string, pair = keyPair()) {
  const data = await enrollment(f, accountId, pair);
  return { ...data, binding: await f.activate(accountId, data.challenge.challengeId, data.signature, key()) };
}
const rejects = (work: () => unknown, code: string) => assert.rejects(async () => work(), { code });

/** The same observable domain and HTTP contract runs against synchronous SQLite and real async PostgreSQL. */
export function domainContract(label: string, fixture: DomainFactory) {
  test(`${label}: invitation identity, session expiry, logout, disable and identity replacement`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      person = h.people[0]!;
    const first = await f.issueInvitation('local', person.subject),
      second = await f.issueInvitation('local', person.subject);
    await rejects(() => f.register(first.ticket, person.proof), 'INVALID_INVITATION');
    await rejects(() => f.register(second.ticket, h.people[1]!.proof), 'IDENTITY_MISMATCH');
    const a = await f.register(second.ticket, person.proof);
    await rejects(() => f.register(second.ticket, person.proof), 'INVALID_INVITATION');
    assert.equal(await f.authenticate(a.accessToken), a.accountId);
    await f.logout(a.accessToken);
    await rejects(() => f.authenticate(a.accessToken), 'UNAUTHORIZED');
    const b = await f.login('local', person.proof);
    h.setTime(b.expiresAt);
    await rejects(() => f.authenticate(b.accessToken), 'UNAUTHORIZED');
    await f.cleanupExpired();
    await f.setAccountActive(a.accountId, false, 'contract disabled');
    assert.equal(await f.isAccountActive(a.accountId), false);
    await rejects(() => f.login('local', person.proof), 'ACCOUNT_DISABLED');
    await f.setAccountActive(a.accountId, true, 'contract restored');
    await f.assertAccountActive(a.accountId);
    const c = await f.login('local', person.proof);
    await f.changeIdentity(a.accountId, 'local', h.people[1]!.subject, 'contract transfer');
    await rejects(() => f.authenticate(c.accessToken), 'UNAUTHORIZED');
    await rejects(() => f.login('local', person.proof), 'IDENTITY_NOT_REGISTERED');
    assert.equal((await f.login('local', h.people[1]!.proof)).accountId, a.accountId);
  });

  test(`${label}: order command replay, payment provenance, upgrades and credit accounting`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h),
      command = key();
    const order = await f.createOrder(a.accountId, 'buy-tool-1', command);
    assert.deepEqual(await f.createOrder(a.accountId, 'buy-tool-1', command), order);
    await rejects(() => f.createOrder(a.accountId, 'buy-addon-1', command), 'IDEMPOTENCY_CONFLICT');
    const payment = { method: 'bank', reference: key(), amount: order.offer.amount, currency: 'CNY' };
    await rejects(
      () => f.confirmPayment(order.orderId, { ...payment, amount: 1 }),
      'PAYMENT_AMOUNT_MISMATCH',
    );
    assert.equal((await f.confirmPayment(order.orderId, payment)).replayed, false);
    assert.equal((await f.confirmPayment(order.orderId, payment)).replayed, true);
    assert.equal((await f.bestUpgradeOffer(a.accountId, 'tool-2')).id, 'upgrade-tool-1-to-2');
    await buy(f, a.accountId, 'upgrade-tool-1-to-2');
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-2', 'stable'), true);
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-2', 'beta'), false);
    await rejects(() => f.createOrder(a.accountId, 'buy-tool-1', key()), 'EDITION_ALREADY_OWNED');
    await buy(f, a.accountId, 'desktop-rebind');
    const creditKey = key();
    assert.equal((await f.grantCredits(a.accountId, 'desktop', 2, 'contract credit', creditKey)).balance, 3);
    assert.equal((await f.grantCredits(a.accountId, 'desktop', 2, 'contract credit', creditKey)).balance, 3);
    const orders = await f.orders(a.accountId);
    assert.equal(orders.length, 3);
    assert.ok(orders.every((row) => row.status === 'paid'));
    const profile = await f.profile(a.accountId);
    assert.equal((profile.credits[0] as { balance: number }).balance, 3);
  });

  test(`${label}: entitlement import ownership, revocation and explicit beta access`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h),
      b = await register(h, 1);
    const evidence = {
      source: 'contract',
      reference: 'proof-1',
      reason: 'contract evidence',
      betaAccess: true,
    };
    assert.equal((await f.importEntitlement(a.accountId, 'tool-1', evidence)).status, 'imported');
    assert.equal((await f.importEntitlement(a.accountId, 'tool-1', evidence)).status, 'already-owned');
    await rejects(
      () => f.importEntitlement(b.accountId, 'tool-1', evidence),
      'ENTITLEMENT_IMPORT_ALREADY_CLAIMED',
    );
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'beta'), true);
    await f.revokeEntitlement(a.accountId, 'tool-1', 'contract revoked');
    assert.equal((await f.importEntitlement(a.accountId, 'tool-1', evidence)).status, 'revoked');
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'stable'), false);
    await f.setEntitlementAccess(a.accountId, 'tool-1', 'stable', 'contract restored', key());
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'beta'), false);
    await f.setEntitlementAccess(a.accountId, 'tool-1', 'beta', 'contract beta', key());
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'beta'), true);
    await f.setEntitlementAccess(a.accountId, 'tool-1', 'none', 'contract removed', key());
    assert.equal(await f.hasReleaseAccess(a.accountId, 'tool-1', 'stable'), false);
  });

  test(`${label}: order expiry, reviewed late payment and exception apply/refund`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h);
    const old = await f.createOrder(a.accountId, 'buy-tool-1', key());
    h.setTime(old.expiresAt);
    assert.equal((await f.orderLifecycle(old.orderId)).status, 'expired');
    const money = { method: 'bank', reference: key(), amount: old.offer.amount, currency: 'CNY' };
    await rejects(() => f.confirmPayment(old.orderId, money), 'LATE_PAYMENT_REVIEW_REQUIRED');
    assert.equal(await f.expireOrders(), 1);
    assert.equal(await f.expireOrders(), 0);
    const incident = await f.recordPaymentException(old.orderId, money, 'contract reconciliation');
    assert.equal(
      (await f.recordPaymentException(old.orderId, money, 'contract reconciliation')).replayed,
      true,
    );
    await rejects(
      () => f.confirmPayment(old.orderId, money, { latePaymentReason: 'contract reviewed' }),
      'PAYMENT_REFERENCE_REUSED',
    );
    const target = await f.createOrder(a.accountId, 'buy-tool-1', key());
    const apply = { action: 'apply' as const, orderId: target.orderId, reason: 'contract reviewed' };
    assert.equal((await f.resolvePaymentException(incident.id, apply)).status, 'applied');
    assert.equal((await f.resolvePaymentException(incident.id, apply)).replayed, true);
    assert.equal((await f.orderLifecycle(target.orderId)).status, 'paid');
    const cancelled = await f.createOrder(a.accountId, 'buy-addon-1', key());
    await f.cancelOrder(a.accountId, cancelled.orderId);
    await rejects(
      () =>
        f.confirmPayment(cancelled.orderId, { ...money, reference: key(), amount: cancelled.offer.amount }),
      'ORDER_NOT_PENDING',
    );
    const refund = await f.recordPaymentException(
      cancelled.orderId,
      { ...money, reference: key() },
      'contract refund',
    );
    const resolution = {
      action: 'refund' as const,
      refundReference: 'synthetic-refund-1',
      reason: 'contract settled',
    };
    assert.equal((await f.resolvePaymentException(refund.id, resolution)).status, 'refunded');
    assert.equal((await f.resolvePaymentException(refund.id, resolution)).replayed, true);
    assert.equal((await f.paymentExceptions()).length, 2);
    assert.equal(await f.hasReleaseAccess(a.accountId, 'addon-1', 'stable'), false);
  });

  test(`${label}: signed device enrollment, lease, credit reset and stale challenge rejection`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h);
    await buy(f, a.accountId);
    const old = await activate(f, a.accountId),
      challenge = await f.licenseChallenge(old.binding.deviceId, 'tool-1');
    const license = await f.issueLicense(
      challenge.challengeId,
      signChallenge(challenge.message, old.pair.privateKey),
    );
    const claims = verifyEnvelope(license.token, f.signer.publicKey, 'plk-license') as {
      device: string;
      generation: number;
    };
    assert.equal(claims.device, old.binding.deviceId);
    assert.equal(claims.generation, 1);
    await rejects(
      () => f.issueLicense(challenge.challengeId, signChallenge(challenge.message, old.pair.privateKey)),
      'INVALID_CHALLENGE',
    );
    const same = await activate(f, a.accountId, old.pair);
    assert.equal(same.binding.deviceId, old.binding.deviceId);
    assert.equal(same.binding.cost, 'same-device');
    const nextAttempt = await enrollment(f, a.accountId);
    await rejects(
      () => f.activate(a.accountId, nextAttempt.challenge.challengeId, nextAttempt.signature, key()),
      'REBIND_COOLDOWN',
    );
    await f.grantCredits(a.accountId, 'desktop', 2, 'contract reset', key());
    const staleLease = await f.licenseChallenge(old.binding.deviceId, 'tool-1'),
      resetKey = key();
    const reset = await f.resetDevice(a.accountId, 'desktop', old.binding.generation, 'credit', resetKey);
    assert.equal(reset.credits, 1);
    assert.deepEqual(
      await f.resetDevice(a.accountId, 'desktop', old.binding.generation, 'credit', resetKey),
      reset,
    );
    assert.equal((await f.deviceResetStatus(a.accountId, 'desktop')).state, 'reset-pending');
    assert.equal(
      (await f.profile(a.accountId)).bindings[0] &&
        ((await f.profile(a.accountId)).bindings[0] as { reset_pending: number }).reset_pending,
      1,
    );
    await rejects(
      () => f.issueLicense(staleLease.challengeId, signChallenge(staleLease.message, old.pair.privateKey)),
      'INVALID_CHALLENGE',
    );
    await rejects(
      () => f.activate(a.accountId, nextAttempt.challenge.challengeId, nextAttempt.signature, key()),
      'INVALID_CHALLENGE',
    );
    const next = await activate(f, a.accountId);
    assert.equal(next.binding.cost, 'reset');
    assert.equal(next.binding.freeAt, reset.freeAt);
    assert.notEqual(next.binding.deviceId, old.binding.deviceId);
    await f.revokeAccess(a.accountId, 'contract revoke', true);
    assert.equal((await f.deviceResetStatus(a.accountId, 'desktop')).freeAt, reset.freeAt);
    await rejects(() => f.licenseChallenge(next.binding.deviceId, 'tool-1'), 'LICENSE_UNAVAILABLE');
  });

  test(`${label}: free reset deadline, challenge expiry and bad signatures`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h);
    await buy(f, a.accountId);
    const invalid = await enrollment(f, a.accountId);
    await rejects(
      () => f.activate(a.accountId, invalid.challenge.challengeId, 'A'.repeat(86), key()),
      'INVALID_DEVICE_PROOF',
    );
    h.setTime(invalid.challenge.expiresAt);
    await rejects(
      () => f.activate(a.accountId, invalid.challenge.challengeId, invalid.signature, key()),
      'INVALID_CHALLENGE',
    );
    const old = await activate(f, a.accountId);
    h.setTime(old.binding.freeAt);
    const free = await f.resetDevice(a.accountId, 'desktop', old.binding.generation, 'free', key());
    assert.equal(free.cost, 'free');
    assert.equal(free.credits, 0);
    assert.ok(free.freeAt > old.binding.freeAt);
    assert.equal((await activate(f, a.accountId)).binding.cost, 'reset');
  });

  test(`${label}: immutable distribution manifests, current access and stable scoped pagination`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h),
      b = await register(h, 1);
    await buy(f, a.accountId);
    const ids: string[] = [];
    for (let i = 0; i < 3; i++) {
      const row = await f.reserveDistribution(a.accountId, 'tool-1', `release-${i}`, key());
      ids.push(row.distributionId);
      const finalized = await f.finalizeDistribution(row.distributionId, sha256(`artifact-${i}`));
      assert.deepEqual(await f.finalizeDistribution(row.distributionId, sha256(`artifact-${i}`)), finalized);
      assert.equal(
        (
          verifyEnvelope(finalized.manifest, f.signer.publicKey, 'plk-distribution') as {
            distributionId: string;
          }
        ).distributionId,
        row.distributionId,
      );
      await rejects(
        () => f.finalizeDistribution(row.distributionId, sha256('different')),
        'DISTRIBUTION_IMMUTABLE',
      );
    }
    await f.reserveDistribution(a.accountId, 'tool-1', 'unfinished', key());
    const first = await f.distributionsPage(a.accountId, { limit: 2 });
    assert.equal(first.items.length, 2);
    assert.ok(first.nextCursor);
    const second = await f.distributionsPage(a.accountId, { limit: 2, cursor: first.nextCursor });
    assert.equal(second.items.length, 1);
    assert.equal(second.nextCursor, null);
    assert.equal(new Set([...first.items, ...second.items].map((row) => row.id)).size, 3);
    await rejects(
      () => f.distributionsPage(b.accountId, { cursor: first.nextCursor }),
      'INVALID_PAGE_CURSOR',
    );
    const audit = await f.auditPage({ limit: 2 });
    assert.ok(audit.nextCursor);
    assert.equal((await f.auditLog()).length > 3, true);
    await rejects(() => f.ordersPage(a.accountId, { cursor: audit.nextCursor }), 'INVALID_PAGE_CURSOR');
    await f.changeIdentity(a.accountId, 'local', h.people[2]!.subject, 'contract identity');
    assert.deepEqual(JSON.parse((await f.traceDistribution(ids[0]!)).identity_snapshot), {
      provider: 'local',
      subject: h.people[0]!.subject,
    });
    await f.revokeEntitlement(a.accountId, 'tool-1', 'contract rights revoked');
    assert.equal((await f.distributions(a.accountId)).length, 0);
  });

  test(`${label}: outbox retry retains event identity and exact order resource`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      a = await register(h),
      order = await buy(f, a.accountId);
    const observed: { id: string; topic: string; resource?: { kind: string; id: string } }[] = [];
    const failed = await f.dispatchNotifications({
      async send(event) {
        observed.push(event);
        throw new NotificationNotSentError('SYNTHETIC_REJECTION');
      },
    });
    assert.equal(failed.delivered, 0);
    assert.equal(failed.failed, 2);
    // Distributed dispatchers enforce persistent backoff; the SQLite reference dispatcher retries immediately.
    if (f instanceof AsyncFramework) await new Promise((resolve) => setTimeout(resolve, 1100));
    const delivered: string[] = [];
    assert.deepEqual(
      await f.dispatchNotifications({
        async send(event, identity) {
          assert.equal(identity.subject, h.people[0]!.subject);
          delivered.push(event.id);
          if (event.topic === 'order.fulfilled')
            assert.deepEqual(event.resource, { kind: 'order', id: order.orderId });
        },
      }),
      { delivered: 2, failed: 0 },
    );
    assert.deepEqual(
      delivered,
      observed.map((row) => row.id),
    );
    assert.deepEqual(
      await f.dispatchNotifications({
        async send() {
          assert.fail('already delivered');
        },
      }),
      { delivered: 0, failed: 0 },
    );
  });

  test(`${label}: HTTP awaits auth and writes, enforces roles and surfaces domain errors`, async (t) => {
    const h = await fixture(t),
      f = h.framework,
      adminToken = key() + key();
    const app = await createApp(f, { adminToken });
    t.after(() => app.close());
    const adminHeaders = { authorization: `Bearer ${adminToken}` };
    const invite = await app.inject({
      method: 'POST',
      url: '/v1/admin/invitations',
      headers: adminHeaders,
      payload: { provider: 'local', subject: h.people[0]!.subject },
    });
    assert.equal(invite.statusCode, 200);
    const registered = await app.inject({
      method: 'POST',
      url: '/v1/auth/register',
      payload: { ticket: invite.json().ticket, proof: h.people[0]!.proof },
    });
    assert.equal(registered.statusCode, 200);
    const session = registered.json() as { accessToken: string; accountId: string };
    const headers = { authorization: `Bearer ${session.accessToken}`, 'idempotency-key': key() };
    assert.equal((await app.inject({ url: '/v1/me' })).statusCode, 401);
    assert.equal((await app.inject({ url: '/v1/admin/audit', headers })).statusCode, 403);
    assert.equal((await app.inject({ url: '/v1/me', headers })).json().account.id, session.accountId);
    const order = await app.inject({
      method: 'POST',
      url: '/v1/orders',
      headers,
      payload: { offerId: 'buy-tool-1' },
    });
    assert.equal(order.statusCode, 200);
    const orderId = order.json().orderId as string;
    assert.equal(
      (await app.inject({ method: 'POST', url: `/v1/orders/${key()}/cancel`, headers })).statusCode,
      404,
    );
    assert.equal(
      (await app.inject({ method: 'POST', url: `/v1/orders/${orderId}/cancel`, headers })).statusCode,
      200,
    );
    assert.equal((await f.orderLifecycle(orderId)).status, 'cancelled');
    assert.equal(
      (await app.inject({ method: 'POST', url: `/v1/orders/${orderId}/cancel`, headers })).statusCode,
      409,
    );
    const status = `/v1/admin/accounts/${session.accountId}/status`;
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: status,
          headers: adminHeaders,
          payload: { active: false, reason: 'contract disabled' },
        })
      ).statusCode,
      200,
    );
    assert.equal((await app.inject({ url: '/v1/me', headers })).statusCode, 401);
    assert.equal(
      (
        await app.inject({
          method: 'POST',
          url: status,
          headers: adminHeaders,
          payload: { active: true, reason: 'contract restored' },
        })
      ).statusCode,
      200,
    );
    const login = await app.inject({
      method: 'POST',
      url: '/v1/auth/login',
      payload: { provider: 'local', proof: h.people[0]!.proof },
    });
    const loggedIn = { authorization: `Bearer ${login.json().accessToken}` };
    assert.equal(
      (await app.inject({ method: 'POST', url: '/v1/auth/logout', headers: loggedIn })).statusCode,
      200,
    );
    assert.equal((await app.inject({ url: '/v1/me', headers: loggedIn })).statusCode, 401);
  });
}
