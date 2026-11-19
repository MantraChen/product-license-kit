import test from 'node:test';
import assert from 'node:assert/strict';
import type { Notification } from '../src/index.js';
import { harness, key } from './helpers.js';

test('events distinguish simultaneous paid orders and preserve their resources across failed delivery', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register();
  const purchase = h.buy(user.accountId);
  const credits = h.buy(user.accountId, 'desktop-rebind');
  const first: Notification[] = [];
  const attempt = await h.framework.dispatchNotifications({ async send(event) { first.push(event); throw new Error('synthetic outage'); } });
  assert.equal(attempt.failed, 3);
  const paid = first.filter(event => event.topic === 'order.fulfilled');
  assert.equal(paid[0]!.createdAt, paid[1]!.createdAt);
  assert.deepEqual(paid.map(event => event.resource!.id).sort(), [purchase.orderId, credits.orderId].sort());
  assert.ok(paid.every(event => event.resource!.kind === 'order' && event.accountId === user.accountId));
  const retried: Notification[] = [];
  assert.equal((await h.framework.dispatchNotifications({ async send(event) { retried.push(event); } })).delivered, 3);
  assert.deepEqual(retried, first);
  assert.equal((await h.framework.dispatchNotifications({ async send() { throw new Error('unexpected resend'); } })).delivered, 0);
});

test('resource insertion failure rolls back payment and rights with the durable event', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register();
  const order = h.framework.createOrder(user.accountId, 'buy-tool-1', key());
  const payment = { method: 'manual-bank', reference: key(), amount: order.offer.amount, currency: order.offer.currency };
  h.store.run("CREATE TRIGGER fail_notification_resource BEFORE INSERT ON outbox_resources WHEN NEW.kind='order' BEGIN SELECT RAISE(ABORT,'synthetic resource write failure'); END");
  assert.throws(() => h.framework.confirmPayment(order.orderId, payment), /synthetic resource write failure/);
  assert.equal(h.framework.orderLifecycle(order.orderId).status, 'pending');
  assert.deepEqual(h.framework.profile(user.accountId).entitlements, []);
  assert.equal(h.store.get<{ n: number }>("SELECT count(*) n FROM outbox WHERE topic='order.fulfilled'")!.n, 0);
  h.store.run('DROP TRIGGER fail_notification_resource');
  h.framework.confirmPayment(order.orderId, payment);
  assert.equal(h.framework.profile(user.accountId).entitlements.length, 1);
  assert.equal(h.store.get<{ resource_id: string }>("SELECT r.resource_id FROM outbox_resources r JOIN outbox o ON o.id=r.event_id WHERE o.topic='order.fulfilled'")!.resource_id, order.orderId);
});

test('legacy events remain unlinked and batch boundaries prevent accidental unbounded sends', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register();
  h.store.run('INSERT INTO outbox(id,topic,account_id,created_at) VALUES(?,?,?,?)', key(), 'order.fulfilled', user.accountId, h.now());
  for (const limit of [0, -1, 101, 1.5, NaN])
    await assert.rejects(h.framework.dispatchNotifications({ async send() { throw new Error('must not send'); } }, limit), /INVALID_NOTIFICATION_LIMIT/);
  const events: Notification[] = [];
  assert.equal((await h.framework.dispatchNotifications({ async send(event) { events.push(event); } }, 1)).delivered, 1);
  assert.equal((await h.framework.dispatchNotifications({ async send(event) { events.push(event); } }, 1)).delivered, 1);
  const legacy = events.find(event => event.topic === 'order.fulfilled')!;
  assert.equal(Object.hasOwn(legacy, 'resource'), false);
  assert.deepEqual(events.find(event => event.topic === 'account.registered')!.resource, { kind: 'account', id: user.accountId });
});

test('finalized distribution events carry only the exact distribution reference', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register(); h.buy(user.accountId);
  const distribution = h.framework.reserveDistribution(user.accountId, 'tool-1', 'release-for-notification', key());
  h.framework.finalizeDistribution(distribution.distributionId, 'b'.repeat(64));
  const events: Notification[] = [];
  await h.framework.dispatchNotifications({ async send(event) { events.push(event); } });
  const ready = events.find(event => event.topic === 'distribution.ready')!;
  assert.deepEqual(ready.resource, { kind: 'distribution', id: distribution.distributionId });
  assert.deepEqual(Object.keys(ready).sort(), ['accountId', 'createdAt', 'id', 'resource', 'topic']);
});
