import test from 'node:test';
import assert from 'node:assert/strict';
import { harness, key } from './helpers.js';

test('expiry is enforced at the boundary before cleanup; late payments require explicit review', async t => {
  const h = harness(); t.after(h.close);
  const a = await h.register();
  const order = h.framework.createOrder(a.accountId, 'buy-tool-1', key());
  const payment = {method:'bank', reference:key(), amount:order.offer.amount, currency:order.offer.currency};
  h.setTime(new Date(order.expiresAt).toISOString());
  assert.equal(h.framework.orders(a.accountId)[0]!.status, 'expired');
  assert.throws(() => h.framework.confirmPayment(order.orderId, payment), /LATE_PAYMENT_REVIEW_REQUIRED/);
  assert.equal(h.framework.expireOrders(), 1);
  assert.equal(h.framework.expireOrders(), 0);
  assert.throws(() => h.framework.confirmPayment(order.orderId, payment, {latePaymentReason:' '}), /LATE_PAYMENT_REVIEW_REQUIRED/);
  assert.equal(h.framework.confirmPayment(order.orderId, payment, {latePaymentReason:'Bank receipt manually reconciled'}).replayed, false);
  assert.equal(h.framework.confirmPayment(order.orderId, payment).replayed, true);
  assert.equal(h.framework.orders(a.accountId)[0]!.status, 'paid');
  assert.equal(h.store.all("SELECT * FROM audit WHERE action='order.expired'").length, 1);
});

test('manual cancellation cannot be bypassed as a late payment; reference and eligibility remain enforced', async t => {
  const h = harness(); t.after(h.close);
  const a = await h.register();
  const order = h.framework.createOrder(a.accountId, 'buy-tool-1', key());
  h.framework.cancelOrder(a.accountId, order.orderId);
  h.setTime(new Date(order.expiresAt + 1).toISOString());
  h.framework.expireOrders();
  assert.equal(h.framework.orders(a.accountId)[0]!.status, 'cancelled');
  assert.throws(() => h.framework.confirmPayment(order.orderId, {method:'bank', reference:key(), amount:order.offer.amount, currency:order.offer.currency}, {latePaymentReason:'reviewed'}), /ORDER_NOT_PENDING/);
});
