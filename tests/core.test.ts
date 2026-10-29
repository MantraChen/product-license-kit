import test from 'node:test';
import assert from 'node:assert/strict';
import { addCalendarMonths, parseCatalog, rebindCost } from '../src/core/model.js';
import { sha256 } from '../src/core/crypto.js';
import { signChallenge, verifyDistribution, verifyLicense } from '../src/sdk/client.js';
import { catalog, harness, key, keyPair } from './helpers.js';

test('calendar months clamp at month end, preserve Beijing local time, and handle leap years', () => {
  assert.equal(new Date(addCalendarMonths(Date.parse('2027-01-31T15:59:00Z'), 3, 480)).toISOString(), '2027-04-30T15:59:00.000Z');
  assert.equal(new Date(addCalendarMonths(Date.parse('2027-11-30T15:30:00Z'), 3, 480)).toISOString(), '2028-02-29T15:30:00.000Z');
  assert.equal(new Date(addCalendarMonths(Date.parse('2027-01-31T18:00:00Z'), 3, 480)).toISOString(), '2027-04-30T18:00:00.000Z');
});
test('free eligibility never expires or accumulates and is preferred to paid credit', () => {
  assert.equal(rebindCost(100, 100000, 9), 'free');
  assert.equal(rebindCost(100, 10, 1), 'credit');
  assert.throws(() => rebindCost(100, 10, 0), /REBIND_COOLDOWN/);
});
test('catalog rejects duplicate identifiers and cross-product upgrade routes', () => {
  const duplicate = catalog(); duplicate.groups.push(duplicate.groups[0]!);
  assert.throws(() => parseCatalog(duplicate), /DUPLICATE_CATALOG_ID/);
  const invalid = catalog(); invalid.offers.find(o => o.kind === 'upgrade')!.requiresEditionId = 'studio-1';
  assert.throws(() => parseCatalog(invalid), /INVALID_UPGRADE_OFFER/);
});
test('registration verifies ticket identity, is single use, and stores token hashes', async t => {
  const h = harness(); t.after(h.close);
  const invitation = h.framework.issueInvitation('local', h.people[0]!.subject);
  await assert.rejects(h.framework.register(invitation.ticket, h.people[1]!.proof), /IDENTITY_MISMATCH/);
  const session = await h.framework.register(invitation.ticket, h.people[0]!.proof);
  assert.equal(h.framework.authenticate(session.accessToken), session.accountId);
  await assert.rejects(h.framework.register(invitation.ticket, h.people[0]!.proof), /INVALID_INVITATION/);
  assert.equal(h.store.get<{ hash: string }>('SELECT hash FROM sessions')!.hash, sha256(session.accessToken));
  assert.equal(h.store.get<{ hash: string }>('SELECT hash FROM invitations')!.hash, sha256(invitation.ticket));
});
test('concurrent registration of one invitation creates one account', async t => {
  const h = harness(); t.after(h.close); const invitation = h.framework.issueInvitation('local', h.people[0]!.subject);
  const results = await Promise.allSettled([1, 2].map(() => h.framework.register(invitation.ticket, h.people[0]!.proof)));
  assert.equal(results.filter(r => r.status === 'fulfilled').length, 1);
  assert.equal(h.store.all('SELECT * FROM accounts').length, 1);
});
test('expired invitation and revoked session fail closed', async t => {
  const h = harness(); t.after(h.close);
  const invitation = h.framework.issueInvitation('local', h.people[0]!.subject);
  h.setTime('2027-01-15T03:01:00Z');
  await assert.rejects(h.framework.register(invitation.ticket, h.people[0]!.proof), /INVALID_INVITATION/);
  const session = await h.register(); h.framework.logout(session.accessToken);
  assert.throws(() => h.framework.authenticate(session.accessToken), /UNAUTHORIZED/);
});
test('paid upgrade adds a perpetual edition without removing old rights', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register();
  assert.throws(() => h.framework.createOrder(accountId, 'upgrade-tool-1-to-2', key()), /UPGRADE_NOT_ELIGIBLE/);
  h.buy(accountId); h.buy(accountId, 'upgrade-tool-1-to-2');
  assert.equal(h.framework.profile(accountId).entitlements.length, 2);
  assert.throws(() => h.framework.createOrder(accountId, 'buy-tool-2', key()), /EDITION_ALREADY_OWNED/);
});
test('payment amounts, currency, duplicate callbacks and reference reuse are checked', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register();
  const order = h.framework.createOrder(accountId, 'buy-tool-1', key());
  const payment = { method: 'manual-bank', reference: key(), amount: 5000, currency: 'CNY' };
  assert.throws(() => h.framework.confirmPayment(order.orderId, { ...payment, amount: 1 }), /PAYMENT_AMOUNT_MISMATCH/);
  assert.throws(() => h.framework.confirmPayment(order.orderId, { ...payment, currency: 'USD' }), /PAYMENT_AMOUNT_MISMATCH/);
  assert.equal(h.framework.confirmPayment(order.orderId, payment).replayed, false);
  assert.equal(h.framework.confirmPayment(order.orderId, payment).replayed, true);
  assert.equal(h.framework.profile(accountId).entitlements.length, 1);
  const another = h.framework.createOrder(accountId, 'desktop-rebind', key());
  assert.throws(() => h.framework.confirmPayment(another.orderId, { ...payment, amount: another.offer.amount }), /PAYMENT_REFERENCE_REUSED/);
  assert.equal(h.framework.profile(accountId).credits.length, 0);
});
test('order idempotency is scoped and rejects changed request payload', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); const command = key();
  const first = h.framework.createOrder(accountId, 'buy-tool-1', command);
  assert.deepEqual(h.framework.createOrder(accountId, 'buy-tool-1', command), first);
  assert.throws(() => h.framework.createOrder(accountId, 'buy-tool-2', command), /IDEMPOTENCY_CONFLICT/);
  assert.equal(h.framework.orders(accountId).length, 1);
});
test('pending payment retains its server-side price snapshot after catalog price changes', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register();
  const order = h.framework.createOrder(accountId, 'buy-tool-1', key());
  h.framework.catalog.offers.find(o => o.id === 'buy-tool-1')!.amount = 9999;
  assert.equal(h.framework.confirmPayment(order.orderId, { method: 'manual-bank', reference: key(), amount: 5000, currency: 'CNY' }).status, 'paid');
});
test('cancelled orders cannot be fulfilled and another account cannot cancel them', async t => {
  const h = harness(); t.after(h.close); const a = await h.register(); const b = await h.register(1);
  const order = h.framework.createOrder(a.accountId, 'buy-tool-1', key());
  assert.throws(() => h.framework.cancelOrder(b.accountId, order.orderId), /ORDER_NOT_FOUND/);
  h.framework.cancelOrder(a.accountId, order.orderId);
  assert.throws(() => h.framework.confirmPayment(order.orderId, { method: 'manual-bank', reference: key(), amount: 5000, currency: 'CNY' }), /ORDER_NOT_PENDING/);
});
test('initial activation starts cooldown; same-device reauthentication never resets it', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId);
  const first = h.activate(accountId);
  assert.equal(first.binding.cost, 'initial');
  assert.equal(new Date(first.binding.freeAt).toISOString(), '2027-04-15T02:30:00.000Z');
  h.setTime('2027-02-10T02:30:00Z'); const same = h.activate(accountId, first.pair);
  assert.equal(same.binding.deviceId, first.binding.deviceId); assert.equal(same.binding.freeAt, first.binding.freeAt);
  assert.equal(same.binding.cost, 'same-device');
  assert.throws(() => h.activate(accountId), /REBIND_COOLDOWN/);
});
test('paid and admin credits bypass cooldown only on successful swap; free is consumed first', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); h.activate(accountId);
  const original = h.framework.profile(accountId).bindings;
  h.buy(accountId, 'desktop-rebind'); assert.deepEqual(h.framework.profile(accountId).bindings, original);
  h.setTime('2027-02-10T02:30:00Z');
  const second = h.activate(accountId); assert.equal(second.binding.cost, 'credit');
  assert.equal(new Date(second.binding.freeAt).toISOString(), '2027-05-10T02:30:00.000Z');
  assert.equal(h.store.get<{ balance: number }>('SELECT balance FROM credits')!.balance, 0);
  h.framework.grantCredits(accountId, 'desktop', 2, 'support exception', key());
  h.setTime('2028-08-20T02:30:00Z'); const third = h.activate(accountId);
  assert.equal(third.binding.cost, 'free');
  assert.equal(h.store.get<{ balance: number }>('SELECT balance FROM credits')!.balance, 2);
  assert.equal(new Date(third.binding.freeAt).toISOString(), '2028-11-20T02:30:00.000Z');
});
test('invalid device proof does not spend credit, change binding or consume challenge', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); h.activate(accountId);
  h.framework.grantCredits(accountId, 'desktop', 1, 'test recovery', key());
  const before = h.framework.profile(accountId); const attempt = h.enrollment(accountId);
  assert.throws(() => h.framework.activate(accountId, attempt.challenge.challengeId,
    signChallenge(attempt.challenge.message, keyPair().privateKey), key()), /INVALID_DEVICE_PROOF/);
  assert.deepEqual(h.framework.profile(accountId), before);
  assert.equal(h.framework.activate(accountId, attempt.challenge.challengeId, attempt.signature, key()).cost, 'credit');
});
test('same activation command replays safely; another key cannot reuse its challenge', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId);
  const attempt = h.enrollment(accountId); const command = key();
  const result = h.framework.activate(accountId, attempt.challenge.challengeId, attempt.signature, command);
  assert.deepEqual(h.framework.activate(accountId, attempt.challenge.challengeId, attempt.signature, command), result);
  assert.throws(() => h.framework.activate(accountId, attempt.challenge.challengeId, attempt.signature, key()), /INVALID_CHALLENGE/);
});
test('challenge cannot be claimed by another account or after expiration', async t => {
  const h = harness(); t.after(h.close); const a = await h.register(); const b = await h.register(1); h.buy(a.accountId); h.buy(b.accountId);
  const attempt = h.enrollment(a.accountId);
  assert.throws(() => h.framework.activate(b.accountId, attempt.challenge.challengeId, attempt.signature, key()), /CHALLENGE_NOT_FOUND/);
  h.setTime('2027-01-15T02:36:00Z');
  assert.throws(() => h.framework.activate(a.accountId, attempt.challenge.challengeId, attempt.signature, key()), /INVALID_CHALLENGE/);
});
test('one device key cannot bind to two users in a shared group', async t => {
  const h = harness(); t.after(h.close); const a = await h.register(); const b = await h.register(1); h.buy(a.accountId); h.buy(b.accountId);
  const first = h.activate(a.accountId);
  assert.throws(() => h.activate(b.accountId, first.pair), /DEVICE_KEY_ALREADY_BOUND/);
});
test('all owned editions share binding; new binding rejects old-device license requests', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); h.buy(accountId, 'upgrade-tool-1-to-2');
  const first = h.activate(accountId);
  h.issue(first.binding.deviceId, first.pair.privateKey); h.issue(first.binding.deviceId, first.pair.privateKey, 'tool-2');
  const pending = h.framework.licenseChallenge(first.binding.deviceId, 'tool-1');
  h.setTime('2027-04-15T02:30:00Z'); h.activate(accountId);
  assert.throws(() => h.issue(first.binding.deviceId, first.pair.privateKey), /LICENSE_UNAVAILABLE/);
  assert.throws(() => h.framework.issueLicense(pending.challengeId, signChallenge(pending.message, first.pair.privateKey)), /INVALID_CHALLENGE|LICENSE_UNAVAILABLE/);
});
test('independent device groups stay isolated across products', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); h.buy(accountId, 'buy-studio-1');
  const desktop = h.activate(accountId); const studio = h.activate(accountId, keyPair(), 'studio');
  assert.equal(h.framework.profile(accountId).bindings.length, 2);
  assert.throws(() => h.framework.licenseChallenge(desktop.binding.deviceId, 'studio-1'), /LICENSE_UNAVAILABLE/);
  h.issue(studio.binding.deviceId, studio.pair.privateKey, 'studio-1');
});
test('client verifies signature, issuer, product, edition, account, device, key and expiration', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); const active = h.activate(accountId);
  const license = h.issue(active.binding.deviceId, active.pair.privateKey);
  const expected = { issuer: 'test-issuer', productId: 'sample-tool', editionId: 'tool-1', accountId,
    deviceId: active.binding.deviceId, devicePublicKey: active.pair.publicKey, now: h.now() };
  assert.equal(verifyLicense(license.token, h.serverKeys.publicKey, expected).ownership, 'perpetual');
  for (const field of ['issuer', 'productId', 'editionId', 'accountId', 'deviceId'] as const) {
    assert.throws(() => verifyLicense(license.token, h.serverKeys.publicKey, { ...expected, [field]: 'wrong' }), /LICENSE_SCOPE_MISMATCH/);
  }
  assert.throws(() => verifyLicense(license.token, h.serverKeys.publicKey, { ...expected, devicePublicKey: keyPair().publicKey }), /LICENSE_SCOPE_MISMATCH/);
  assert.throws(() => verifyLicense(license.token, keyPair().publicKey, expected), /INVALID_ENVELOPE_HEADER|INVALID_SIGNATURE/);
  const parts = license.token.split('.'); parts[1] = Buffer.from('{}').toString('base64url');
  assert.throws(() => verifyLicense(parts.join('.'), h.serverKeys.publicKey, expected), /INVALID_SIGNATURE/);
  assert.throws(() => verifyLicense(license.token, h.serverKeys.publicKey, { ...expected, now: h.now() + 900_000 }), /LICENSE_EXPIRED/);
});
test('license challenge is single use and revocation takes effect on refresh', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId); const active = h.activate(accountId);
  const challenge = h.framework.licenseChallenge(active.binding.deviceId, 'tool-1'); const signature = signChallenge(challenge.message, active.pair.privateKey);
  h.framework.issueLicense(challenge.challengeId, signature);
  assert.throws(() => h.framework.issueLicense(challenge.challengeId, signature), /INVALID_CHALLENGE/);
  h.framework.revokeEntitlement(accountId, 'tool-1', 'refund confirmed manually');
  assert.throws(() => h.issue(active.binding.deviceId, active.pair.privateKey), /LICENSE_UNAVAILABLE/);
});
test('identity reassignment invalidates sessions and devices but retains cooldown and historical attribution', async t => {
  const h = harness(); t.after(h.close); const session = await h.register(); h.buy(session.accountId); const active = h.activate(session.accountId);
  const distribution = h.framework.reserveDistribution(session.accountId, 'tool-1', '1.0.0', key());
  h.framework.changeIdentity(session.accountId, 'local', h.people[1]!.subject, 'verified recovery request');
  assert.throws(() => h.framework.authenticate(session.accessToken), /UNAUTHORIZED/);
  assert.throws(() => h.issue(active.binding.deviceId, active.pair.privateKey), /LICENSE_UNAVAILABLE/);
  assert.equal(JSON.parse(h.framework.traceDistribution(distribution.distributionId).identity_snapshot).subject, h.people[0]!.subject);
  const recovered = await h.framework.login('local', h.people[1]!.proof);
  const same = h.activate(recovered.accountId, active.pair);
  assert.equal(same.binding.cost, 'same-device'); assert.equal(same.binding.freeAt, active.binding.freeAt);
});
test('distribution finalization is immutable and signed manifest detects tampering and cross-account access', async t => {
  const h = harness(); t.after(h.close); const a = await h.register(); const b = await h.register(1); h.buy(a.accountId);
  const reservation = h.framework.reserveDistribution(a.accountId, 'tool-1', '1.0.0', key());
  const bytes = Buffer.from(`console.log('sample'); // ${reservation.marker}`);
  const result = h.framework.finalizeDistribution(reservation.distributionId, sha256(bytes));
  const expected = { distributionId: reservation.distributionId, editionId: 'tool-1', releaseId: '1.0.0' };
  verifyDistribution(result.manifest, h.serverKeys.publicKey, bytes, expected);
  assert.throws(() => verifyDistribution(result.manifest, h.serverKeys.publicKey, Buffer.from('modified'), expected), /DISTRIBUTION_MISMATCH/);
  assert.deepEqual(h.framework.finalizeDistribution(reservation.distributionId, sha256(bytes)), result);
  assert.throws(() => h.framework.finalizeDistribution(reservation.distributionId, sha256('different')), /DISTRIBUTION_IMMUTABLE/);
  assert.equal(h.framework.distributions(b.accountId).length, 0);
  h.framework.revokeEntitlement(a.accountId, 'tool-1', 'operator decision');
  assert.equal(h.framework.distributions(a.accountId).length, 0);
});
test('notification failure never rolls back fulfilled rights; retry sends same durable event ID', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); h.buy(accountId);
  const failed = await h.framework.dispatchNotifications({ async send() { throw new Error('provider unavailable'); } });
  assert.equal(failed.failed, 2); assert.equal(h.framework.profile(accountId).entitlements.length, 1);
  const ids: string[] = [];
  assert.equal((await h.framework.dispatchNotifications({ async send(event) { ids.push(event.id); } })).delivered, 2);
  assert.equal((await h.framework.dispatchNotifications({ async send(event) { ids.push(event.id); } })).delivered, 0);
  assert.equal(new Set(ids).size, 2);
});
test('admin credit grants are idempotent and cannot decrement balances', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register(); const command = key();
  h.framework.grantCredits(accountId, 'desktop', 2, 'approved support case', command);
  assert.equal(h.framework.grantCredits(accountId, 'desktop', 2, 'approved support case', command).balance, 2);
  assert.throws(() => h.framework.grantCredits(accountId, 'desktop', -1, 'invalid request', key()), /INVALID_CREDITS/);
});
