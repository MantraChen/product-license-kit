import test from 'node:test';
import assert from 'node:assert/strict';
import { harness, key, keyPair } from './helpers.js';
import { createApp } from '../src/http/app.js';
import { signChallenge } from '../src/sdk/client.js';

test('free reset revokes old challenges and renewals, preserves cooldown and pays for exactly one new binding', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.buy(accountId);
  const old = h.activate(accountId);
  h.setTime('2027-04-15T02:30:00Z');
  const enrollment = h.enrollment(accountId);
  const lease = h.framework.licenseChallenge(old.binding.deviceId, 'tool-1');
  const reset = h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'free', key());
  assert.equal(reset.freeAt, Date.parse('2027-07-15T02:30:00Z'));
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').state, 'reset-pending');
  assert.throws(() => h.framework.licenseChallenge(old.binding.deviceId, 'tool-1'), /LICENSE_UNAVAILABLE/);
  assert.throws(() => h.framework.issueLicense(lease.challengeId, signChallenge(lease.message, old.pair.privateKey)), /INVALID_CHALLENGE/);
  assert.throws(() => h.framework.activate(accountId, enrollment.challenge.challengeId, enrollment.signature, key()), /INVALID_CHALLENGE/);
  h.setTime('2027-04-17T02:30:00Z');
  const next = h.activate(accountId);
  assert.equal(next.binding.cost, 'reset');
  assert.equal(next.binding.freeAt, reset.freeAt);
  assert.notEqual(next.binding.deviceId, old.binding.deviceId);
  assert.ok(h.issue(next.binding.deviceId, next.pair.privateKey).token);
  assert.throws(() => h.activate(accountId), /REBIND_COOLDOWN/);
});

test('credit reset is atomic, idempotent and cannot spend again while awaiting binding', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.buy(accountId);
  const old = h.activate(accountId);
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').canReset, false);
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', key()), /REBIND_COOLDOWN/);
  h.framework.grantCredits(accountId, 'desktop', 2, 'test credits', key());
  const command = key();
  const result = h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', command);
  assert.equal(result.credits, 1);
  assert.deepEqual(h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', command), result);
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', key()), /DEVICE_BINDING_CHANGED/);
  const next = h.activate(accountId, old.pair);
  assert.equal(next.binding.cost, 'reset');
  assert.notEqual(next.binding.deviceId, old.binding.deviceId);
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').credits, 1);
});

test('reset preview must still match the binding and cost at confirmation', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.buy(accountId);
  const old = h.activate(accountId); h.framework.grantCredits(accountId, 'desktop', 2, 'test credits', key());
  h.setTime('2027-04-15T02:30:00Z');
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', key()), /DEVICE_RESET_COST_CHANGED/);
  const next = h.activate(accountId, keyPair());
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', key()), /DEVICE_BINDING_CHANGED/);
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').generation, next.binding.generation);
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').credits, 2);
});

test('unbound, revoked and disabled accounts cannot reset a device', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.buy(accountId);
  assert.equal(h.framework.deviceResetStatus(accountId, 'desktop').state, 'unbound');
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', 1, 'free', key()), /DEVICE_BINDING_CHANGED/);
  const old = h.activate(accountId); h.framework.grantCredits(accountId, 'desktop', 1, 'test credits', key());
  h.framework.revokeEntitlement(accountId, 'tool-1', 'test revoke');
  assert.throws(() => h.framework.resetDevice(accountId, 'desktop', old.binding.generation, 'credit', key()), /GROUP_NOT_OWNED/);
  h.framework.setAccountActive(accountId, false, 'test disable');
  assert.throws(() => h.framework.deviceResetStatus(accountId, 'desktop'), /ACCOUNT_DISABLED/);
});

test('reset HTTP API requires authenticated ownership and explicit confirmation', async t => {
  const h = harness(); const app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(async () => { await app.close(); h.close(); });
  const a = await h.register(), b = await h.register(1); h.buy(a.accountId); h.buy(b.accountId);
  const old = h.activate(a.accountId); h.framework.grantCredits(a.accountId, 'desktop', 1, 'test credits', key());
  const url = '/v1/devices/desktop/reset';
  const headers = { authorization: `Bearer ${a.accessToken}`, 'idempotency-key': key() };
  assert.equal((await app.inject({ url })).statusCode, 401);
  assert.equal((await app.inject({ url, headers })).json().cost, 'credit');
  const payload = { generation: old.binding.generation, cost: 'credit', confirm: true };
  assert.equal((await app.inject({ method: 'POST', url, headers, payload: { ...payload, confirm: false } })).statusCode, 400);
  assert.equal((await app.inject({ method: 'POST', url, headers: { ...headers, authorization: `Bearer ${b.accessToken}` }, payload })).statusCode, 409);
  assert.equal((await app.inject({ method: 'POST', url, headers, payload })).statusCode, 200);
  assert.equal((await app.inject({ method: 'POST', url, headers, payload })).json().credits, 0);
});
