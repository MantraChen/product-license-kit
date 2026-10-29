import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/http/app.js';
import { KookIdentityProvider, KookNotificationSink } from '../src/adapters/kook.js';
import { LocalIdentityProvider } from '../src/adapters/local-identity.js';
import { LicenseClient } from '../src/sdk/client.js';
import { harness, key } from './helpers.js';

test('HTTP separates user/admin privileges, rejects mass assignment and requires command keys', async t => {
  const h = harness(); const adminToken = key() + key();
  const app = await createApp(h.framework, { adminToken }); t.after(async () => { await app.close(); h.close(); });
  const session = await h.register(); const userHeaders = { authorization: `Bearer ${session.accessToken}` };
  assert.equal((await app.inject({ method: 'GET', url: '/v1/me' })).statusCode, 401);
  assert.equal((await app.inject({ method: 'GET', url: '/v1/admin/audit', headers: userHeaders })).statusCode, 403);
  assert.equal((await app.inject({ method: 'GET', url: '/v1/admin/audit', headers: { authorization: `Bearer ${adminToken}` } })).statusCode, 200);
  assert.equal((await app.inject({ method: 'POST', url: '/v1/orders', headers: userHeaders, payload: { offerId: 'buy-tool-1' } })).statusCode, 400);
  const changed = await app.inject({ method: 'POST', url: '/v1/orders', headers: { ...userHeaders, 'idempotency-key': key() },
    payload: { offerId: 'buy-tool-1', amount: 1, accountId: 'attacker' } });
  assert.equal(changed.statusCode, 400); assert.equal(h.framework.orders(session.accountId).length, 0);
  assert.equal((await app.inject({ method: 'GET', url: '/v1/me', headers: { ...userHeaders, origin: 'https://untrusted.example' } })).statusCode, 403);
  const me = await app.inject({ method: 'GET', url: '/v1/me', headers: userHeaders });
  assert.equal(me.headers['cache-control'], 'no-store'); assert.equal(me.json().account.id, session.accountId);
});
test('HTTP repeated activation cannot double-spend; two different replacements compete for one credit', async t => {
  const h = harness(); const app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(async () => { await app.close(); h.close(); });
  const session = await h.register(); h.buy(session.accountId); h.activate(session.accountId);
  h.framework.grantCredits(session.accountId, 'desktop', 1, 'one replacement', key());
  const attempts = [h.enrollment(session.accountId), h.enrollment(session.accountId)];
  const responses = await Promise.all(attempts.map(attempt => app.inject({ method: 'POST', url: '/v1/devices/activate',
    headers: { authorization: `Bearer ${session.accessToken}`, 'idempotency-key': key() },
    payload: { challengeId: attempt.challenge.challengeId, signature: attempt.signature } })));
  assert.deepEqual(responses.map(r => r.statusCode).sort(), [200, 409]);
  assert.equal(h.store.get<{ balance: number }>('SELECT balance FROM credits')!.balance, 0);
  assert.equal(h.store.all('SELECT * FROM bindings').length, 1);
});
test('HTTP validation errors never echo supplied secrets and oversized bodies are rejected', async t => {
  const h = harness(); const app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(async () => { await app.close(); h.close(); });
  const secret = key();
  const response = await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { provider: 'local', proof: secret, extraSecret: secret } });
  assert.equal(response.statusCode, 400); assert.ok(!response.body.includes(secret));
  assert.equal((await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { provider: 'local', proof: 'a'.repeat(17000) } })).statusCode, 413);
});
test('auth endpoints rate limit credential attempts', async t => {
  const h = harness(); const app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(async () => { await app.close(); h.close(); });
  const responses = [];
  for (let i = 0; i < 11; i++) responses.push(await app.inject({ method: 'POST', url: '/v1/auth/login', payload: { provider: 'local', proof: key() } }));
  assert.equal(responses[10]!.statusCode, 429);
});
test('KOOK verifies server-returned immutable ID using the external token', async () => {
  let observedAuthorization: string | null = null;
  const provider = new KookIdentityProvider(async (input, init) => {
    assert.equal(input, 'https://www.kookapp.cn/api/v3/user/me');
    observedAuthorization = new Headers(init?.headers).get('Authorization');
    return new Response(JSON.stringify({ code: 0, data: { id: 'verified-kook-id', username: 'ignored-name' } }));
  });
  assert.deepEqual(await provider.verify('synthetic-provider-token'), { provider: 'kook', subject: 'verified-kook-id' });
  assert.equal(observedAuthorization, 'Bearer synthetic-provider-token');
});
test('KOOK provider rejects failed and malformed verification, without trusting a client ID', async () => {
  const unauthorized = new KookIdentityProvider(async () => new Response('{}', { status: 401 }));
  await assert.rejects(unauthorized.verify('wrong'), /IDENTITY_VERIFICATION_FAILED/);
  const bad = new KookIdentityProvider(async () => new Response(JSON.stringify({ code: 0, data: { username: 'someone' } })));
  await assert.rejects(bad.verify('wrong'), /IDENTITY_PROVIDER_UNAVAILABLE/);
});
test('KOOK notification adapter can be tested without contacting or messaging anyone', async () => {
  let body: Record<string, unknown> = {};
  const sink = new KookNotificationSink('synthetic-bot-token', async (_input, init) => {
    body = JSON.parse(init?.body as string) as Record<string, unknown>;
    return new Response(JSON.stringify({ code: 0 }));
  });
  await sink.send({ id: 'event-123', topic: 'order.fulfilled', accountId: 'internal', createdAt: 1 }, { provider: 'kook', subject: 'recipient' });
  assert.equal(body.target_id, 'recipient'); assert.ok(String(body.content).includes('event-123'));
  assert.ok(!String(body.content).includes('internal'));
});
test('SDK rejects insecure remote endpoints and redirect credential forwarding', async () => {
  assert.throws(() => new LicenseClient('http://public.example'), /HTTPS_REQUIRED/);
  assert.throws(() => new LicenseClient('https://name:password@public.example'), /INVALID_SERVER_URL/);
  const client = new LicenseClient('https://api.example', async (_input, init) => {
    assert.equal(init?.redirect, 'error'); return new Response(JSON.stringify({ ok: true }));
  });
  assert.deepEqual(await client.request('/v1/catalog'), { ok: true });
  await assert.rejects(client.request('https://attacker.example'), /INVALID_API_PATH/);
});
test('local identity adapter refuses production mode', () => {
  const previous = process.env.NODE_ENV;
  try {
    process.env.NODE_ENV = 'production';
    assert.throws(() => new LocalIdentityProvider([{ subject: 'demo', proof: key() }]), /LOCAL_IDENTITY_FORBIDDEN_IN_PRODUCTION/);
  } finally {
    if (previous === undefined) delete process.env.NODE_ENV; else process.env.NODE_ENV = previous;
  }
});
