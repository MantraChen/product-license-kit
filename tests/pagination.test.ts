import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../src/http/app.js';
import { harness, key } from './helpers.js';

function addOrders(h: ReturnType<typeof harness>, accountId: string, count: number) {
  const ids: string[] = [];
  const offer = h.framework.catalog.offers.find(item => item.id === 'buy-tool-1')!;
  for (let index = 0; index < count; index++) {
    const id = key(); ids.push(id);
    h.store.run('INSERT INTO orders(id,account_id,offer_json,status,created_at) VALUES(?,?,?,?,?)',
      id, accountId, JSON.stringify(offer), 'pending', h.now());
  }
  return ids.sort().reverse();
}

test('order cursors traverse older than one hundred rows and equal timestamps without duplication', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register(); const other = await h.register(1);
  const expected = addOrders(h, user.accountId, 125);
  addOrders(h, other.accountId, 25);
  const first = h.framework.ordersPage(user.accountId, { limit: 17 });
  assert.deepEqual(first.items.map(row => row.id), expected.slice(0, 17));
  assert.ok(first.nextCursor);
  assert.throws(() => h.framework.ordersPage(other.accountId, { cursor: first.nextCursor }), /INVALID_PAGE_CURSOR/);
  h.setTime('2027-01-15T02:31:00Z');
  const inserted = h.framework.createOrder(user.accountId, 'buy-tool-1', key());
  const collected = first.items.map(row => row.id);
  let cursor: string | null = first.nextCursor;
  while (cursor) {
    const page = h.framework.ordersPage(user.accountId, { limit: 17, cursor });
    collected.push(...page.items.map(row => row.id));
    cursor = page.nextCursor;
  }
  assert.deepEqual(collected, expected);
  assert.equal(new Set(collected).size, 125);
  assert.equal(h.framework.ordersPage(user.accountId).items[0]!.id, inserted.orderId);
  assert.equal(h.framework.orders(user.accountId).length, 100);
  h.framework.setAccountActive(user.accountId, false, 'pagination revocation test');
  assert.throws(() => h.framework.ordersPage(user.accountId, { cursor: first.nextCursor }), /ACCOUNT_DISABLED/);
});

test('HTTP pagination retains legacy arrays, validates boundaries and preserves administrator isolation', async t => {
  const h = harness(); const adminToken = key() + key();
  const app = await createApp(h.framework, { adminToken });
  t.after(async () => { await app.close(); h.close(); });
  const user = await h.register(); addOrders(h, user.accountId, 125);
  const headers = { authorization: `Bearer ${user.accessToken}` };
  const legacy = await app.inject({ url: '/v1/orders', headers });
  assert.equal(legacy.statusCode, 200); assert.equal(legacy.json().length, 100);
  const first = await app.inject({ url: '/v1/orders?limit=7', headers });
  assert.equal(first.statusCode, 200);
  const page = first.json(); assert.equal(page.items.length, 7); assert.ok(page.nextCursor);
  const second = await app.inject({ url: `/v1/orders?limit=7&cursor=${page.nextCursor}`, headers });
  assert.equal(second.statusCode, 200);
  assert.equal(new Set([...page.items, ...second.json().items].map(row => row.id)).size, 14);
  for (const query of ['limit=0', 'limit=101', 'limit=1.5', 'cursor=invalid', 'limit=2&accountId=foreign'])
    assert.equal((await app.inject({ url: `/v1/orders?${query}`, headers })).statusCode, 400);
  assert.equal((await app.inject({ url: '/v1/orders?limit=2' })).statusCode, 401);
  assert.equal((await app.inject({ url: '/v1/admin/audit?limit=2', headers })).statusCode, 403);
  const admin = { authorization: `Bearer ${adminToken}` };
  const audit = await app.inject({ url: '/v1/admin/audit?limit=1', headers: admin });
  assert.equal(audit.statusCode, 200); assert.equal(audit.json().items.length, 1); assert.ok(audit.json().nextCursor);
  assert.equal((await app.inject({ url: `/v1/orders?cursor=${audit.json().nextCursor}`, headers })).statusCode, 400);
  assert.ok(Array.isArray((await app.inject({ url: '/v1/admin/audit', headers: admin })).json()));
  assert.equal(h.framework.ordersPage(user.accountId, { limit: 100 }).items.length, 100);
});

function addDistributions(h: ReturnType<typeof harness>, accountId: string, count: number,
  editionId = 'tool-1', finalized = true, createdAt = h.now()) {
  const ids: string[] = [];
  for (let index = 0; index < count; index++) {
    const id = key(); ids.push(id);
    // Synthetic historical rows exercise list selection independently of file generation.
    h.store.run('INSERT INTO distributions VALUES(?,?,?,?,?,?,?,?,?)', id, accountId, editionId,
      'test-release', 'private-identity-snapshot', finalized ? 'b'.repeat(64) : null,
      finalized ? 'synthetic-signed-manifest' : null, createdAt, finalized ? createdAt : null);
  }
  return ids.sort().reverse();
}

test('distribution pages filter current rights and finalization before limiting and recheck revocation on every page', async t => {
  const h = harness(); t.after(h.close);
  const user = await h.register(); const other = await h.register(1);
  h.buy(user.accountId);
  const expected = addDistributions(h, user.accountId, 125);
  addDistributions(h, user.accountId, 125, 'tool-2', true, h.now() + 1);
  addDistributions(h, user.accountId, 25, 'tool-1', false, h.now() + 2);
  addDistributions(h, other.accountId, 25);
  const first = h.framework.distributionsPage(user.accountId, { limit: 17 });
  assert.deepEqual(first.items.map(row => row.id), expected.slice(0, 17));
  assert.ok(first.nextCursor);
  assert.deepEqual(Object.keys(first.items[0]!).sort(), ['editionId', 'id', 'manifest', 'releaseId', 'sha256']);
  assert.throws(() => h.framework.distributionsPage(other.accountId, { cursor: first.nextCursor }), /INVALID_PAGE_CURSOR/);
  assert.throws(() => h.framework.ordersPage(user.accountId, { cursor: first.nextCursor }), /INVALID_PAGE_CURSOR/);
  addDistributions(h, user.accountId, 1, 'tool-1', true, h.now() + 100);
  const collected = first.items.map(row => row.id);
  let cursor: string | null = first.nextCursor;
  while (cursor) {
    const page = h.framework.distributionsPage(user.accountId, { cursor, limit: 17 });
    collected.push(...page.items.map(row => row.id)); cursor = page.nextCursor;
  }
  assert.deepEqual(collected, expected);
  assert.equal(new Set(collected).size, 125);
  assert.equal(h.framework.distributions(user.accountId).length, 100);
  h.framework.setEntitlementAccess(user.accountId, 'tool-1', 'none', 'pagination revocation test', key());
  assert.deepEqual(h.framework.distributionsPage(user.accountId, { cursor: first.nextCursor }), { items: [], nextCursor: null });
  assert.deepEqual(h.framework.distributions(user.accountId), []);
  h.framework.setAccountActive(user.accountId, false, 'pagination account revocation test');
  assert.throws(() => h.framework.distributionsPage(user.accountId, { cursor: first.nextCursor }), /ACCOUNT_DISABLED/);
});

test('distribution HTTP pages retain the legacy array and reject foreign, cross-list and malformed cursors', async t => {
  const h = harness(); const app = await createApp(h.framework, { adminToken: key() + key() });
  t.after(async () => { await app.close(); h.close(); });
  const user = await h.register(); const other = await h.register(1);
  h.buy(user.accountId); addDistributions(h, user.accountId, 125);
  const headers = { authorization: `Bearer ${user.accessToken}` };
  assert.equal((await app.inject({ url: '/v1/distributions', headers })).json().length, 100);
  const page = (await app.inject({ url: '/v1/distributions?limit=7', headers })).json();
  assert.equal(page.items.length, 7); assert.ok(page.nextCursor);
  const second = await app.inject({ url: `/v1/distributions?cursor=${page.nextCursor}&limit=7`, headers });
  assert.equal(second.statusCode, 200);
  assert.equal(new Set([...page.items, ...second.json().items].map(row => row.id)).size, 14);
  for (const query of ['limit=0', 'limit=101', 'limit=1.5', 'cursor=invalid', 'limit=2&accountId=foreign'])
    assert.equal((await app.inject({ url: `/v1/distributions?${query}`, headers })).statusCode, 400);
  assert.equal((await app.inject({ url: '/v1/distributions?limit=2' })).statusCode, 401);
  assert.equal((await app.inject({ url: `/v1/distributions?cursor=${page.nextCursor}`,
    headers: { authorization: `Bearer ${other.accessToken}` } })).statusCode, 400);
  h.buy(user.accountId, 'desktop-rebind');
  const orderCursor = h.framework.ordersPage(user.accountId, { limit: 1 }).nextCursor;
  assert.ok(orderCursor);
  assert.equal((await app.inject({ url: `/v1/distributions?cursor=${orderCursor}`, headers })).statusCode, 400);
});
