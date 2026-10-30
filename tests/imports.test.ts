import test from 'node:test';
import assert from 'node:assert/strict';
import { harness } from './helpers.js';

const evidence = { source: 'verified-membership', reference: 'guild-user-hash', reason: 'Verified historical purchase role' };
test('verified import is permanent, idempotent, and does not fabricate payment', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register();
  assert.equal(h.framework.importEntitlement(accountId, 'tool-1', evidence).status, 'imported');
  assert.equal(h.framework.importEntitlement(accountId, 'tool-1', evidence).status, 'already-owned');
  assert.equal(h.store.all('SELECT * FROM entitlement_imports').length, 1);
  assert.equal(h.framework.orders(accountId).length, 0);
  assert.equal(h.store.get<{ order_id: string | null }>('SELECT order_id FROM entitlements')!.order_id, null);
  assert.equal(h.framework.bestUpgradeOffer(accountId, 'tool-2').requiresEditionId, 'tool-1');
  const other = await h.register(1);
  assert.throws(() => h.framework.importEntitlement(other.accountId, 'tool-1', evidence), /ALREADY_CLAIMED/);
  h.framework.revokeEntitlement(accountId, 'tool-1', 'manual correction');
  assert.equal(h.framework.importEntitlement(accountId, 'tool-1', evidence).status, 'revoked');
  assert.throws(() => h.framework.bestUpgradeOffer(accountId, 'tool-2'), /NOT_ELIGIBLE/);
});
test('imports preserve paid provenance and reject disabled accounts and unknown editions', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); const paid = h.buy(accountId);
  h.framework.importEntitlement(accountId, 'tool-1', evidence);
  assert.equal(h.store.get<{ order_id: string }>('SELECT order_id FROM entitlements')!.order_id, paid.orderId);
  assert.throws(() => h.framework.importEntitlement(accountId, 'missing', evidence), /EDITION_NOT_FOUND/);
  h.framework.setAccountActive(accountId, false, 'test suspension');
  assert.throws(() => h.framework.importEntitlement(accountId, 'tool-1', evidence), /ACCOUNT_DISABLED/);
});
test('upgrade selection uses cheapest eligible price and a deterministic tie break', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.framework.importEntitlement(accountId, 'tool-1', evidence);
  const original = h.framework.bestUpgradeOffer(accountId, 'tool-2');
  h.framework.catalog.offers.push({ ...original, id: 'cheaper', amount: 1 });
  assert.equal(h.framework.bestUpgradeOffer(accountId, 'tool-2').id, 'cheaper');
  h.framework.catalog.offers.push({ ...original, id: 'a-cheaper', amount: 1 });
  assert.equal(h.framework.bestUpgradeOffer(accountId, 'tool-2').id, 'a-cheaper');
});
test('beta includes stable only for its edition and cannot restore revoked rights', async t => {
  const h = harness(); t.after(h.close); const { accountId } = await h.register();
  h.framework.importEntitlement(accountId, 'tool-1', evidence);
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-1', 'beta'), false);
  h.framework.importEntitlement(accountId, 'tool-1', { ...evidence, betaAccess: true });
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-1', 'stable'), true);
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-1', 'beta'), true);
  h.framework.importEntitlement(accountId, 'tool-1', evidence);
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-1', 'beta'), true);
  h.buy(accountId, 'upgrade-tool-1-to-2');
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-2', 'stable'), true);
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-2', 'beta'), false);
  h.framework.revokeEntitlement(accountId, 'tool-1', 'manual correction');
  h.framework.importEntitlement(accountId, 'tool-1', { ...evidence, betaAccess: true });
  assert.equal(h.framework.hasReleaseAccess(accountId, 'tool-1', 'beta'), false);
});
