import test from 'node:test';
import assert from 'node:assert/strict';
import { harness, key } from './helpers.js';
import { parseCatalog } from '../src/core/model.js';

function offers(f: ReturnType<typeof harness>) {
  const [first, second] = f.framework.catalog.editions;
  f.framework.catalog.offers.push(
    {id: 'beta-first', kind: 'channel', editionId: first!.id, channel: 'beta', amount: 100, currency: 'CNY'},
    {id: 'beta-second', kind: 'channel', editionId: second!.id, channel: 'beta', amount: 300, currency: 'CNY'},
    {id: 'beta-upgrade', kind: 'upgrade', editionId: second!.id, requiresEditionId: first!.id, requiresChannel: 'beta', channel: 'beta', amount: 200, currency: 'CNY'});
  return [first!.id,second!.id] as const;
}
test('Beta channel top-up preserves Stable purchase and rejects duplicates, missing ownership and wrong amounts', async t => {
  const f=harness(); t.after(f.close); const [edition]=offers(f); const account=await f.register();
  assert.throws(()=>f.framework.createOrder(account.accountId,'beta-first',key()), /UPGRADE_NOT_ELIGIBLE/);
  const stable=f.buy(account.accountId);
  const order=f.framework.createOrder(account.accountId,'beta-first',key());
  assert.equal(f.framework.hasReleaseAccess(account.accountId,edition,'beta'),false);
  const payment={method:'manual-bank',reference:key(),amount:100,currency:'CNY'};
  assert.throws(()=>f.framework.confirmPayment(order.orderId,{...payment,amount:99}), /PAYMENT_AMOUNT_MISMATCH/);
  assert.equal(f.framework.confirmPayment(order.orderId,payment).replayed,false);
  assert.equal(f.framework.confirmPayment(order.orderId,payment).replayed,true);
  assert.equal(f.framework.hasReleaseAccess(account.accountId,edition,'beta'),true);
  assert.equal(f.store.get<{order_id:string}>('SELECT order_id FROM entitlements WHERE account_id=? AND edition_id=?',account.accountId,edition)!.order_id,stable.orderId);
  assert.throws(()=>f.framework.createOrder(account.accountId,'beta-first',key()), /CHANNEL_ALREADY_OWNED/);
});
test('cross-edition Beta upgrade requires source Beta, selects lowest target-channel price and rechecks at payment', async t=>{
  const f=harness();t.after(f.close);const [first,second]=offers(f);const {accountId}=await f.register(); f.buy(accountId);
  assert.throws(()=>f.framework.createOrder(accountId,'beta-upgrade',key()),/UPGRADE_NOT_ELIGIBLE/);
  f.buy(accountId,'beta-first');
  assert.equal(f.framework.bestUpgradeOffer(accountId,second,'beta').id,'beta-upgrade');
  const order=f.framework.createOrder(accountId,'beta-upgrade',key());
  f.framework.setEntitlementAccess(accountId,first,'stable','test',key());
  assert.throws(()=>f.framework.confirmPayment(order.orderId,{method:'manual-bank',reference:key(),amount:200,currency:'CNY'}),/UPGRADE_NOT_ELIGIBLE/);
  assert.equal(f.framework.orderLifecycle(order.orderId).status,'pending');
  f.framework.setEntitlementAccess(accountId,first,'beta','test',key());
  f.framework.confirmPayment(order.orderId,{method:'manual-bank',reference:key(),amount:200,currency:'CNY'});
  assert.equal(f.framework.hasReleaseAccess(accountId,second,'stable'),true);
  assert.equal(f.framework.hasReleaseAccess(accountId,second,'beta'),true);
});
test('catalog rejects malformed Beta channel offers and Beta prerequisites on Stable/rebind offers',t=>{
 const f=harness();t.after(f.close);offers(f);
 const catalog=structuredClone(f.framework.catalog);
 for(const patch of [{kind:'channel',channel:undefined},{kind:'edition',channel:undefined,requiresChannel:'beta'},{kind:'rebind',groupId:catalog.groups[0]!.id,credits:1}]){
  const copy=structuredClone(catalog);Object.assign(copy.offers.at(-1)!,patch);
  assert.throws(()=>parseCatalog(copy));
 }
});
