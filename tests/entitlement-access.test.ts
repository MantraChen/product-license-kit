import test from 'node:test';
import assert from 'node:assert/strict';
import {harness,key} from './helpers.js';

test('explicit access changes restore revoked rights, preserve paid provenance and scope Beta to one edition',async t=>{
 const h=harness();t.after(h.close);const {accountId}=await h.register();const order=h.buy(accountId);
 const set=(access:'none'|'stable'|'beta',k=key())=>h.framework.setEntitlementAccess(accountId,'tool-1',access,'verified operator correction',k);
 set('none');
 assert.equal(h.framework.importEntitlement(accountId,'tool-1',{source:'role',reference:'fixture',reason:'verified role'}).status,'revoked');
 const k=key();set('beta',k);
 assert.equal(h.framework.hasReleaseAccess(accountId,'tool-1','beta'),true);
 assert.equal(h.store.get<{order_id:string}>('SELECT order_id FROM entitlements WHERE account_id=?',accountId)!.order_id,order.orderId);
 set('stable');assert.equal(h.framework.hasReleaseAccess(accountId,'tool-1','beta'),false);
 set('none');set('beta',k);assert.equal(h.framework.hasReleaseAccess(accountId,'tool-1','stable'),false);
 assert.throws(()=>set('stable',k),/IDEMPOTENCY_CONFLICT/);
 assert.equal(h.framework.orders(accountId).length,1);
 h.framework.setAccountActive(accountId,false,'suspended');assert.throws(()=>set('beta'),/ACCOUNT_DISABLED/);
});

test('manual access never invents an order and validates the edition and reason',async t=>{
 const h=harness();t.after(h.close);const {accountId}=await h.register();
 h.framework.setEntitlementAccess(accountId,'tool-1','stable','operator grant',key());
 assert.equal(h.framework.orders(accountId).length,0);
 assert.equal(h.store.get<{order_id:null}>('SELECT order_id FROM entitlements WHERE account_id=?',accountId)!.order_id,null);
 assert.throws(()=>h.framework.setEntitlementAccess(accountId,'unknown','stable','operator grant',key()));
 assert.throws(()=>h.framework.setEntitlementAccess(accountId,'tool-1','stable','',key()),/INVALID_ENTITLEMENT_CHANGE/);
});
