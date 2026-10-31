import test from 'node:test';
import assert from 'node:assert/strict';
import {harness,key} from './helpers.js';
import {sha256} from '../src/core/crypto.js';
import {signChallenge,verifyLicense} from '../src/sdk/client.js';

test('a reused device key with changed hardware follows rebind policy and rotates the generation',async t=>{
  const h=harness();t.after(h.close);const {accountId}=await h.register();h.buy(accountId);
  const old=h.activate(accountId),fingerprint={schema:'test-v1',digest:sha256('different')};
  const changed=h.framework.enrollmentChallenge(accountId,'desktop',old.pair.publicKey,fingerprint);
  const signature=signChallenge(changed.message,old.pair.privateKey);
  assert.throws(()=>h.framework.activate(accountId,changed.challengeId,signature,key()),/REBIND_COOLDOWN/);
  h.framework.grantCredits(accountId,'desktop',1,'fixture allowance',key());
  const next=h.framework.activate(accountId,changed.challengeId,signature,key());
  assert.equal(next.cost,'credit');assert.notEqual(next.deviceId,old.binding.deviceId);
  assert.throws(()=>h.framework.licenseChallenge(old.binding.deviceId,'tool-1'),/LICENSE_UNAVAILABLE/);
});

test('channel and fingerprint are signed and enforced at both issuance and SDK verification',async t=>{
  const h=harness();t.after(h.close);const {accountId}=await h.register();h.buy(accountId);const active=h.activate(accountId);
  assert.throws(()=>h.framework.licenseChallenge(active.binding.deviceId,'tool-1','beta'),/LICENSE_UNAVAILABLE/);
  const license=h.issue(active.binding.deviceId,active.pair.privateKey);
  const expected={issuer:'test-issuer',productId:'sample-tool',editionId:'tool-1',accountId,
    deviceId:active.binding.deviceId,devicePublicKey:active.pair.publicKey,now:h.now(),fingerprint:{schema:'test-v1',digest:sha256('synthetic')}};
  assert.equal(verifyLicense(license.token,h.serverKeys.publicKey,expected).channel,'stable');
  assert.throws(()=>verifyLicense(license.token,h.serverKeys.publicKey,{...expected,channel:'beta'}),/LICENSE_SCOPE_MISMATCH/);
  assert.throws(()=>verifyLicense(license.token,h.serverKeys.publicKey,{...expected,fingerprint:{...expected.fingerprint,digest:sha256('other')}}),/LICENSE_SCOPE_MISMATCH/);
  h.framework.importEntitlement(accountId,'tool-1',{source:'fixture',reference:'test-beta',reason:'beta purchase',betaAccess:true});
  const beta=h.framework.licenseChallenge(active.binding.deviceId,'tool-1','beta');
  h.framework.revokeEntitlement(accountId,'tool-1','mistaken role');
  h.buy(accountId);
  assert.equal(h.framework.hasReleaseAccess(accountId,'tool-1','beta'),false);
  assert.throws(()=>h.framework.issueLicense(beta.challengeId,signChallenge(beta.message,active.pair.privateKey)),/LICENSE_UNAVAILABLE/);
});

test('security recovery invalidates pending proofs without providing a free rebind',async t=>{
  const h=harness();t.after(h.close);const account=await h.register();h.buy(account.accountId);const active=h.activate(account.accountId);
  const pending=h.enrollment(account.accountId),lease=h.framework.licenseChallenge(active.binding.deviceId,'tool-1');
  h.framework.revokeAccess(account.accountId,'password recovered',true);
  assert.throws(()=>h.framework.authenticate(account.accessToken),/UNAUTHORIZED/);
  assert.throws(()=>h.framework.activate(account.accountId,pending.challenge.challengeId,pending.signature,key()),/INVALID_CHALLENGE/);
  assert.throws(()=>h.framework.issueLicense(lease.challengeId,signChallenge(lease.message,active.pair.privateKey)),/INVALID_CHALLENGE/);
  assert.throws(()=>h.activate(account.accountId),/REBIND_COOLDOWN/);
  assert.equal(h.framework.deviceResetStatus(account.accountId,'desktop').freeAt,active.binding.freeAt);
});

test('cancelled-order money is reserved once, can only pay the same account, and cannot be refunded twice',async t=>{
  const h=harness();t.after(h.close);const a=await h.register(),b=await h.register(1);
  const order=h.framework.createOrder(a.accountId,'buy-tool-1',key());h.framework.cancelOrder(a.accountId,order.orderId);
  const payment={method:'manual-bank',reference:' receipt-001 ',amount:order.offer.amount,currency:order.offer.currency};
  const receipt=h.framework.recordPaymentException(order.orderId,payment,'User cancelled after transfer');
  assert.equal(h.framework.recordPaymentException(order.orderId,payment,'retry').id,receipt.id);
  const foreign=h.framework.createOrder(b.accountId,'buy-tool-1',key());
  assert.throws(()=>h.framework.resolvePaymentException(receipt.id,{action:'apply',orderId:foreign.orderId,reason:'apply receipt'}),/PAYMENT_ACCOUNT_MISMATCH/);
  const target=h.framework.createOrder(a.accountId,'buy-tool-1',key());
  assert.throws(()=>h.framework.confirmPayment(target.orderId,payment),/PAYMENT_REFERENCE_REUSED/);
  const resolution={action:'apply' as const,orderId:target.orderId,reason:'Reconciled verified bank transfer'};
  assert.equal(h.framework.resolvePaymentException(receipt.id,resolution).status,'applied');
  assert.equal(h.framework.resolvePaymentException(receipt.id,resolution).replayed,true);
  assert.throws(()=>h.framework.resolvePaymentException(receipt.id,{action:'refund',refundReference:'refund-001',reason:'second use'}),/PAYMENT_EXCEPTION_RESOLVED/);
  assert.throws(()=>h.framework.recordPaymentException(foreign.orderId,payment,'reused receipt'),/PAYMENT_REFERENCE_REUSED/);
});

test('refund recording grants nothing, blocks reuse and preserves evidence',async t=>{
  const h=harness();t.after(h.close);const {accountId}=await h.register();const order=h.framework.createOrder(accountId,'buy-tool-1',key());
  h.framework.cancelOrder(accountId,order.orderId);
  const payment={method:'manual-bank',reference:'receipt-refund',amount:order.offer.amount,currency:order.offer.currency};
  const receipt=h.framework.recordPaymentException(order.orderId,payment,'already refunded offline');
  const result=h.framework.resolvePaymentException(receipt.id,{action:'refund',refundReference:'bank-refund-reference',reason:'Verified outgoing refund in bank account'});
  assert.equal(result.status,'refunded');assert.equal(h.framework.profile(accountId).entitlements.length,0);
  const next=h.framework.createOrder(accountId,'buy-tool-1',key());
  assert.throws(()=>h.framework.confirmPayment(next.orderId,payment),/PAYMENT_REFERENCE_REUSED/);
  assert.equal(h.framework.paymentExceptions()[0]!.status,'refunded');
});
