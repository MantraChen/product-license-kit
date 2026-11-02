import test from 'node:test';
import assert from 'node:assert/strict';
import { constants, createPublicKey, generateKeyPairSync, sign } from 'node:crypto';
import { EnvelopeSigner, normalizeDevicePublicKey, normalizePublicKey, sha256, verifyDeviceProof, verifyEnvelope } from '../src/core/crypto.js';
import { signChallenge, verifyLicense } from '../src/sdk/client.js';
import { harness, key, keyPair } from './helpers.js';

function rsaPair(bits = 2048, exponent = 65537) {
  const pair = generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: exponent });
  return { publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}
const rsa = rsaPair();
const message = '["product-license-kit",1,"enroll","challenge",1,"nonce",{}]';

test('device algorithms are selected by the validated key, not signature shape or padding', () => {
  const signature = signChallenge(message, rsa.privateKey);
  const normalized = normalizeDevicePublicKey(rsa.publicKey);
  assert.equal(normalized.algorithm, 'PS256');
  assert.equal(normalized.thumbprint, sha256(createPublicKey(rsa.publicKey).export({ type: 'spki', format: 'der' })));
  assert.equal(signature.length, 342);
  assert.ok(verifyDeviceProof(rsa.publicKey, message, signature));
  assert.ok(!verifyDeviceProof(rsa.publicKey, message + ' ', signature));
  for (const options of [
    { padding: constants.RSA_PKCS1_PADDING },
    { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 0 },
    { padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 20 },
  ]) assert.ok(!verifyDeviceProof(rsa.publicKey, message, sign('sha256', Buffer.from(message), { key: rsa.privateKey, ...options }).toString('base64url')));
  assert.ok(!verifyDeviceProof(rsa.publicKey, message, sign('sha1', Buffer.from(message), {
    key: rsa.privateKey, padding: constants.RSA_PKCS1_PSS_PADDING, saltLength: 20 }).toString('base64url')));
  const ed = keyPair(); const edSignature = signChallenge(message, ed.privateKey);
  assert.ok(verifyDeviceProof(ed.publicKey, message, edSignature));
  assert.ok(!verifyDeviceProof(rsa.publicKey, message, edSignature));
  assert.ok(!verifyDeviceProof(ed.publicKey, message, signature));
  for (const [pem, value] of [[rsa.publicKey, signature], [ed.publicKey, edSignature]]) {
    assert.ok(!verifyDeviceProof(pem!, message, value! + '='));
    const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_';
    const altered = value!.slice(0, -1) + alphabet[alphabet.indexOf(value!.at(-1)!) + 1];
    assert.equal(Buffer.from(altered, 'base64url').toString('base64url'), value);
    assert.ok(!verifyDeviceProof(pem!, message, altered), 'noncanonical trailing bits rejected');
  }
});

test('device keys reject private keys, unsupported parameters and ambiguous PEM/DER', () => {
  const ec = generateKeyPairSync('ec', { namedCurve: 'prime256v1' });
  for (const pem of [rsa.privateKey, rsaPair(1024).publicKey, rsaPair(2048, 3).publicKey,
    ec.publicKey.export({ type: 'spki', format: 'pem' }).toString(), rsa.publicKey + rsa.publicKey,
    'junk' + rsa.publicKey, rsa.publicKey + 'junk'])
    assert.throws(() => normalizeDevicePublicKey(pem), /INVALID_DEVICE_KEY/);
  const der = createPublicKey(rsa.publicKey).export({ type: 'spki', format: 'der' });
  const trailing = '-----BEGIN PUBLIC KEY-----\n' + Buffer.concat([der, Buffer.from([0])]).toString('base64') + '\n-----END PUBLIC KEY-----\n';
  assert.throws(() => normalizeDevicePublicKey(trailing), /INVALID_DEVICE_KEY/);
  assert.equal(normalizeDevicePublicKey(rsa.publicKey.replace(/\n/g, '\r\n')).pem, rsa.publicKey);
});

test('RSA devices do not expand server envelope algorithms or trust roots', () => {
  assert.throws(() => new EnvelopeSigner(rsa.privateKey), /ED25519_REQUIRED/);
  assert.throws(() => normalizePublicKey(rsa.publicKey), /INVALID_DEVICE_KEY/);
  const token = new EnvelopeSigner(keyPair().privateKey).sign({ test: true }, 'plk-license');
  assert.throws(() => verifyEnvelope(token, rsa.publicKey, 'plk-license'));
});

test('RSA device enrolls, verifies licenses, preserves binding and cannot bypass rebind cooldown', async t => {
  const h = harness(); t.after(h.close);
  const { accountId } = await h.register(); h.buy(accountId);
  const enrollment = h.enrollment(accountId, rsa);
  const wrong = sign('sha256', Buffer.from(enrollment.challenge.message), { key: rsa.privateKey,
    padding: constants.RSA_PKCS1_PADDING }).toString('base64url');
  assert.throws(() => h.framework.activate(accountId, enrollment.challenge.challengeId, wrong, key()), /INVALID_DEVICE_PROOF/);
  const binding = h.framework.activate(accountId, enrollment.challenge.challengeId, enrollment.signature, key());
  const result = h.issue(binding.deviceId, rsa.privateKey);
  const claims = verifyLicense(result.token, h.serverKeys.publicKey, { issuer: 'test-issuer', productId: h.framework.catalog.editions.find(x => x.id === 'tool-1')!.productId,
    editionId: 'tool-1', accountId, deviceId: binding.deviceId, devicePublicKey: rsa.publicKey, now: h.now(),
    fingerprint: { schema: 'test-v1', digest: sha256('synthetic') } });
  assert.equal(claims.keyThumbprint, normalizeDevicePublicKey(rsa.publicKey).thumbprint);
  const same = h.activate(accountId, rsa).binding;
  assert.equal(same.deviceId, binding.deviceId); assert.equal(same.generation, binding.generation);
  assert.throws(() => h.activate(accountId, keyPair()), /REBIND_COOLDOWN/);
});
