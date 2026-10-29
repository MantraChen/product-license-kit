import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFileSync, mkdirSync, writeFileSync } from 'node:fs';
import { Framework, SqliteStore, EnvelopeSigner, parseCatalog, createApp, sha256 } from '../dist/index.js';
import { LocalIdentityProvider } from '../dist/adapters/local-identity.js';
import { LicenseClient, signChallenge, verifyLicense, verifyDistribution } from '../dist/sdk/client.js';

const pair = () => {
  const keys = generateKeyPairSync('ed25519');
  return { privateKey: keys.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
    publicKey: keys.publicKey.export({ type: 'spki', format: 'pem' }).toString() };
};
const adminToken = randomUUID() + randomUUID();
const identityProof = randomUUID() + randomUUID();
const serverKeys = pair(); const deviceKeys = pair();
const store = new SqliteStore(':memory:');
const framework = new Framework({ store, catalog: parseCatalog(JSON.parse(readFileSync(new URL('./catalog.json', import.meta.url), 'utf8'))),
  signer: new EnvelopeSigner(serverKeys.privateKey), issuer: 'demo-license-service',
  providers: [new LocalIdentityProvider([{ subject: 'synthetic-buyer', proof: identityProof }])],
});
const app = await createApp(framework, { adminToken });
try {
  const address = await app.listen({ host: '127.0.0.1', port: 0 });
  const client = new LicenseClient(address);
  const admin = (path, body) => client.request('/v1/admin' + path, { accessToken: adminToken, body, idempotencyKey: randomUUID() });
  const invite = await admin('/invitations', { provider: 'local', subject: 'synthetic-buyer' });
  const session = await client.request('/v1/auth/register', { body: { ticket: invite.ticket, proof: identityProof } });
  const user = (path, body) => client.request('/v1' + path, { accessToken: session.accessToken, body, idempotencyKey: randomUUID() });
  console.log('1. Verified identity and claimed one-use invitation.');
  for (const offerId of ['buy-tool-1', 'upgrade-tool-1-to-2']) {
    const order = await user('/orders', { offerId });
    await admin(`/orders/${order.orderId}/confirm`, { method: 'manual-bank', reference: `SYNTHETIC-${randomUUID()}`,
      amount: order.offer.amount, currency: order.offer.currency });
  }
  console.log('2. Confirmed synthetic payments; original and upgraded edition rights coexist. No real payment occurred.');
  const challenge = await user('/devices/challenges', { groupId: 'desktop', publicKey: deviceKeys.publicKey,
    fingerprint: { schema: 'demo-v1', digest: sha256('synthetic-hardware') } });
  const binding = await user('/devices/activate', { challengeId: challenge.challengeId, signature: signChallenge(challenge.message, deviceKeys.privateKey) });
  const licenseChallenge = await client.request('/v1/licenses/challenges', { body: { deviceId: binding.deviceId, editionId: 'tool-2' } });
  const license = await client.request('/v1/licenses/issue', { body: { challengeId: licenseChallenge.challengeId,
    signature: signChallenge(licenseChallenge.message, deviceKeys.privateKey) } });
  verifyLicense(license.token, serverKeys.publicKey, { issuer: 'demo-license-service', productId: 'sample-tool', editionId: 'tool-2',
    accountId: session.accountId, deviceId: binding.deviceId, devicePublicKey: deviceKeys.publicKey });
  console.log('3. Activated a device and verified a signed, device-bound license using a pinned server key.');
  const distribution = await admin('/distributions', { accountId: session.accountId, editionId: 'tool-2', releaseId: '2.0.0' });
  // Deliberately a JavaScript example. Do not append markers to signed EXEs.
  const artifact = Buffer.from(`// ${distribution.marker}\nconsole.log('Sample product; distribution ${distribution.distributionId}');\n`);
  const { manifest } = await admin(`/distributions/${distribution.distributionId}/finalize`, { sha256: sha256(artifact) });
  verifyDistribution(manifest, serverKeys.publicKey, artifact, { distributionId: distribution.distributionId, editionId: 'tool-2', releaseId: '2.0.0' });
  mkdirSync('.data/demo-artifacts', { recursive: true });
  writeFileSync(`.data/demo-artifacts/${distribution.distributionId}.mjs`, artifact, { flag: 'wx' });
  console.log('4. Generated and hash-verified a personalized sample artifact in .data/demo-artifacts/.');
  const me = await user('/me');
  console.log(JSON.stringify({ entitlements: me.entitlements.map(e => e.edition_id), deviceGroups: me.bindings.length,
    nextFreeRebind: new Date(binding.freeAt).toISOString() }, null, 2));
} finally { await app.close(); store.close(); }
