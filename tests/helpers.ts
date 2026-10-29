import { generateKeyPairSync, randomUUID } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { SqliteStore } from '../src/adapters/sqlite.js';
import { LocalIdentityProvider } from '../src/adapters/local-identity.js';
import { EnvelopeSigner, sha256 } from '../src/core/crypto.js';
import { parseCatalog } from '../src/core/model.js';
import { Framework } from '../src/service.js';
import { signChallenge } from '../src/sdk/client.js';

export const catalog = () => parseCatalog(JSON.parse(readFileSync('examples/catalog.json', 'utf8')));
export const key = () => randomUUID();
export function keyPair() {
  const pair = generateKeyPairSync('ed25519');
  return { publicKey: pair.publicKey.export({ type: 'spki', format: 'pem' }).toString(),
    privateKey: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() };
}
export function harness() {
  let now = Date.parse('2027-01-15T02:30:00Z');
  const store = new SqliteStore(':memory:'); const serverKeys = keyPair();
  const people = [1, 2, 3].map(n => ({ subject: `test-person-${n}`, proof: randomUUID() + randomUUID() }));
  const framework = new Framework({ store, catalog: catalog(), signer: new EnvelopeSigner(serverKeys.privateKey),
    providers: [new LocalIdentityProvider(people)], issuer: 'test-issuer', now: () => now });
  async function register(index = 0) {
    const person = people[index]!; const invitation = framework.issueInvitation('local', person.subject);
    return framework.register(invitation.ticket, person.proof);
  }
  function buy(accountId: string, offerId = 'buy-tool-1') {
    const order = framework.createOrder(accountId, offerId, key());
    framework.confirmPayment(order.orderId, { method: 'manual-bank', reference: key(), amount: order.offer.amount, currency: order.offer.currency });
    return order;
  }
  function enrollment(accountId: string, pair = keyPair(), groupId = 'desktop') {
    const challenge = framework.enrollmentChallenge(accountId, groupId, pair.publicKey, { schema: 'test-v1', digest: sha256('synthetic') });
    return { pair, challenge, signature: signChallenge(challenge.message, pair.privateKey) };
  }
  function activate(accountId: string, pair = keyPair(), groupId = 'desktop') {
    const data = enrollment(accountId, pair, groupId);
    return { ...data, binding: framework.activate(accountId, data.challenge.challengeId, data.signature, key()) };
  }
  function issue(deviceId: string, privateKey: string, editionId = 'tool-1') {
    const challenge = framework.licenseChallenge(deviceId, editionId);
    return framework.issueLicense(challenge.challengeId, signChallenge(challenge.message, privateKey));
  }
  return { framework, store, serverKeys, people, register, buy, enrollment, activate, issue,
    now: () => now, setTime: (value: string) => { now = Date.parse(value); }, close: () => store.close() };
}
