import assert from 'node:assert/strict';
import { generateKeyPairSync, randomUUID, sign } from 'node:crypto';
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { Readable } from 'node:stream';
import { fileURLToPath } from 'node:url';
import { createApp } from '../.test-build/src/http/app.js';
import { verifyEnvelope, verifyDeviceProof } from '../.test-build/src/core/crypto.js';
import { harness } from '../.test-build/tests/helpers.js';
import { AsyncFramework } from '../.test-build/src/async-service.js';
import { PostgresStore } from '../.test-build/src/adapters/postgres.js';
import { AsyncQueries } from '../.test-build/src/core/async-queries.js';
import pg from 'pg';

// Integration tests use random local identities and loopback HTTP. PostgreSQL requires the owned fixture.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
assert.equal(process.cwd(), root, 'Run from the framework root after pnpm check.');
const language = process.argv[2] ?? 'dotnet';
const dotnet = process.env.PLK_DOTNET ?? 'dotnet';
assert.ok(['dotnet', 'rust'].includes(language), 'Unsupported SDK runner.');
const backend = process.env.PLK_NATIVE_BACKEND ?? 'sqlite';
assert.ok(['sqlite', 'postgres'].includes(backend));
const base = harness();
let h = base;
if (backend === 'postgres') {
  assert.equal(process.env.PLK_TEST_POSTGRES_SCOPED, '1', 'Use scripts/test-postgres.mjs --native.');
  assert.ok(process.env.PLK_TEST_POSTGRES_URL);
  const schema = `plk_native_${randomUUID().replaceAll('-', '')}`;
  const admin = new pg.Pool({ connectionString: process.env.PLK_TEST_POSTGRES_URL, max: 1 });
  let store;
  try {
    store = await PostgresStore.connect({ connectionString: process.env.PLK_TEST_POSTGRES_URL, schema });
    const framework = await AsyncFramework.create({ store, catalog: base.framework.catalog, signer: base.framework.signer,
      providers: [...base.framework.providers.values()], issuer: base.framework.issuer, now: base.now });
    h = { ...base, framework, store: new AsyncQueries(store), close: async () => {
      try { await store.close(); await admin.query(`DROP SCHEMA "${schema}" CASCADE`); } finally { await admin.end(); base.close(); }
    } };
  } catch (error) { await store?.close(); await admin.end(); base.close(); throw error; }
}
const adminToken = randomUUID() + randomUUID();
const app = await createApp(h.framework, { adminToken, rateLimitMax: 1000 });
let redirected = 0;
const kinds = new Set();
app.addHook('preHandler', async request => {
  if (request.url === '/v1/devices/activate') {
    const data = request.body;
    const challenge = await h.store.get('SELECT message,payload FROM challenges WHERE id=?', data.challengeId);
    assert.ok(challenge);
    const { publicKey } = JSON.parse(challenge.payload);
    assert.ok(verifyDeviceProof(publicKey, challenge.message, data.signature));
    kinds.add(publicKey.length < 200 ? 'Ed25519' : 'PS256');
  }
});
const custom = (header, body) => {
  const first = Buffer.from(header).toString('base64url'), second = Buffer.from(body).toString('base64url');
  const message = `${first}.${second}`;
  return `${message}.${sign(null, Buffer.from(message), h.serverKeys.privateKey).toString('base64url')}`;
};
app.post('/v1/test/vectors', async request => {
  const accountId = await h.framework.authenticate(request.headers.authorization.slice(7));
  const claims = verifyEnvelope(request.body.token, h.serverKeys.publicKey, 'plk-license');
  assert.equal(claims.sub, accountId);
  const header = JSON.stringify({ alg: 'EdDSA', typ: 'plk-license', kid: h.framework.signer.kid });
  const payload = JSON.stringify(claims);
  const modified = [
    { ...claims, iat: Math.floor(h.now() / 1000) + 1 }, { ...claims, nbf: Math.floor(h.now() / 1000) + 1 },
    { ...claims, exp: Math.floor(h.now() / 1000) }, { ...claims, generation: 0 }, { ...claims, generation: 1.5 },
    { ...claims, generation: 9007199254740992 }, { ...claims, ownership: 'temporary' },
    { ...claims, fingerprint: { ...claims.fingerprint, extra: true } }, { ...claims, extra: true },
  ].map(value => h.framework.signer.sign(value, 'plk-license'));
  modified.push(custom(header.replace('EdDSA', 'HS256'), payload));
  modified.push(custom(header.replace('plk-license', 'plk-operation'), payload));
  modified.push(custom(header.replace('"alg":"EdDSA"', '"alg":"EdDSA","alg":"EdDSA"'), payload));
  modified.push(custom(header, payload.replace('"ownership":"perpetual"', '"ownership":"perpetual","ownership":"perpetual"')));
  modified.push(custom(header, payload.replace('"schema":', '"schema":"duplicate","schema":')));
  modified.push(request.body.token + '=');
  modified.push(request.body.token.replace(/.$/, ch => ch === 'A' ? 'B' : 'A'));
  return modified.map(token => ({ token }));
});
app.get('/v1/test/redirect', (_request, reply) => reply.redirect('/v1/test/bait'));
app.get('/v1/test/bait', () => { redirected++; return { unexpected: true }; });
app.get('/v1/test/oversized', (_request, reply) => reply.type('application/json').send('a'.repeat(1048577)));
app.get('/v1/test/chunked', (_request, reply) => reply.type('application/json').send(Readable.from([Buffer.alloc(524288, 97), Buffer.alloc(524290, 97)])));
const directory = mkdtempSync(join(tmpdir(), 'plk-native-sdk-'));
async function run(executable, arguments_) {
  return await new Promise((done, fail) => {
    const child = spawn(executable, arguments_, { cwd: root, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
    let output = '', errors = '', timedOut = false;
    const timer = setTimeout(() => { timedOut = true; child.kill(); }, 90000);
    child.stdout.on('data', value => { output += value; }); child.stderr.on('data', value => { errors += value; });
    child.on('error', error => { clearTimeout(timer); fail(error); });
    child.on('close', code => {
      clearTimeout(timer);
      if (code !== 0 || timedOut) return fail(new Error(`SDK_TEST_FAILED:${timedOut ? 'timeout' : code}\n${errors.slice(0, 4000)}`));
      try { done(JSON.parse(output.trim())); } catch { fail(new Error('INVALID_SDK_TEST_RESULT')); }
    });
  });
}
try {
  const origin = await app.listen({ host: '127.0.0.1', port: 0 });
  const cases = await Promise.all(h.people.slice(0, 2).map(async (person, index) => ({ algorithm: index ? 'PS256' : 'Ed25519',
    proof: person.proof, ticket: (await h.framework.issueInvitation('local', person.subject)).ticket,
    ...(language === 'rust' && index ? { privateKey: generateKeyPairSync('rsa', { modulusLength: 2048 }).privateKey.export({ type: 'pkcs8', format: 'pem' }).toString() } : {}) })));
  const configPath = join(directory, 'fixture.json');
  const config = { origin, adminToken, publicKey: h.serverKeys.publicKey, now: h.now(), cases,
    artifact: Buffer.from('synthetic native SDK artifact').toString('base64'), storageRoot: join(directory, 'identity'),
    storageAccountId: randomUUID(), rustStorageAccountId: randomUUID(), allowCreateIdentity: true };
  const writeConfig = () => writeFileSync(configPath, JSON.stringify(config), { mode: 0o600 });
  writeConfig();
  const dll = join(root, 'clients/dotnet/ProductLicenseKit.Tests/bin/Release/net10.0/ProductLicenseKit.Tests.dll');
  if (process.platform === 'win32') {
    const storage = await run(dotnet, [dll, '--storage', configPath]);
    config.protectedPublicKey = storage.publicKey;
    config.fingerprint = { schema: storage.fingerprint.Schema, digest: storage.fingerprint.Digest };
    config.allowCreateIdentity = false;
    writeConfig();
  }
  const executable = language === 'dotnet' ? dotnet : join(root, 'clients/rust/target/release/examples/interop' + (process.platform === 'win32' ? '.exe' : ''));
  const result = await run(executable, [...(language === 'dotnet' ? [dll] : []), '--interop', configPath]);
  let storageCrossRead = false;
  if (process.platform === 'win32' && language === 'rust') {
    config.storageAccountId = config.rustStorageAccountId; writeConfig();
    const storage = await run(dotnet, [dll, '--storage', configPath]);
    assert.equal(storage.publicKey, result.createdProtectedKey);
    assert.equal(storage.fingerprint.Digest, config.fingerprint.digest);
    storageCrossRead = true;
  }
  delete result.createdProtectedKey;
  assert.equal(result.cases, 2); assert.ok(result.checks >= 60);
  assert.deepEqual([...kinds].sort(), ['Ed25519', 'PS256']);
  assert.equal((await h.store.get('SELECT count(*) n FROM bindings')).n, 2);
  assert.equal((await h.store.get('SELECT count(*) n FROM entitlements WHERE active=1')).n, 2);
  assert.equal((await h.store.get('SELECT count(*) n FROM orders WHERE status=\'paid\'')).n, 2);
  assert.equal(redirected, 0);
  console.log(JSON.stringify({ ...result, backend, activeBindings: 2, paidSyntheticOrders: 2, redirectForwards: redirected, externalMessages: 0, storageCrossRead }));
} finally {
  await app.close(); await h.close();
  const exact = realpathSync(directory), expectedParent = realpathSync(tmpdir());
  assert.equal(dirname(exact).toLowerCase(), expectedParent.toLowerCase());
  assert.ok(exact.toLowerCase().startsWith(join(expectedParent, 'plk-native-sdk-').toLowerCase()));
  rmSync(exact, { recursive: true });
}
