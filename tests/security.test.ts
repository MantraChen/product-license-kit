import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { execFileSync } from 'node:child_process';
import { harness, key, catalog } from './helpers.js';
import { Framework } from '../src/service.js';
import { signChallenge } from '../src/sdk/client.js';
import { guardBrowserRequest } from '../src/security/browser.js';
import { encryptBackup, decryptBackup, restoreBackup } from '../src/security/backup.js';
import { privateDirectory } from '../src/security/private-storage.js';
import { hashPassword } from '../src/security/password.js';
import { trustedProxies } from '../src/security/proxy.js';
import { createApp } from '../src/http/app.js';
import { writePrivateAtomic } from '../src/security/private-storage.js';
import { rotateSigningKey } from '../src/security/signing-rotation.js';
import { assertServiceStopped, acquireServiceLock } from '../src/security/process-lock.js';
import { EnvelopeSigner, verifyEnvelope } from '../src/core/crypto.js';
import { SqliteStore, backupDatabase } from '../src/adapters/sqlite.js';

test('account suspension revokes sessions and challenges and blocks command-cache replay', async t => {
  const h = harness(); t.after(h.close);
  const account = await h.register(); h.buy(account.accountId);
  const enrollment = h.enrollment(account.accountId), command = key();
  const device = h.framework.activate(account.accountId, enrollment.challenge.challengeId, enrollment.signature, command);
  const challenge = h.framework.licenseChallenge(device.deviceId, 'tool-1');
  h.framework.setAccountActive(account.accountId, false, 'security incident');
  assert.throws(() => h.framework.authenticate(account.accessToken));
  assert.throws(() => h.framework.activate(account.accountId, enrollment.challenge.challengeId, enrollment.signature, command), /ACCOUNT_DISABLED/);
  assert.throws(() => h.framework.enrollmentChallenge(account.accountId, 'desktop', enrollment.pair.publicKey, {schema:'test', digest:'a'.repeat(64)}), /ACCOUNT_DISABLED/);
  assert.throws(() => h.framework.licenseChallenge(device.deviceId, 'tool-1'));
  assert.throws(() => h.framework.issueLicense(challenge.challengeId, signChallenge(challenge.message, enrollment.pair.privateKey)));
  await assert.rejects(h.framework.login('local', h.people[0]!.proof), /ACCOUNT_DISABLED/);
  assert.throws(() => h.framework.distributions(account.accountId), /ACCOUNT_DISABLED/);
  h.framework.setAccountActive(account.accountId, true, 'incident resolved');
  assert.throws(() => h.framework.authenticate(account.accessToken));
  assert.throws(() => h.framework.licenseChallenge(device.deviceId, 'tool-1'));
  const active = h.activate(account.accountId, enrollment.pair);
  assert.equal(active.binding.freeAt, device.freeAt);
  assert.ok(h.issue(active.binding.deviceId, enrollment.pair.privateKey).token);
});

test('product policy applies inside core authorization, including already-issued challenges', async t => {
  const h = harness(); t.after(h.close);
  const account = await h.register(); h.buy(account.accountId);
  const device = h.activate(account.accountId), original = h.framework;
  let active = true;
  const core = new Framework({ store: h.store, catalog: catalog(), signer: original.signer,
    issuer: original.issuer, providers: [...original.providers.values()], now: h.now, accountEnabled: () => active });
  const challenge = core.licenseChallenge(device.binding.deviceId, 'tool-1');
  const reserve = key(); core.reserveDistribution(account.accountId, 'tool-1', 'r1', reserve);
  active = false;
  assert.throws(() => core.issueLicense(challenge.challengeId, signChallenge(challenge.message, device.pair.privateKey)), /ACCOUNT_DISABLED/);
  assert.throws(() => core.licenseChallenge(device.binding.deviceId, 'tool-1'), /ACCOUNT_DISABLED/);
  assert.throws(() => core.reserveDistribution(account.accountId, 'tool-1', 'r1', reserve), /ACCOUNT_DISABLED/);
  assert.throws(() => core.authenticate(account.accessToken), /ACCOUNT_DISABLED/);
  assert.equal(h.store.get<{used_at:null}>('SELECT used_at FROM challenges WHERE id=?', challenge.challengeId)!.used_at, null);
});

test('nested account and product state updates roll back together', async t => {
  const h = harness(); t.after(h.close);
  const account = await h.register();
  assert.throws(() => h.store.transaction(() => {
    h.framework.setAccountActive(account.accountId, false, 'atomic test');
    throw new Error('product update failed');
  }), /product update failed/);
  assert.equal(h.framework.authenticate(account.accessToken), account.accountId);
  assert.equal(h.framework.isAccountActive(account.accountId), true);
  assert.equal(h.store.get("SELECT 1 FROM audit WHERE action='account.disabled'"), undefined);
});

test('browser guard uses matched routes and checks origin and CSRF independently', () => {
  const policy = {origin:'https://portal.example', protectedPrefixes:['/api/'], publicWrites:['/api/login'], machinePrefixes:['/api/bot/']};
  const req = {method:'POST', matchedRoute:'/api/orders'};
  assert.throws(() => guardBrowserRequest(req, policy, () => 'secret'), /ORIGIN_REQUIRED/);
  assert.throws(() => guardBrowserRequest({...req, origin:policy.origin}, policy, () => 'secret'), /CSRF_REJECTED/);
  assert.throws(() => guardBrowserRequest({...req, origin:'https://other.example', csrfToken:'secret'}, policy, () => 'secret'), /ORIGIN_REJECTED/);
  guardBrowserRequest({...req, origin:policy.origin, csrfToken:'secret'}, policy, () => 'secret');
  guardBrowserRequest({...req, matchedRoute:'/api/login', origin:policy.origin}, policy, () => {throw new Error('must not require login');});
  guardBrowserRequest({...req, matchedRoute:'/api/bot/orders'}, policy, () => {throw new Error('machine auth is separate');});
});

test('backup preserves WAL changes, rejects tampering and restores only to new private directories', async t => {
  const h = harness(); t.after(h.close);
  const account = await h.register(); h.buy(account.accountId);
  const root = privateDirectory(mkdtempSync(join(tmpdir(), 'plk-backup-')));
  const path = join(root, 'snapshot.sqlite');
  h.store.backup(path);
  assert.throws(() => h.store.backup(path), /BACKUP_ALREADY_EXISTS/);
  const password = 'synthetic-backup-password-123456';
  const bundle = encryptBackup({'framework.sqlite':readFileSync(path), 'signing.pem':Buffer.from(h.serverKeys.privateKey)}, password);
  assert.ok(!bundle.includes(Buffer.from(h.serverKeys.privateKey)));
  assert.throws(() => decryptBackup(bundle, 'incorrect-backup-password'), /BACKUP_AUTH_FAILED/);
  const damaged = Buffer.from(bundle); damaged[damaged.length - 1] = damaged[damaged.length - 1]! ^ 1;
  assert.throws(() => decryptBackup(damaged, password), /BACKUP_AUTH_FAILED/);
  const restored = join(root, 'restored');
  restoreBackup(bundle, password, restored);
  assert.throws(() => restoreBackup(bundle, password, restored), /RESTORE_TARGET_EXISTS/);
  const db = new DatabaseSync(join(restored, 'framework.sqlite'), {readOnly:true});
  try {
    assert.equal(db.prepare('PRAGMA integrity_check').get()!.integrity_check, 'ok');
    assert.equal(db.prepare('SELECT count(*) AS n FROM entitlements WHERE account_id=?').get(account.accountId)!.n, 1);
    assert.equal(db.prepare('PRAGMA foreign_key_check').all().length, 0);
  } finally { db.close(); }
  assert.equal(readFileSync(join(restored, 'signing.pem'), 'utf8'), h.serverKeys.privateKey);
  assert.throws(() => encryptBackup({'../escape':Buffer.from('no')}, password), /INVALID_BACKUP_FILENAME/);
  assert.throws(() => encryptBackup({'CON':Buffer.from('no')}, password), /INVALID_BACKUP_FILENAME/);
  assert.equal(existsSync(join(root, 'escape')), false);
  if (process.platform === 'win32') {
    const count = execFileSync('powershell.exe', ['-NoProfile','-Command',
      "$a=Get-Acl -LiteralPath $env:PLK_TEST_PATH; @($a.Access | Where-Object {$_.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -in @('S-1-1-0','S-1-5-11','S-1-5-32-545')}).Count"],
    {encoding:'utf8', windowsHide:true, env:{...process.env, PLK_TEST_PATH:join(restored, 'signing.pem'), PSModulePath:undefined}});
    assert.equal(count.trim(), '0');
  }
});

test('password hashing rejects excess queued work without changing the scrypt format', async () => {
  const results = await Promise.allSettled(Array.from({length:40}, () => hashPassword('synthetic-password', 'synthetic-salt')));
  const successes = results.filter(result => result.status === 'fulfilled');
  assert.equal(successes.length, 36);
  assert.ok(results.filter(result => result.status === 'rejected').every(result => /AUTH_BUSY/.test(String(result.reason))));
  assert.equal(new Set(successes.map(result => result.value)).size, 1);
  assert.equal((await hashPassword('synthetic-password', 'synthetic-salt')).length, 128);
});

test('trusted proxy policy rejects global or implicit trust and ignores spoofed forwarding from untrusted peers', async t => {
  assert.equal(trustedProxies(''), false);
  for (const value of ['true','1','0.0.0.0/0','::/0','example.com','127.0.0.1/33']) assert.throws(() => trustedProxies(value));
  const h = harness(); t.after(h.close);
  const app = await createApp(h.framework, {adminToken:key()+key(), trustedProxyCidrs:'127.0.0.1/32'}); t.after(() => app.close());
  app.get('/test-ip', request => ({ip:request.ip}));
  const untrusted = await app.inject({url:'/test-ip', remoteAddress:'203.0.113.9', headers:{'x-forwarded-for':'198.51.100.2'}});
  assert.equal(untrusted.json().ip, '203.0.113.9');
  const trusted = await app.inject({url:'/test-ip', remoteAddress:'127.0.0.1', headers:{'x-forwarded-for':'198.51.100.2'}});
  assert.equal(trusted.json().ip, '198.51.100.2');
});

test('signing rotation keeps public history and old signatures do not verify under the new key', async t => {
  const h = harness(); t.after(h.close);
  const root = privateDirectory(mkdtempSync(join(tmpdir(), 'plk-rotate-')));
  writePrivateAtomic(join(root, 'signing.pem'), h.serverKeys.privateKey);
  const original = h.framework.signer.sign({test:true}, 'plk-license');
  const rotated = rotateSigningKey(root);
  const next = new EnvelopeSigner(readFileSync(join(root, 'signing.pem'), 'utf8'));
  assert.notEqual(rotated.kid, rotated.previousKid);
  assert.equal(rotated.kid, next.kid);
  assert.throws(() => verifyEnvelope(original, next.publicKey, 'plk-license'));
  assert.deepEqual(verifyEnvelope(original, JSON.parse(readFileSync(join(root, 'signing-public-history.json'), 'utf8'))[rotated.previousKid], 'plk-license'), {test:true});
});

test('service lock refuses a second live instance and releases cleanly', () => {
  const root = privateDirectory(mkdtempSync(join(tmpdir(), 'plk-lock-'))), path = join(root, 'service.lock');
  const release = acquireServiceLock(path);
  try {
    assert.throws(() => assertServiceStopped(path), /SERVICE_MUST_BE_STOPPED/);
    assert.throws(() => acquireServiceLock(path), /SERVICE_MUST_BE_STOPPED/);
    assert.ok(existsSync(path));
  } finally { release(); }
  assertServiceStopped(path);
  const again = acquireServiceLock(path); again();
});

test('additive migrations preserve legacy accounts and are idempotent', () => {
  const root = privateDirectory(mkdtempSync(join(tmpdir(), 'plk-migrate-'))), path = join(root, 'legacy.sqlite');
  const old = new DatabaseSync(path);
  old.exec("CREATE TABLE accounts(id TEXT PRIMARY KEY, provider TEXT NOT NULL,subject TEXT NOT NULL,created_at INTEGER NOT NULL,UNIQUE(provider,subject)); INSERT INTO accounts VALUES('legacy','local','legacy-person',1)");
  old.exec(`CREATE TABLE orders(id TEXT PRIMARY KEY,account_id TEXT NOT NULL REFERENCES accounts(id),offer_json TEXT NOT NULL,
    status TEXT NOT NULL,created_at INTEGER NOT NULL,paid_at INTEGER,payment_method TEXT,payment_reference TEXT);
    INSERT INTO orders VALUES('old-order','legacy','{}','paid',1,1,'manual-bank','old-reference');
    CREATE TABLE entitlements(account_id TEXT NOT NULL REFERENCES accounts(id),edition_id TEXT NOT NULL,
      order_id TEXT NOT NULL REFERENCES orders(id),active INTEGER NOT NULL,PRIMARY KEY(account_id,edition_id));
    INSERT INTO entitlements VALUES('legacy','tool-1','old-order',1);`);
  old.close();
  backupDatabase(path, join(root, 'before-upgrade.sqlite'));
  const untouched = new DatabaseSync(join(root, 'before-upgrade.sqlite'), {readOnly:true});
  assert.equal(untouched.prepare("SELECT name FROM sqlite_master WHERE name='plk_migrations'").get(), undefined);
  untouched.close();
  for (let i = 0; i < 2; i++) {
    const db = new SqliteStore(path);
    try {
      assert.equal(db.get<{n:number}>('SELECT count(*) AS n FROM accounts')!.n, 1);
      assert.equal(db.get<{n:number}>('SELECT count(*) AS n FROM plk_migrations WHERE version=2')!.n, 1);
      assert.equal(db.get<{n:number}>('SELECT count(*) AS n FROM plk_migrations WHERE version=3')!.n, 1);
      assert.equal(db.get<{order_id:string}>('SELECT order_id FROM entitlements')!.order_id, 'old-order');
      assert.equal(db.all<{name:string;notnull:number}>('PRAGMA table_info(entitlements)').find(c => c.name === 'order_id')!.notnull, 0);
      assert.equal(db.all('PRAGMA foreign_key_check').length, 0);
    } finally { db.close(); }
  }
});
