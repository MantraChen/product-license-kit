import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import pg from 'pg';
import { Script } from 'node:vm';
import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import { writeFileSync } from 'node:fs';
import { mkdtempSync, readFileSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import {
  backupPostgres,
  restorePostgres,
} from '../../src/security/postgres-backup.js';
import { decryptBackup, encryptBackup } from '../../src/security/backup.js';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { AsyncFramework } from '../../src/async-service.js';
import {
  PostgresPortal,
  portalPermissions,
} from '../../src/adapters/postgres-portal.js';
import { createPortalApp } from '../../src/http/portal.js';
import { portalScript } from '../../src/http/portal-assets.js';
import { LocalIdentityProvider } from '../../src/adapters/local-identity.js';
import { EnvelopeSigner, sha256 } from '../../src/core/crypto.js';
import { totpCode } from '../../src/security/totp.js';
import { StorageError } from '../../src/core/async-store.js';
import { catalog, key, keyPair } from '../helpers.js';
import { activate } from '../contracts/domain.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(
  connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1',
  'Use scripts/test-postgres.mjs.',
);
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
async function fixture(t: TestContext) {
  const schema = 'plk_portal_' + randomUUID().replaceAll('-', ''),
    store = await PostgresStore.connect({
      connectionString: connection!,
      schema,
    });
  t.after(async () => {
    await store.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
  });
  const people = Array.from({ length: 3 }, (_, i) => ({
      subject: 'person-' + i,
      proof: key() + key(),
    })),
    serverKeys = keyPair(),
    framework = await AsyncFramework.create({
      store,
      issuer: 'synthetic-portal',
      catalog: catalog(),
      signer: new EnvelopeSigner(serverKeys.privateKey),
      providers: [new LocalIdentityProvider(people)],
    });
  const accounts: string[] = [];
  for (const person of people) {
    const invite = await framework.issueInvitation('local', person.subject);
    accounts.push(
      (await framework.register(invite.ticket, person.proof)).accountId,
    );
  }
  let exchanges = 0;
  const keyMaterial = randomBytes(32),
    options = {
      namespace: 'synthetic',
      origin: 'https://portal.example',
      encryptionKey: keyMaterial,
      provider: 'local',
      authorizationOrigin: 'https://identity.example',
      oauth: {
        authorizationUrl: (state: string) =>
          'https://identity.example/authorize?state=' + state,
        verify: async (code: string) => {
          exchanges++;
          const person = people[Number(code)];
          assert.ok(person);
          return { provider: 'local', subject: person.subject };
        },
      },
    };
  const portal = await PostgresPortal.create(framework, store, options),
    now = async () =>
      (await store.get<{ now: number }>(
        'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now',
      ))!.now;
  const begin = async (index = 0, remember = false, p = portal) => {
    const flow = await p.beginOAuth(remember),
      state = new URL(flow.authorizationUrl).searchParams.get('state')!,
      pending = await p.completeOAuth(state, flow.browser, String(index));
    return { ...pending, state, browser: flow.browser };
  };
  const login = async (index = 0, remember = false) => {
    const pending = await begin(index, remember),
      session = await portal.current(pending.token);
    assert.equal(session.stage, 'setup');
    const secret = session.setup!.secret,
      result = await portal.verifyMfa(
        pending.token,
        session.csrf,
        totpCode(secret, Math.floor((await now()) / 30000)),
      );
    return {
      ...result,
      secret,
      session: await portal.current(result.token),
      accountId: accounts[index]!,
    };
  };
  return {
    store,
    schema,
    framework,
    portal,
    options,
    serverKeys,
    accounts,
    people,
    begin,
    login,
    now,
    exchanges: () => exchanges,
  };
}

test('portal OAuth is bound to the initiating browser, consumed once before platform I/O and never exposes a native bearer before MFA', async (t) => {
  const f = await fixture(t),
    flow = await f.portal.beginOAuth(true),
    state = new URL(flow.authorizationUrl).searchParams.get('state')!;
  await assert.rejects(
    f.portal.completeOAuth(state, randomBytes(32).toString('base64url'), '0'),
    { code: 'OAUTH_STATE_INVALID' },
  );
  assert.equal(f.exchanges(), 0);
  const pending = await f.portal.completeOAuth(state, flow.browser, '0');
  assert.equal(f.exchanges(), 1);
  await assert.rejects(f.portal.completeOAuth(state, flow.browser, '0'), {
    code: 'OAUTH_STATE_INVALID',
  });
  assert.equal(f.exchanges(), 1);
  await assert.rejects(f.portal.userData(pending.token, 'profile'), {
    code: 'PORTAL_MFA_REQUIRED',
  });
  const data = await f.portal.current(pending.token);
  assert.equal(data.stage, 'setup');
  assert.ok(data.setup?.uri.startsWith('otpauth://totp/'));
  const stored = await f.store.get<{
    core_token: string;
    setup_secret: string;
    core_hash: string;
  }>('SELECT * FROM portal_sessions');
  assert.ok(!stored!.setup_secret.includes(data.setup!.secret));
  assert.notEqual(stored!.core_token, stored!.core_hash);
  assert.ok(!JSON.stringify(data).includes(stored!.core_token));
  await f.framework.revokeAccess(
    f.accounts[0]!,
    'test pending session revocation',
  );
  await assert.rejects(f.portal.current(pending.token), {
    code: 'PORTAL_AUTH_REQUIRED',
  });
});

test('MFA enrollment rotates cookies, enforces counter replay and one-use recovery, and honors remembered versus operator lifetimes', async (t) => {
  const f = await fixture(t),
    normal = await f.login(0, true);
  assert.equal(normal.recoveryCodes.length, 10);
  assert.ok(normal.maxAge >= 30 * 86400 - 1);
  const codes = await f.store.all<{ hash: string }>(
    'SELECT hash FROM portal_recovery',
  );
  assert.equal(codes.length, 10);
  assert.ok(!JSON.stringify(codes).includes(normal.recoveryCodes[0]!));
  const sameCode = totpCode(normal.secret, Math.floor((await f.now()) / 30000));
  await assert.rejects(
    f.portal.verifyMfa(normal.token, normal.session.csrf, sameCode),
    { code: 'MFA_CODE_INVALID' },
  );
  const pending = await f.begin(0),
    step = await f.portal.current(pending.token);
  assert.equal(step.stage, 'mfa');
  assert.equal(step.setup, undefined);
  const recovered = await f.portal.verifyMfa(
    pending.token,
    step.csrf,
    normal.recoveryCodes[0]!,
  );
  assert.equal(recovered.recoveryCodes.length, 0);
  await assert.rejects(f.portal.current(pending.token), {
    code: 'PORTAL_AUTH_REQUIRED',
  });
  const current = await f.portal.current(recovered.token);
  await assert.rejects(
    f.portal.verifyMfa(recovered.token, current.csrf, normal.recoveryCodes[0]!),
    { code: 'MFA_CODE_INVALID' },
  );
  await f.portal.bootstrapOperator(
    f.accounts[1]!,
    portalPermissions,
    'isolated operator bootstrap',
  );
  const staff = await f.login(1, true);
  assert.ok(staff.maxAge <= 7200);
  assert.ok(staff.session.permissions.includes('operators.write'));
  await f.store.run(
    'UPDATE portal_sessions SET last_seen=$2 WHERE hash=$1',
    sha256(staff.token),
    (await f.now()) - 31 * 60000,
  );
  await assert.rejects(f.portal.current(staff.token), {
    code: 'PORTAL_AUTH_REQUIRED',
  });
});

test('different node objects share encrypted MFA state, account attempt budgets and concurrent recovery-code consumption', async (t) => {
  const f = await fixture(t),
    owner = await f.login(),
    node = await PostgresPortal.create(f.framework, f.store, {
      ...f.options,
      encryptionKey: Buffer.from(f.options.encryptionKey),
    }),
    pending = await f.begin(0, false, node),
    state = await node.current(pending.token);
  const outcomes = await Promise.allSettled([
    node.verifyMfa(pending.token, state.csrf, owner.recoveryCodes[0]!),
    f.portal.verifyMfa(pending.token, state.csrf, owner.recoveryCodes[0]!),
  ]);
  assert.equal(
    outcomes.filter((result) => result.status === 'fulfilled').length,
    1,
  );
  const bad = await f.begin(),
    badState = await node.current(bad.token);
  for (let i = 0; i < 10; i++)
    await assert.rejects(
      node.verifyMfa(bad.token, badState.csrf, 'not-a-valid-code'),
    );
  await assert.rejects(
    f.portal.verifyMfa(bad.token, badState.csrf, owner.recoveryCodes[1]!),
    { code: 'MFA_RATE_LIMITED' },
  );
  const changed = randomBytes(32);
  await assert.rejects(
    PostgresPortal.create(f.framework, f.store, {
      ...f.options,
      encryptionKey: changed,
    }),
    { code: 'PORTAL_CONTEXT_CHANGED' },
  );
});

test('operators are live, permission-scoped, audited by account identity, and cannot remove the last owner', async (t) => {
  const f = await fixture(t);
  await f.portal.bootstrapOperator(
    f.accounts[0]!,
    portalPermissions,
    'isolated owner setup',
  );
  const owner = await f.login(),
    viewer = await f.login(1),
    ordinary = await f.login(2);
  await assert.rejects(f.portal.adminData(ordinary.token, 'audit'), {
    code: 'PORTAL_PERMISSION_DENIED',
  });
  await f.portal.adminWrite(owner.token, owner.session.csrf, 'operator', {
    accountId: viewer.accountId,
    reason: 'read only',
    permissions: ['audit.read'],
    enabled: true,
    revision: null,
  });
  await assert.rejects(f.portal.adminData(viewer.token, 'audit'), {
    code: 'MFA_REAUTH_REQUIRED',
  });
  const elevated = await f.portal.verifyMfa(
      viewer.token,
      viewer.session.csrf,
      viewer.recoveryCodes[0]!,
    ),
    active = await f.portal.current(elevated.token);
  assert.ok(await f.portal.adminData(elevated.token, 'audit'));
  await assert.rejects(
    f.portal.adminWrite(elevated.token, active.csrf, 'grant-credits', {
      accountId: ordinary.accountId,
      groupId: 'desktop',
      count: 1,
      commandKey: key(),
      reason: 'forbidden',
    }),
    { code: 'PORTAL_PERMISSION_DENIED' },
  );
  await assert.rejects(
    f.portal.adminWrite(owner.token, owner.session.csrf, 'operator', {
      accountId: owner.accountId,
      reason: 'remove only owner',
      permissions: [],
      enabled: false,
      revision: 0,
    }),
    { code: 'PORTAL_LAST_OWNER_REQUIRED' },
  );
  const commandKey = key(),
    request = {
      accountId: ordinary.accountId,
      groupId: 'desktop',
      count: 2,
      commandKey,
      reason: 'isolated approved grant',
    };
  await f.portal.adminWrite(
    owner.token,
    owner.session.csrf,
    'grant-credits',
    request,
  );
  await f.portal.adminWrite(
    owner.token,
    owner.session.csrf,
    'grant-credits',
    request,
  );
  assert.equal(
    (await f.store.get<{ balance: number }>(
      'SELECT balance FROM credits WHERE account_id=$1',
      ordinary.accountId,
    ))!.balance,
    2,
  );
  assert.ok(
    await f.store.get(
      "SELECT 1 FROM audit WHERE actor=$1 AND action='portal.admin.grant-credits'",
      owner.accountId,
    ),
  );
  await f.portal.adminWrite(owner.token, owner.session.csrf, 'operator', {
    accountId: viewer.accountId,
    reason: 'revoke read access',
    permissions: [],
    enabled: false,
    revision: 0,
  });
  await assert.rejects(f.portal.adminData(elevated.token, 'audit'), {
    code: 'PORTAL_PERMISSION_DENIED',
  });
});

test('device reset requires a fresh owned preview, explicit confirmation, unchanged cost and atomic single debit across concurrent confirmations', async (t) => {
  const f = await fixture(t),
    user = await f.login(),
    other = await f.login(1),
    order = await f.framework.createOrder(user.accountId, 'buy-tool-1', key());
  await f.framework.confirmPayment(order.orderId, {
    method: 'synthetic',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  await activate(f.framework, user.accountId);
  await f.framework.grantCredits(
    user.accountId,
    'desktop',
    2,
    'isolated reset credits',
    key(),
  );
  const preview = await f.portal.resetPreview(
    user.token,
    user.session.csrf,
    'desktop',
  );
  assert.equal(preview.cost, 'credit');
  await assert.rejects(
    f.portal.resetConfirm(user.token, user.session.csrf, preview.intent, false),
    { code: 'DEVICE_RESET_CONFIRMATION_REQUIRED' },
  );
  await assert.rejects(
    f.portal.resetConfirm(
      other.token,
      other.session.csrf,
      preview.intent,
      true,
    ),
    { code: 'RESET_INTENT_INVALID' },
  );
  await f.framework.grantCredits(
    user.accountId,
    'desktop',
    1,
    'changed quote',
    key(),
  );
  await assert.rejects(
    f.portal.resetConfirm(user.token, user.session.csrf, preview.intent, true),
    { code: 'DEVICE_RESET_PREVIEW_CHANGED' },
  );
  const reviewed = await f.portal.resetPreview(
      user.token,
      user.session.csrf,
      'desktop',
    ),
    results = await Promise.all([
      f.portal.resetConfirm(
        user.token,
        user.session.csrf,
        reviewed.intent,
        true,
      ),
      f.portal.resetConfirm(
        user.token,
        user.session.csrf,
        reviewed.intent,
        true,
      ),
    ]);
  assert.deepEqual(results[0], results[1]);
  assert.equal(
    (await f.store.get<{ balance: number }>(
      'SELECT balance FROM credits WHERE account_id=$1',
      user.accountId,
    ))!.balance,
    2,
  );
  assert.equal(
    (await f.store.get<{ n: number }>(
      "SELECT count(*)::int AS n FROM audit WHERE action='device.reset'",
    ))!.n,
    1,
  );
});

test('browser HTTP enforces origin/CSRF, HttpOnly host cookies, setup QR privacy and distinct staff routes without a deployment token', async (t) => {
  const f = await fixture(t),
    app = await createPortalApp(f.portal);
  t.after(() => app.close());
  new Script(portalScript);
  assert.equal((await app.inject('/api/profile')).statusCode, 401);
  assert.equal(
    (
      await app.inject({
        method: 'POST',
        url: '/api/auth/start',
        payload: { remember: true },
      })
    ).statusCode,
    403,
  );
  assert.equal(
    (
      await app.inject({
        method: 'POST',
        url: '/api/auth/start',
        headers: { origin: 'https://evil.example' },
        payload: { remember: true },
      })
    ).statusCode,
    403,
  );
  const begin = await app.inject({
    method: 'POST',
    url: '/api/auth/start',
    headers: { origin: f.options.origin },
    payload: { remember: true },
  });
  assert.equal(begin.statusCode, 200);
  const state = new URL(
      begin.json().authorizationUrl as string,
    ).searchParams.get('state')!,
    cookie = begin.cookies[0]!;
  assert.equal(cookie.name, '__Host-plk_oauth');
  assert.ok(cookie.httpOnly && cookie.secure);
  assert.equal(cookie.sameSite, 'Lax');
  const callback = await app.inject({
    url: '/auth/callback?state=' + state + '&code=0',
    cookies: { [cookie.name]: cookie.value },
  });
  assert.equal(callback.statusCode, 302);
  const portalCookie = callback.cookies.find(
      (item) => item.name === '__Host-plk_portal',
    )!,
    cookies = { [portalCookie.name]: portalCookie.value },
    setup = await app.inject({ url: '/api/session', cookies });
  assert.equal(setup.json().stage, 'setup');
  const qr = await app.inject({ url: '/api/setup-qr', cookies });
  assert.equal(qr.headers['content-type'], 'image/png');
  assert.ok(qr.rawPayload.length > 100);
  assert.equal(qr.headers['cache-control'], 'no-store');
  assert.equal(
    (await app.inject({ url: '/api/profile', cookies })).statusCode,
    401,
  );
  const code = totpCode(
    setup.json().setup.secret as string,
    Math.floor((await f.now()) / 30000),
  );
  assert.equal(
    (
      await app.inject({
        method: 'POST',
        url: '/api/auth/mfa',
        cookies,
        headers: { origin: f.options.origin },
        payload: { code },
      })
    ).statusCode,
    403,
  );
  const verified = await app.inject({
    method: 'POST',
    url: '/api/auth/mfa',
    cookies,
    headers: {
      origin: f.options.origin,
      'x-csrf-token': setup.json().csrf as string,
    },
    payload: { code },
  });
  assert.equal(verified.statusCode, 200);
  assert.equal(verified.json().token, undefined);
  assert.equal(verified.json().accessToken, undefined);
  assert.equal(verified.json().recoveryCodes.length, 10);
  const active = verified.cookies[0]!;
  assert.notEqual(active.value, portalCookie.value);
  const activeCookies = { [active.name]: active.value };
  assert.equal(
    (await app.inject({ url: '/api/profile', cookies: activeCookies }))
      .statusCode,
    200,
  );
  assert.equal(
    (await app.inject({ url: '/api/admin/operators', cookies: activeCookies }))
      .statusCode,
    403,
  );
  assert.equal(
    (
      await app.inject({
        url: '/api/admin/operators',
        headers: {
          authorization: 'Bearer ' + randomBytes(32).toString('base64url'),
        },
      })
    ).statusCode,
    401,
  );
  const html = await app.inject('/admin');
  assert.ok(html.body.includes('HttpOnly'));
  assert.match(
    String(html.headers['content-security-policy']),
    /frame-ancestors 'none'/,
  );
  assert.ok(!html.body.includes('adminToken'));
});

test('audit failure rolls back debit and intent receipt; a lost commit is reconciled by the same owned intent without a second reset', async (t) => {
  const f = await fixture(t),
    user = await f.login(),
    order = await f.framework.createOrder(user.accountId, 'buy-tool-1', key());
  await f.framework.confirmPayment(order.orderId, {
    method: 'synthetic',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  await activate(f.framework, user.accountId);
  await f.framework.grantCredits(
    user.accountId,
    'desktop',
    2,
    'synthetic',
    key(),
  );
  const preview = await f.portal.resetPreview(
    user.token,
    user.session.csrf,
    'desktop',
  );
  await admin.query(
    `CREATE FUNCTION "${f.schema}".reject_portal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='portal.device.reset-confirmed' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$`,
  );
  await admin.query(
    `CREATE TRIGGER reject_portal BEFORE INSERT ON "${f.schema}".audit FOR EACH ROW EXECUTE FUNCTION "${f.schema}".reject_portal()`,
  );
  await assert.rejects(
    f.portal.resetConfirm(user.token, user.session.csrf, preview.intent, true),
    { code: 'POSTGRES_QUERY_FAILED' },
  );
  assert.equal(
    (await f.store.get<{ balance: number }>(
      'SELECT balance FROM credits WHERE account_id=$1',
      user.accountId,
    ))!.balance,
    2,
  );
  await admin.query(`DROP TRIGGER reject_portal ON "${f.schema}".audit`);
  let lost = false;
  const real = f.store.transaction.bind(f.store);
  f.store.transaction = async (work) => {
    const result = await real(work);
    if (!lost) {
      lost = true;
      throw new StorageError('TRANSACTION_COMMIT_UNCERTAIN');
    }
    return result;
  };
  await assert.rejects(
    f.portal.resetConfirm(user.token, user.session.csrf, preview.intent, true),
    { code: 'TRANSACTION_COMMIT_UNCERTAIN' },
  );
  await f.portal.resetConfirm(
    user.token,
    user.session.csrf,
    preview.intent,
    true,
  );
  assert.equal(
    (await f.store.get<{ balance: number }>(
      'SELECT balance FROM credits WHERE account_id=$1',
      user.accountId,
    ))!.balance,
    1,
  );
});

test('MFA setup rollback cannot enable an account or publish recovery secrets when its audit fails', async (t) => {
  const f = await fixture(t),
    pending = await f.begin(),
    setup = await f.portal.current(pending.token),
    code = totpCode(setup.setup!.secret, Math.floor((await f.now()) / 30000));
  await admin.query(
    `CREATE FUNCTION "${f.schema}".reject_mfa() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='portal.mfa.enrolled' THEN RAISE EXCEPTION 'synthetic'; END IF; RETURN NEW; END $$`,
  );
  await admin.query(
    `CREATE TRIGGER reject_mfa BEFORE INSERT ON "${f.schema}".audit FOR EACH ROW EXECUTE FUNCTION "${f.schema}".reject_mfa()`,
  );
  await assert.rejects(f.portal.verifyMfa(pending.token, setup.csrf, code), {
    code: 'POSTGRES_QUERY_FAILED',
  });
  assert.equal((await f.portal.current(pending.token)).stage, 'setup');
  assert.equal(
    (await f.store.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM portal_mfa',
    ))!.n,
    0,
  );
});

test('named management issues one-use invitations, requires explicit manual receipt confirmation and revokes disabled browser sessions', async (t) => {
  const f = await fixture(t);
  await f.portal.bootstrapOperator(
    f.accounts[0]!,
    portalPermissions,
    'isolated management owner',
  );
  const owner = await f.login(),
    user = await f.login(1);
  const issued = (await f.portal.adminWrite(
    owner.token,
    owner.session.csrf,
    'invitation',
    {
      provider: 'local',
      subject: 'new-person',
      reason: 'approved single registration',
    },
  )) as { ticket: string };
  assert.ok(issued.ticket);
  const newPerson = { subject: 'new-person', proof: key() + key() },
    otherFramework = await AsyncFramework.create({
      store: f.store,
      issuer: f.framework.issuer,
      catalog: catalog(),
      signer: new EnvelopeSigner(f.serverKeys.privateKey),
      providers: [new LocalIdentityProvider([...f.people, newPerson])],
    });
  const registration = await otherFramework.register(
    issued.ticket,
    newPerson.proof,
  );
  assert.ok(registration.accountId);
  await assert.rejects(
    otherFramework.register(issued.ticket, newPerson.proof),
    { code: 'INVALID_INVITATION' },
  );
  const order = await f.framework.createOrder(
      user.accountId,
      'buy-tool-1',
      key(),
    ),
    payment = {
      accountId: user.accountId,
      orderId: order.orderId,
      method: 'synthetic-manual',
      reference: key(),
      amount: order.offer.amount,
      currency: order.offer.currency,
      reason: 'verified synthetic receipt',
      confirmed: true,
    };
  await assert.rejects(
    f.portal.adminWrite(owner.token, owner.session.csrf, 'payment', {
      ...payment,
      confirmed: false,
    }),
  );
  await assert.rejects(
    f.portal.adminWrite(owner.token, owner.session.csrf, 'payment', {
      ...payment,
      accountId: owner.accountId,
    }),
    { code: 'ORDER_NOT_FOUND' },
  );
  await f.portal.adminWrite(
    owner.token,
    owner.session.csrf,
    'payment',
    payment,
  );
  await f.portal.adminWrite(
    owner.token,
    owner.session.csrf,
    'payment',
    payment,
  );
  assert.equal(
    (await f.store.get<{ n: number }>(
      "SELECT count(*)::int AS n FROM outbox WHERE topic='order.fulfilled'",
    ))!.n,
    1,
  );
  assert.ok(
    await f.store.get(
      "SELECT 1 FROM audit WHERE actor=$1 AND action='portal.admin.payment'",
      owner.accountId,
    ),
  );
  await f.portal.adminWrite(owner.token, owner.session.csrf, 'account-status', {
    accountId: user.accountId,
    active: false,
    reason: 'isolated disable verification',
  });
  await assert.rejects(f.portal.current(user.token), {
    code: 'PORTAL_AUTH_REQUIRED',
  });
});

test('encrypted recovery requires the portal key, clears all browser grants and preserves MFA, operators, paid rights and replay counters', async (t) => {
  const f = await fixture(t);
  await f.portal.bootstrapOperator(
    f.accounts[0]!,
    portalPermissions,
    'isolated recovery owner',
  );
  const user = await f.login(),
    order = await f.framework.createOrder(user.accountId, 'buy-tool-1', key());
  await f.framework.confirmPayment(order.orderId, {
    method: 'synthetic',
    reference: key(),
    amount: order.offer.amount,
    currency: order.offer.currency,
  });
  await activate(f.framework, user.accountId);
  await f.framework.grantCredits(
    user.accountId,
    'desktop',
    2,
    'synthetic',
    key(),
  );
  await f.portal.resetPreview(user.token, user.session.csrf, 'desktop');
  await f.portal.beginOAuth(true);
  const root = mkdtempSync(join(tmpdir(), 'plk-portal-restore-')),
    targetSchema = 'plk_portal_restored_' + randomUUID().replaceAll('-', ''),
    target = await PostgresStore.connect({
      connectionString: connection!,
      schema: targetSchema,
    });
  t.after(async () => {
    await target.close();
    await admin.query(`DROP SCHEMA "${targetSchema}" CASCADE`);
    const exact = realpathSync(root),
      parent = realpathSync(tmpdir());
    assert.equal(dirname(exact).toLowerCase(), parent.toLowerCase());
    assert.ok(
      exact
        .toLowerCase()
        .startsWith(join(parent, 'plk-portal-restore-').toLowerCase()),
    );
    rmSync(exact, { recursive: true });
  });
  const settings = {
    directory: root,
    password: 'synthetic-portal-backup-password',
    privateKeys: [f.serverKeys.privateKey],
  };
  await assert.rejects(backupPostgres(f.store, settings), {
    code: 'POSTGRES_BACKUP_PORTAL_KEY_MISSING',
  });
  const saved = await backupPostgres(f.store, {
      ...settings,
      portalKeys: [
        { namespace: f.options.namespace, key: f.options.encryptionKey },
      ],
    }),
    bundle = readFileSync(saved.path),
    files = decryptBackup(bundle, settings.password),
    name = 'portal-' + sha256(f.options.namespace).slice(0, 24) + '.key';
  assert.ok(files[name]!.equals(f.options.encryptionKey));
  assert.ok(!bundle.includes(f.options.encryptionKey));
  const altered = { ...files, [name]: randomBytes(32) };
  await assert.rejects(
    restorePostgres(
      target,
      encryptBackup(altered, settings.password),
      settings.password,
      { actor: 'owner', reason: 'reject wrong MFA key', expectedPolicies: {} },
    ),
    { code: 'POSTGRES_BACKUP_PORTAL_KEY_INVALID' },
  );
  await restorePostgres(target, bundle, settings.password, {
    actor: 'owner',
    reason: 'isolated complete recovery',
    expectedPolicies: {},
  });
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM portal_sessions',
    ))!.n,
    0,
  );
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM portal_oauth_states',
    ))!.n,
    0,
  );
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM portal_reset_intents',
    ))!.n,
    0,
  );
  const framework = await AsyncFramework.create({
      store: target,
      issuer: f.framework.issuer,
      catalog: catalog(),
      signer: new EnvelopeSigner(f.serverKeys.privateKey),
      providers: [new LocalIdentityProvider(f.people)],
    }),
    portal = await PostgresPortal.create(framework, target, f.options);
  await assert.rejects(portal.current(user.token), {
    code: 'PORTAL_AUTH_REQUIRED',
  });
  const flow = await portal.beginOAuth(false),
    pending = await portal.completeOAuth(
      new URL(flow.authorizationUrl).searchParams.get('state')!,
      flow.browser,
      '0',
    ),
    session = await portal.current(pending.token);
  assert.equal(session.stage, 'mfa');
  await assert.rejects(
    portal.verifyMfa(pending.token, session.csrf, user.recoveryCodes[0]!),
    { code: 'MFA_RATE_LIMITED' },
  );
  // Restored budgets stay exhausted until the original window ends. Simulate that clock boundary, never clear it in production.
  await target.run('UPDATE rate_limit_buckets SET expires_at=0');
  const active = await portal.verifyMfa(
    pending.token,
    session.csrf,
    user.recoveryCodes[0]!,
  );
  assert.ok(
    (await portal.current(active.token)).permissions.includes(
      'operators.write',
    ),
  );
  assert.equal(
    (await target.get<{ status: string }>(
      'SELECT status FROM orders WHERE id=$1',
      order.orderId,
    ))!.status,
    'paid',
  );
  assert.equal(
    (await target.get<{ balance: number }>(
      'SELECT balance FROM credits WHERE account_id=$1',
      user.accountId,
    ))!.balance,
    2,
  );
});

test('the standalone portal starts from private configuration, serves its own pages and builds a confidential OAuth redirect without platform I/O', async (t) => {
  const f = await fixture(t),
    root = mkdtempSync(join(tmpdir(), 'plk-portal-entry-')),
    probe = createServer();
  await new Promise<void>((done) => probe.listen(0, '127.0.0.1', done));
  const address = probe.address();
  assert.ok(address && typeof address === 'object');
  const port = address.port;
  await new Promise<void>((done) => probe.close(() => done()));
  const botProbe = createServer();
  await new Promise<void>((done) => botProbe.listen(0, '127.0.0.1', done));
  const botAddress = botProbe.address();
  assert.ok(botAddress && typeof botAddress === 'object');
  const botPort = botAddress.port;
  await new Promise<void>((done) => botProbe.close(() => done()));
  const origin = 'http://127.0.0.1:' + port,
    secret = 'synthetic-platform-secret-20261118',
    configFile = join(root, 'private.json');
  writeFileSync(join(root, 'signing.pem'), f.serverKeys.privateKey);
  writeFileSync(join(root, 'portal.key'), randomBytes(32));
  writeFileSync(join(root, 'oauth-secret.txt'), secret);
  writeFileSync(join(root, 'catalog.json'), JSON.stringify(catalog()));
  writeFileSync(join(root, 'bot-token.txt'), 'synthetic-bot-token');
  writeFileSync(
    join(root, 'verify-token.txt'),
    'synthetic-webhook-verification',
  );
  writeFileSync(
    configFile,
    JSON.stringify({
      connectionString: connection!,
      schema: f.schema,
      host: '127.0.0.1',
      port,
      origin,
      issuer: f.framework.issuer,
      namespace: 'reference-entry',
      catalogPath: 'catalog.json',
      keyFiles: ['signing.pem'],
      portalKeyFile: 'portal.key',
      kookClientId: 'synthetic-client-id',
      kookSecretFile: 'oauth-secret.txt',
      kookBot: {
        namespace: 'reference-bot',
        botId: '90001',
        tokenFile: 'bot-token.txt',
        verifyTokenFile: 'verify-token.txt',
        compressed: false,
        guildId: '80001',
        anyRoleIds: [7],
        admissionVersion: 'synthetic-v1',
        port: botPort,
      },
    }),
  );
  const child = spawn(process.execPath, ['examples/portal-server.mjs'], {
    env: { ...process.env, PLK_PORTAL_CONFIG_FILE: configFile },
    windowsHide: true,
    stdio: ['ignore', 'pipe', 'pipe', 'ipc'],
  });
  let output = '';
  child.stdout!.on('data', (part) => (output += part));
  child.stderr!.on('data', (part) => (output += part));
  let ended = false;
  const exited = new Promise<number | null>((done, fail) => {
    child.once('error', fail);
    child.once('close', (code) => {
      ended = true;
      done(code);
    });
  });
  t.after(async () => {
    if (!ended) child.send('stop');
    assert.equal(await exited, 0);
    assert.equal(output.includes(connection!), false);
    assert.equal(output.includes(secret), false);
    const exact = realpathSync(root),
      parent = realpathSync(tmpdir());
    assert.equal(dirname(exact).toLowerCase(), parent.toLowerCase());
    assert.ok(
      exact
        .toLowerCase()
        .startsWith(join(parent, 'plk-portal-entry-').toLowerCase()),
    );
    rmSync(exact, { recursive: true });
  });
  await Promise.race([
    new Promise<void>((done) =>
      child.on('message', (message) => {
        if ((message as { type?: string }).type === 'ready') done();
      }),
    ),
    exited.then(() => {
      throw new Error('PORTAL_EXITED_BEFORE_READY');
    }),
  ]);
  assert.equal(
    (await fetch(origin + '/health', { signal: AbortSignal.timeout(10000) }))
      .status,
    200,
  );
  assert.ok(
    (
      await (
        await fetch(origin + '/admin', { signal: AbortSignal.timeout(10000) })
      ).text()
    ).includes('HttpOnly'),
  );
  const start = await fetch(origin + '/api/auth/start', {
    method: 'POST',
    headers: { Origin: origin, 'Content-Type': 'application/json' },
    body: JSON.stringify({ remember: true }),
    signal: AbortSignal.timeout(10000),
  });
  assert.equal(start.status, 200);
  const location = new URL(
    ((await start.json()) as { authorizationUrl: string }).authorizationUrl,
  );
  assert.equal(location.origin, 'https://www.kookapp.cn');
  assert.equal(location.searchParams.get('client_id'), 'synthetic-client-id');
  assert.equal(
    location.searchParams.get('redirect_uri'),
    origin + '/auth/callback',
  );
  assert.equal(location.href.includes(secret), false);
  const challenge = await fetch('http://127.0.0.1:' + botPort + '/webhook', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      s: 0,
      d: {
        type: 255,
        channel_type: 'WEBHOOK_CHALLENGE',
        challenge: 'synthetic-entry',
        verify_token: 'synthetic-webhook-verification',
      },
    }),
    signal: AbortSignal.timeout(10000),
  });
  assert.equal(challenge.status, 200);
  assert.deepEqual(await challenge.json(), { challenge: 'synthetic-entry' });
});
