import test, { after, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes, randomUUID } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, realpathSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { Script } from 'node:vm';
import pg from 'pg';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { AsyncFramework } from '../../src/async-service.js';
import { PostgresPortal } from '../../src/adapters/postgres-portal.js';
import { PostgresKookBot } from '../../src/adapters/postgres-kook-bot.js';
import { PostgresNotificationWorker } from '../../src/adapters/postgres-notifications.js';
import {
  KookApiError,
  type KookBotApi,
  type KookPrivateMessage,
} from '../../src/adapters/kook-bot-api.js';
import { createKookBotApp } from '../../src/http/kook-bot.js';
import { createPortalApp } from '../../src/http/portal.js';
import { portalScript } from '../../src/http/portal-assets.js';
import { EnvelopeSigner, sha256 } from '../../src/core/crypto.js';
import { totpCode } from '../../src/security/totp.js';
import {
  backupPostgres,
  restorePostgres,
} from '../../src/security/postgres-backup.js';
import { catalog, keyPair } from '../helpers.js';

const connection = process.env.PLK_TEST_POSTGRES_URL;
assert.ok(
  connection && process.env.PLK_TEST_POSTGRES_SCOPED === '1',
  'Use scripts/test-postgres.mjs.',
);
const admin = new pg.Pool({ connectionString: connection, max: 2 });
after(() => admin.end());
const verifyToken = 'synthetic-kook-webhook-verification',
  botId = '900001',
  users = ['100001', '100002', '100003'];
class SyntheticKook implements KookBotApi {
  readonly messages = new Map<
    string,
    KookPrivateMessage & { userId: string }
  >();
  readonly sent: { id: string; userId: string; content: string }[] = [];
  readonly allowed = new Set(users);
  mode: 'ok' | 'lost' | 'reject' = 'ok';
  reads = 0;
  async me() {
    this.reads++;
    return botId;
  }
  async admitted(userId: string) {
    return this.allowed.has(userId);
  }
  async conversation(userId: string) {
    this.reads++;
    return 'mobile-private-chat-with-a-long-target-code-' + userId;
  }
  async message(chatCode: string, id: string) {
    this.reads++;
    const value = this.messages.get(id);
    assert.ok(value);
    assert.equal(
      chatCode,
      'mobile-private-chat-with-a-long-target-code-' + value.userId,
    );
    return value;
  }
  async send(userId: string, content: string) {
    if (this.mode === 'reject') throw new KookApiError(true);
    const id = 'message-' + randomUUID();
    this.messages.set(id, { id, userId, authorId: botId, type: 10, content });
    this.sent.push({ id, userId, content });
    if (this.mode === 'lost') throw new KookApiError(false);
    return id;
  }
}
async function fixture(
  t: TestContext,
  flags: {
    sendEnabled?: boolean;
    notificationsEnabled?: boolean;
    registration?: boolean;
    accountEnabled?: (accountId: string) => boolean;
  } = {},
) {
  const schema = 'plk_bot_' + randomUUID().replaceAll('-', ''),
    store = await PostgresStore.connect({
      connectionString: connection!,
      schema,
    });
  t.after(async () => {
    await store.close();
    await admin.query(`DROP SCHEMA "${schema}" CASCADE`);
  });
  const keys = keyPair(),
    framework = await AsyncFramework.create({
      store,
      issuer: 'synthetic-kook',
      catalog: catalog(),
      signer: new EnvelopeSigner(keys.privateKey),
      ...(flags.accountEnabled ? { accountEnabled: flags.accountEnabled } : {}),
      providers: [
        {
          name: 'kook',
          verify: async (proof) => ({ provider: 'kook', subject: proof }),
        },
      ],
    }),
    existing = await framework.registerVerifiedIdentity(
      { provider: 'kook', subject: users[0]! },
      {
        source: 'synthetic',
        reference: 'existing',
        reason: 'seed synthetic identity',
      },
    ),
    api = new SyntheticKook(),
    encryptionKey = randomBytes(32),
    admission = async (identity: { provider: string; subject: string }) =>
      identity.provider === 'kook' && api.allowed.has(identity.subject);
  let exchanges = 0;
  const portalOptions = {
      namespace: 'portal',
      origin: 'https://portal.example',
      provider: 'kook',
      encryptionKey,
      authorizationOrigin: 'https://identity.example',
      oauth: {
        authorizationUrl: (state: string) =>
          'https://identity.example/authorize?state=' + state,
        verify: async (code: string) => {
          exchanges++;
          return { provider: 'kook', subject: code };
        },
      },
      ...(flags.registration === false
        ? {}
        : { registrationAdmission: admission }),
    },
    portal = await PostgresPortal.create(framework, store, portalOptions),
    options = {
      namespace: 'bot',
      botId,
      api,
      admission,
      admissionVersion: 'synthetic-roles-v1',
      credentialHash: sha256('synthetic-bot-credential'),
      webhook: { verifyToken, compressed: false },
      sendEnabled: flags.sendEnabled === true,
      notificationsEnabled: flags.notificationsEnabled === true,
    },
    bot = await PostgresKookBot.create(framework, store, portal, options);
  const now = async () =>
    (await store.get<{ now: number }>(
      'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now',
    ))!.now;
  const command = async (
    userId: string,
    content = '/menu',
    eventId = randomUUID(),
    at?: number,
  ) => ({
    s: 0,
    sn: 1,
    d: {
      type: 1,
      channel_type: 'PERSON',
      author_id: userId,
      target_id:
        'long-mobile-private-target-code-123456789012345678901234567890',
      content,
      msg_id: eventId,
      msg_timestamp: at ?? (await now()),
      verify_token: verifyToken,
      extra: { author: { id: userId, bot: false } },
    },
  });
  const button = async (
    userId: string,
    messageId: string,
    value: string,
    eventId = randomUUID(),
  ) => ({
    s: 0,
    sn: 1,
    d: {
      type: 255,
      channel_type: 'PERSON',
      target_id: 'long-mobile-target',
      msg_id: eventId,
      msg_timestamp: await now(),
      verify_token: verifyToken,
      extra: {
        type: 'message_btn_click',
        body: { msg_id: messageId, user_id: userId, value, target_id: '' },
      },
    },
  });
  const ingest = async (value: unknown) =>
    bot.acceptWebhook(Buffer.from(JSON.stringify(value)));
  const sendCommand = async (userId: string, content: string) => {
    await ingest(await command(userId, content));
    assert.deepEqual(await bot.runInbox(1), { completed: 1, failed: 0 });
    assert.equal((await bot.runDeliveries(1)).delivered, 1);
    return api.sent.at(-1)!;
  };
  const buttons = (content: string) =>
    JSON.parse(content)
      .flatMap(
        (c: {
          modules: {
            elements?: {
              click: string;
              value: string;
              text: { content: string };
            }[];
          }[];
        }) => c.modules.flatMap((m) => m.elements ?? []),
      )
      .filter((b: { click: string }) => b.click === 'return-val') as {
      value: string;
      text: { content: string };
    }[];
  const handoff = async (userId = users[1]!) => {
    const message = await sendCommand(userId, '/register'),
      match = /#register=([A-Za-z0-9_-]{43})/.exec(message.content);
    assert.ok(match);
    return match[1]!;
  };
  const start = async (token: string, p = portal) => {
    const flow = await p.beginOAuth(false, token);
    return {
      ...flow,
      state: new URL(flow.authorizationUrl).searchParams.get('state')!,
    };
  };
  const count = async (table: string) =>
    (await store.get<{ n: number }>('SELECT count(*)::int AS n FROM ' + table))!
      .n;
  return {
    schema,
    store,
    framework,
    keys,
    existing,
    api,
    portal,
    portalOptions,
    options,
    bot,
    now,
    command,
    button,
    ingest,
    sendCommand,
    buttons,
    handoff,
    start,
    count,
    exchanges: () => exchanges,
  };
}

test('Bot webhook persists before acknowledging without platform I/O, rejects conflicting events and handles sn wrap independently', async (t) => {
  const f = await fixture(t),
    app = createKookBotApp(f.bot);
  t.after(() => app.close());
  const challenge = await app.inject({
    method: 'POST',
    url: '/webhook',
    headers: { 'content-type': 'application/json' },
    payload: Buffer.from(
      JSON.stringify({
        s: 0,
        d: {
          type: 255,
          channel_type: 'WEBHOOK_CHALLENGE',
          challenge: 'proof',
          verify_token: verifyToken,
        },
      }),
    ),
  });
  assert.equal(challenge.statusCode, 200);
  assert.deepEqual(challenge.json(), { challenge: 'proof' });
  assert.equal(f.api.reads, 0);
  const event = await f.command(users[0]!),
    body = Buffer.from(JSON.stringify(event));
  for (let i = 0; i < 2; i++) {
    const response = await app.inject({
      method: 'POST',
      url: '/webhook',
      headers: { 'content-type': 'application/json' },
      payload: body,
    });
    assert.equal(response.statusCode, 200);
  }
  assert.equal(f.api.reads, 0);
  assert.equal(f.api.sent.length, 0);
  assert.equal(await f.count('task_jobs'), 2); // One preexisting registration notification plus one inbox job.
  await assert.rejects(
    f.ingest({ ...event, d: { ...event.d, content: '/buy' } }),
    { code: 'TASK_KEY_CONFLICT' },
  );
  await f.ingest(await f.command(users[0]!, '/menu'));
  assert.equal((await f.bot.runInbox(10)).completed, 2);
  await assert.rejects(f.bot.runDeliveries(), { code: 'BOT_SENDING_DISABLED' });
  assert.equal(f.api.sent.length, 0);
  await assert.rejects(
    f.ingest(
      await f.command(
        users[0]!,
        '/menu',
        randomUUID(),
        (await f.now()) - 300001,
      ),
    ),
    { code: 'BOT_EVENT_EXPIRED' },
  );
  const invalid = await app.inject({
    method: 'POST',
    url: '/webhook',
    headers: { 'content-type': 'application/json' },
    payload: Buffer.from('{'),
  });
  assert.equal(invalid.statusCode, 401);
});

test('Bot buttons verify published card author, exact content, recipient and nonce; concurrent clicks create one unpaid order', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    menu = await f.sendCommand(users[0]!, '/buy'),
    purchase = f
      .buttons(menu.content)
      .find((b) => b.text.content.includes('buy-tool-1'))!;
  assert.ok(purchase);
  await f.ingest(await f.button(users[1]!, menu.id, purchase.value));
  assert.equal((await f.bot.runInbox(1)).failed, 1);
  assert.equal(await f.count('orders'), 0);
  const original = f.api.messages.get(menu.id)!;
  f.api.messages.set(menu.id, { ...original, authorId: '666666' });
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  assert.equal((await f.bot.runInbox(1)).failed, 1);
  assert.equal(await f.count('orders'), 0);
  f.api.messages.set(menu.id, { ...original, content: original.content + ' ' });
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  assert.equal((await f.bot.runInbox(1)).failed, 1);
  f.api.messages.set(menu.id, original);
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  const other = await PostgresKookBot.create(
      f.framework,
      f.store,
      f.portal,
      f.options,
    ),
    results = await Promise.all([f.bot.runInbox(1), other.runInbox(1)]);
  assert.equal(
    results.reduce((n, r) => n + r.completed, 0),
    2,
  );
  assert.equal(await f.count('orders'), 1);
  assert.equal(await f.count('entitlements'), 0);
  assert.equal((await f.bot.runDeliveries(10)).delivered, 1);
  const order = await f.store.get<{ status: string; offer_json: string }>(
    'SELECT * FROM orders',
  );
  assert.equal(order!.status, 'pending');
  assert.equal(
    JSON.parse(order!.offer_json).amount,
    catalog().offers.find((o) => o.id === 'buy-tool-1')!.amount,
  );
  assert.ok(f.api.sent.at(-1)!.content.includes('个人收款码'));
  assert.ok(!f.api.sent.at(-1)!.content.includes('accessToken'));
});

test('Bot rechecks current membership and immutable offer snapshots before purchase', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    menu = await f.sendCommand(users[0]!, '/buy'),
    purchase = f
      .buttons(menu.content)
      .find((b) => b.text.content.includes('buy-tool-1'))!;
  f.api.allowed.delete(users[0]!);
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  assert.equal((await f.bot.runInbox(1)).failed, 1);
  assert.equal(await f.count('orders'), 0);
  f.api.allowed.add(users[0]!);
  const changed = catalog();
  changed.offers.find((o) => o.id === 'buy-tool-1')!.amount++;
  const framework = await AsyncFramework.create({
      store: f.store,
      issuer: f.framework.issuer,
      catalog: changed,
      signer: new EnvelopeSigner(f.keys.privateKey),
      providers: [
        {
          name: 'kook',
          verify: async (subject) => ({ provider: 'kook', subject }),
        },
      ],
    }),
    portal = await PostgresPortal.create(framework, f.store, f.portalOptions),
    bot = await PostgresKookBot.create(framework, f.store, portal, f.options);
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  assert.equal((await bot.runInbox(1)).completed, 1);
  assert.equal(await f.count('orders'), 0);
  await bot.runDeliveries(1);
  assert.ok(f.api.sent.at(-1)!.content.includes('商品信息已变化'));
});

test('Bot callback, business result, button consumption and outgoing plan survive a lost COMMIT receipt without a second order', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    menu = await f.sendCommand(users[0]!, '/buy'),
    purchase = f
      .buttons(menu.content)
      .find((b) => b.text.content.includes('buy-tool-1'))!;
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  const original = pg.Client.prototype.query;
  let armed = true;
  const mock = t.mock.method(pg.Client.prototype, 'query', function (
    this: pg.Client,
    ...args: unknown[]
  ) {
    const result = Reflect.apply(
      original,
      this,
      args,
    ) as Promise<pg.QueryResult>;
    if (armed && args[0] === 'COMMIT')
      return result.then(() => {
        armed = false;
        throw new Error('synthetic commit reply lost');
      });
    return result;
  } as pg.Client['query']);
  try {
    assert.equal((await f.bot.runInbox(1)).failed, 1);
  } finally {
    mock.mock.restore();
  }
  assert.equal(await f.count('orders'), 1);
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  await f.bot.runInbox(1);
  assert.equal(await f.count('orders'), 1);
  assert.equal((await f.bot.runDeliveries(10)).delivered, 1);
});

test('a failed Bot audit rolls back the order, consumed button and outgoing plan together, then a safe retry commits once', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    menu = await f.sendCommand(users[0]!, '/buy'),
    purchase = f
      .buttons(menu.content)
      .find((b) => b.text.content.includes('buy-tool-1'))!;
  await admin.query(
    `CREATE FUNCTION "${f.schema}".reject_bot_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF NEW.action='bot.order-created' THEN RAISE EXCEPTION 'synthetic audit unavailable'; END IF; RETURN NEW; END $$`,
  );
  await admin.query(
    `CREATE TRIGGER reject_bot_audit BEFORE INSERT ON "${f.schema}".audit FOR EACH ROW EXECUTE FUNCTION "${f.schema}".reject_bot_audit()`,
  );
  await f.ingest(await f.button(users[0]!, menu.id, purchase.value));
  assert.equal((await f.bot.runInbox(1)).failed, 1);
  assert.equal(await f.count('orders'), 0);
  assert.equal(await f.count('bot_messages'), 1);
  assert.equal(
    (await f.store.get<{ used_at: number | null }>(
      'SELECT used_at FROM bot_actions WHERE hash=$1',
      sha256(purchase.value.slice(4)),
    ))!.used_at,
    null,
  );
  await admin.query(`DROP TRIGGER reject_bot_audit ON "${f.schema}".audit`);
  await f.store.run("UPDATE task_jobs SET next_at=0 WHERE state='pending'");
  assert.equal((await f.bot.runInbox(1)).completed, 1);
  assert.equal(await f.count('orders'), 1);
  assert.equal((await f.bot.runDeliveries(10)).delivered, 1);
});

test('Bot registration handoff is encrypted at rest, separate from native invitations, identity-bound and single-use with mandatory MFA', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    token = await f.handoff();
  assert.equal(await f.count('invitations'), 0);
  const rows = await f.store.all<{ content: string }>(
    'SELECT content FROM bot_messages',
  );
  assert.ok(rows.every((row) => !row.content.includes(token)));
  assert.ok(
    !JSON.stringify(
      await f.store.all('SELECT payload FROM task_jobs'),
    ).includes(token),
  );
  await assert.rejects(f.framework.register(token, users[1]!), {
    code: 'INVALID_INVITATION',
  });
  const wrong = await f.start(token);
  await assert.rejects(
    f.portal.completeOAuth(wrong.state, wrong.browser, users[2]!),
    { code: 'REGISTRATION_IDENTITY_MISMATCH' },
  );
  const flow = await f.start(token);
  await assert.rejects(
    f.portal.completeOAuth(
      flow.state,
      randomBytes(32).toString('base64url'),
      users[1]!,
    ),
    { code: 'OAUTH_STATE_INVALID' },
  );
  const pending = await f.portal.completeOAuth(
      flow.state,
      flow.browser,
      users[1]!,
    ),
    session = await f.portal.current(pending.token);
  assert.equal(session.stage, 'setup');
  assert.equal(await f.count('accounts'), 2);
  assert.equal(await f.count('entitlements'), 0);
  assert.equal(await f.count('credits'), 0);
  await assert.rejects(f.portal.userData(pending.token, 'profile', {}), {
    code: 'PORTAL_MFA_REQUIRED',
  });
  const confirmed = await f.portal.verifyMfa(
    pending.token,
    session.csrf,
    totpCode(session.setup!.secret, Math.floor((await f.now()) / 30000)),
  );
  assert.equal((await f.portal.current(confirmed.token)).stage, 'active');
  assert.equal(confirmed.recoveryCodes.length, 10);
  await assert.rejects(f.portal.beginOAuth(false, token), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  await assert.rejects(
    f.portal.completeOAuth(flow.state, flow.browser, users[1]!),
    { code: 'OAUTH_STATE_INVALID' },
  );
  assert.equal(
    (await f.store.get<{ n: number }>(
      "SELECT count(*)::int AS n FROM audit WHERE action='account.registered'",
    ))!.n,
    2,
  );
});

test('two browser registration flows race for one handoff; lost registration COMMIT acknowledgement cannot create another account', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    token = await f.handoff(),
    a = await f.start(token),
    b = await f.start(token);
  const results = await Promise.allSettled([
    f.portal.completeOAuth(a.state, a.browser, users[1]!),
    f.portal.completeOAuth(b.state, b.browser, users[1]!),
  ]);
  assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
  assert.equal(await f.count('accounts'), 2);
  const token2 = await f.handoff(users[2]!),
    flow = await f.start(token2),
    original = pg.Client.prototype.query;
  let commits = 0;
  const mock = t.mock.method(pg.Client.prototype, 'query', function (
    this: pg.Client,
    ...args: unknown[]
  ) {
    const result = Reflect.apply(
      original,
      this,
      args,
    ) as Promise<pg.QueryResult>;
    if (args[0] === 'COMMIT' && ++commits === 2)
      return result.then(() => {
        throw new Error('synthetic registration result lost');
      });
    return result;
  } as pg.Client['query']);
  try {
    await assert.rejects(
      f.portal.completeOAuth(flow.state, flow.browser, users[2]!),
      { code: 'TRANSACTION_COMMIT_UNCERTAIN' },
    );
  } finally {
    mock.mock.restore();
  }
  assert.equal(await f.count('accounts'), 3);
  await assert.rejects(f.portal.beginOAuth(false, token2), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  assert.equal(await f.count('entitlements'), 0);
});

test('registration is explicitly enabled, and expired, revoked or no-longer-admitted handoffs grant no account', async (t) => {
  const f = await fixture(t, { sendEnabled: true, registration: false }),
    token = await f.handoff();
  await assert.rejects(f.portal.beginOAuth(false, token), {
    code: 'PORTAL_REGISTRATION_DISABLED',
  });
  const enabled = await PostgresPortal.create(f.framework, f.store, {
    ...f.portalOptions,
    registrationAdmission: async (identity) =>
      f.api.allowed.has(identity.subject),
  });
  await f.store.run(
    'UPDATE bot_handoffs SET expires_at=1 WHERE hash=$1',
    sha256(token),
  );
  await assert.rejects(enabled.beginOAuth(false, token), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  const token2 = await f.handoff(),
    flow = await f.start(token2, enabled);
  f.api.allowed.delete(users[1]!);
  await assert.rejects(
    enabled.completeOAuth(flow.state, flow.browser, users[1]!),
    { code: 'REGISTRATION_ADMISSION_DENIED' },
  );
  assert.equal(await f.count('accounts'), 1);
  f.api.allowed.add(users[1]!);
  await f.store.run(
    'UPDATE bot_handoffs SET revoked_at=1 WHERE hash=$1',
    sha256(token2),
  );
  await assert.rejects(enabled.beginOAuth(false, token2), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
});

test('unknown Bot sends are quarantined, API proof reconciles their publication, and explicit rejection can retry safely', async (t) => {
  const f = await fixture(t, { sendEnabled: true });
  await f.ingest(await f.command(users[0]!));
  await f.bot.runInbox(1);
  f.api.mode = 'lost';
  assert.deepEqual(await f.bot.runDeliveries(1), {
    delivered: 0,
    failed: 1,
    uncertain: 1,
  });
  const task = (await f.bot.deliveries.list({ state: 'uncertain' })).items[0]!;
  assert.equal((await f.bot.runDeliveries(10)).delivered, 0);
  assert.equal(f.api.sent.length, 1);
  const sent = f.api.sent[0]!,
    original = f.api.messages.get(sent.id)!;
  f.api.messages.set(sent.id, { ...original, authorId: '66666' });
  await assert.rejects(
    f.bot.resolveDelivery(task.key, {
      outcome: 'published',
      messageId: sent.id,
      generation: task.generation,
      actor: 'owner',
      reason: 'verify sent card',
    }),
    { code: 'BOT_BUTTON_REJECTED' },
  );
  f.api.messages.set(sent.id, original);
  await f.bot.resolveDelivery(task.key, {
    outcome: 'published',
    messageId: sent.id,
    generation: task.generation,
    actor: 'owner',
    reason: 'verify exact platform receipt',
  });
  assert.equal((await f.bot.deliveries.get(task.key))!.state, 'succeeded');
  f.api.mode = 'ok';
  const value = f.buttons(sent.content)[0]!.value;
  await f.ingest(await f.button(users[0]!, sent.id, value));
  assert.equal((await f.bot.runInbox(1)).completed, 1);
  f.api.mode = 'reject';
  assert.deepEqual(await f.bot.runDeliveries(1), {
    delivered: 0,
    failed: 1,
    uncertain: 0,
  });
  const pending = (await f.bot.deliveries.list({ state: 'pending' })).items[0]!;
  await f.store.run('UPDATE task_jobs SET next_at=0 WHERE id=$1', pending.id);
  f.api.mode = 'ok';
  assert.equal((await f.bot.runDeliveries(1)).delivered, 1);
  assert.equal(f.api.sent.length, 2);
});

test('Bot epoch pause invalidates outstanding actions and handoffs; context/key changes fail closed', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    token = await f.handoff(),
    paused = await f.bot.review({
      paused: true,
      epoch: 1,
      actor: 'owner',
      reason: 'local maintenance pause',
    });
  assert.deepEqual(paused, { epoch: 2, paused: true });
  await assert.rejects(f.portal.beginOAuth(false, token), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  await assert.rejects(f.ingest(await f.command(users[0]!)), {
    code: 'BOT_REVIEW_REQUIRED',
  });
  await assert.rejects(
    f.bot.review({
      paused: false,
      epoch: 1,
      actor: 'owner',
      reason: 'stale review rejected',
    }),
    { code: 'BOT_REVIEW_STALE' },
  );
  await f.bot.review({
    paused: false,
    epoch: 2,
    actor: 'owner',
    reason: 'review isolated fixture',
  });
  await assert.rejects(f.portal.beginOAuth(false, token), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  await assert.rejects(
    PostgresKookBot.create(f.framework, f.store, f.portal, {
      ...f.options,
      admissionVersion: 'changed-without-review',
    }),
    { code: 'BOT_CONTEXT_CHANGED' },
  );
});

test('Bot notifications require opt-in and one owner; exact business resources are delivered without account credentials', async (t) => {
  const f = await fixture(t, { sendEnabled: true });
  await assert.rejects(f.bot.runNotifications(), {
    code: 'BOT_NOTIFICATIONS_DISABLED',
  });
  assert.equal(f.api.sent.length, 0);
  const bot = await PostgresKookBot.create(f.framework, f.store, f.portal, {
    ...f.options,
    notificationsEnabled: true,
  });
  assert.equal((await bot.runNotifications(10)).delivered, 1);
  assert.ok(f.api.sent[0]!.content.includes(f.existing.accountId));
  const other = await PostgresKookBot.create(f.framework, f.store, f.portal, {
    ...f.options,
    namespace: 'other',
    notificationsEnabled: true,
  });
  await assert.rejects(other.runNotifications(), {
    code: 'BOT_NOTIFICATION_OWNER_CONFLICT',
  });
  assert.equal(f.api.sent.length, 1);
});

test('mixed identity notifications leave other providers unclaimed by the KOOK Bot', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    framework = await AsyncFramework.create({
      store: f.store,
      issuer: f.framework.issuer,
      catalog: catalog(),
      signer: new EnvelopeSigner(f.keys.privateKey),
      providers: ['kook', 'local'].map((name) => ({
        name,
        verify: async (subject: string) => ({ provider: name, subject }),
      })),
    }),
    local = await framework.registerVerifiedIdentity(
      { provider: 'local', subject: 'synthetic-local-route' },
      {
        source: 'synthetic',
        reference: 'local-route',
        reason: 'mixed provider routing acceptance',
      },
    ),
    portal = await PostgresPortal.create(framework, f.store, f.portalOptions),
    bot = await PostgresKookBot.create(framework, f.store, portal, {
      ...f.options,
      notificationsEnabled: true,
    });
  assert.deepEqual(await bot.runNotifications(10), {
    delivered: 1,
    failed: 0,
    skipped: 0,
    uncertain: 0,
  });
  const localTask = await f.store.get<{
    state: string;
    attempts: number;
    generation: number;
  }>(
    'SELECT j.state,j.attempts,j.generation FROM task_jobs j JOIN outbox o ON o.id=j.task_key WHERE o.account_id=$1',
    local.accountId,
  );
  assert.deepEqual(localTask, { state: 'pending', attempts: 0, generation: 0 });
  assert.equal(f.api.sent.length, 1);
  const providers = ['local'],
    localWorker = new PostgresNotificationWorker(f.store, { providers });
  providers[0] = 'kook';
  assert.equal(
    (
      await localWorker.run(
        {
          send: async (event, identity) => {
            assert.deepEqual(identity, {
              provider: 'local',
              subject: 'synthetic-local-route',
            });
            assert.equal(event.accountId, local.accountId);
          },
        },
        10,
      )
    ).delivered,
    1,
  );
  assert.equal(f.api.sent.length, 1);
});

test('KOOK notification dispatch honors the host account policy before preparing an external send', async (t) => {
  let enabled = true;
  const f = await fixture(t, {
      sendEnabled: true,
      accountEnabled: () => enabled,
    }),
    bot = await PostgresKookBot.create(f.framework, f.store, f.portal, {
      ...f.options,
      notificationsEnabled: true,
    });
  enabled = false;
  assert.deepEqual(await bot.runNotifications(10), {
    delivered: 0,
    failed: 1,
    skipped: 0,
    uncertain: 0,
  });
  assert.equal(f.api.sent.length, 0);
  const task = (await bot.notificationWorker.queue.list({ state: 'dead' }))
    .items[0]!;
  assert.equal(task.lastError, 'ACCOUNT_DISABLED');
  assert.equal(
    (await f.store.get<{ attempts: number }>(
      'SELECT attempts FROM outbox WHERE id=$1',
      task.key,
    ))!.attempts,
    0,
  );
});

test('a host account disabled while checking KOOK admission is rejected before the API send', async (t) => {
  let enabled = true;
  const f = await fixture(t, {
      sendEnabled: true,
      accountEnabled: () => enabled,
    }),
    bot = await PostgresKookBot.create(f.framework, f.store, f.portal, {
      ...f.options,
      notificationsEnabled: true,
      admission: async (identity) => {
        const admitted = await f.options.admission(identity);
        enabled = false;
        return admitted;
      },
    });
  assert.deepEqual(await bot.runNotifications(1), {
    delivered: 0,
    failed: 1,
    skipped: 0,
    uncertain: 0,
  });
  assert.equal(f.api.sent.length, 0);
  const task = (await bot.notificationWorker.queue.list({ state: 'pending' }))
    .items[0]!;
  assert.equal(task.lastError, 'BOT_NOTIFICATION_PREPARATION_FAILED');
  assert.equal(
    (await f.store.get<{ delivered_at: number | null }>(
      'SELECT delivered_at FROM outbox WHERE id=$1',
      task.key,
    ))!.delivered_at,
    null,
  );
});

test('Bot backup includes its encrypted plans via the portal key, restores paused with invalid grants, and cannot replay old sends', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    token = await f.handoff();
  await f.ingest(await f.command(users[0]!));
  await f.bot.runInbox(1);
  await f.start(token);
  const root = mkdtempSync(join(tmpdir(), 'plk-bot-restore-')),
    targetSchema = 'plk_bot_restored_' + randomUUID().replaceAll('-', ''),
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
        .startsWith(join(parent, 'plk-bot-restore-').toLowerCase()),
    );
    rmSync(exact, { recursive: true });
  });
  const saved = await backupPostgres(f.store, {
      directory: root,
      password: 'synthetic-bot-restore-password',
      privateKeys: [f.keys.privateKey],
      portalKeys: [{ namespace: 'portal', key: f.portalOptions.encryptionKey }],
    }),
    bundle = readFileSync(saved.path);
  assert.ok(!bundle.includes(token));
  await restorePostgres(target, bundle, 'synthetic-bot-restore-password', {
    actor: 'owner',
    reason: 'isolated Bot recovery',
    expectedPolicies: {},
  });
  const framework = await AsyncFramework.create({
      store: target,
      issuer: f.framework.issuer,
      catalog: catalog(),
      signer: new EnvelopeSigner(f.keys.privateKey),
      providers: [
        {
          name: 'kook',
          verify: async (subject) => ({ provider: 'kook', subject }),
        },
      ],
    }),
    portal = await PostgresPortal.create(framework, target, f.portalOptions),
    bot = await PostgresKookBot.create(framework, target, portal, f.options);
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM bot_actions',
    ))!.n,
    0,
  );
  assert.equal(
    (await target.get<{ n: number }>(
      'SELECT count(*)::int AS n FROM portal_registration_states',
    ))!.n,
    0,
  );
  await assert.rejects(bot.runDeliveries(), { code: 'BOT_REVIEW_REQUIRED' });
  await assert.rejects(portal.beginOAuth(false, token), {
    code: 'REGISTRATION_GRANT_INVALID',
  });
  await bot.review({
    paused: false,
    epoch: 2,
    actor: 'owner',
    reason: 'review restored Bot adapter',
  });
  assert.equal((await bot.runDeliveries(10)).delivered, 0);
  assert.equal(
    (await bot.deliveries.list({ state: 'uncertain' })).items.length,
    1,
  );
});

test('registration HTTP receives the grant only in the explicit POST body and strips the browser fragment before navigation', async (t) => {
  const f = await fixture(t, { sendEnabled: true }),
    token = await f.handoff(),
    app = await createPortalApp(f.portal);
  t.after(() => app.close());
  new Script(portalScript);
  const response = await app.inject({
    method: 'POST',
    url: '/api/auth/start',
    headers: { origin: f.portal.origin, 'content-type': 'application/json' },
    payload: { remember: false, registration: token },
  });
  assert.equal(response.statusCode, 200);
  assert.ok(!response.body.includes(token));
  assert.ok(!JSON.stringify(response.headers).includes(token));
  const crossed = await app.inject({
    method: 'POST',
    url: '/api/auth/start',
    headers: {
      origin: 'https://other.example',
      'content-type': 'application/json',
    },
    payload: { remember: false, registration: token },
  });
  assert.equal(crossed.statusCode, 403);
  assert.ok(
    portalScript.includes(
      "history.replaceState(null,'',location.pathname+location.search)",
    ),
  );
  assert.ok(portalScript.includes('请勾选注册确认后继续。'));
});
