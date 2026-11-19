import test from 'node:test';
import assert from 'node:assert/strict';
import { createCipheriv, randomBytes } from 'node:crypto';
import { deflateSync } from 'node:zlib';
import { KookWebhookDecoder } from '../src/adapters/kook-webhook.js';
import { KookApiError, KookBotClient } from '../src/adapters/kook-bot-api.js';

const verifyToken = 'synthetic-webhook-verification',
  secret = 'synthetic-encryption';
const challenge = {
  s: 0,
  d: {
    type: 255,
    channel_type: 'WEBHOOK_CHALLENGE',
    challenge: 'synthetic-challenge',
    verify_token: verifyToken,
  },
};
function encrypted(value: unknown) {
  const key = Buffer.alloc(32);
  key.write(secret);
  const iv = Buffer.from('0123456789abcdef'),
    cipher = createCipheriv('aes-256-cbc', key, iv);
  return {
    encrypt: Buffer.concat([
      iv,
      Buffer.from(
        Buffer.concat([
          cipher.update(JSON.stringify(value)),
          cipher.final(),
        ]).toString('base64'),
      ),
    ]).toString('base64'),
  };
}
const command = () => ({
  s: 0,
  sn: 65535,
  d: {
    type: 1,
    channel_type: 'PERSON',
    target_id:
      'a-long-mobile-private-chat-1234567890123456789012345678901234567890',
    author_id: '12345678901234567890',
    content: '/menu',
    msg_id: 'event-1',
    msg_timestamp: Date.now(),
    verify_token: verifyToken,
    extra: { author: { id: '12345678901234567890', bot: false } },
  },
});

test('KOOK challenge supports the documented double-base64 CBC envelope and zlib compression', () => {
  const decoder = new KookWebhookDecoder({
    verifyToken,
    encryptionKey: secret,
  });
  assert.deepEqual(
    decoder.decode(deflateSync(JSON.stringify(encrypted(challenge)))),
    { challenge: 'synthetic-challenge' },
  );
  assert.deepEqual(
    new KookWebhookDecoder({ verifyToken, compressed: false }).decode(
      Buffer.from(JSON.stringify(challenge)),
    ),
    { challenge: 'synthetic-challenge' },
  );
});
test('KOOK encryption does not downgrade to plaintext, accept wrong tokens, wrong keys or invalid padding', () => {
  const decoder = new KookWebhookDecoder({
    verifyToken,
    encryptionKey: secret,
    compressed: false,
  });
  for (const value of [
    challenge,
    encrypted({
      ...challenge,
      d: { ...challenge.d, verify_token: 'wrong-token' },
    }),
    { encrypt: randomBytes(64).toString('base64') },
  ])
    assert.throws(() => decoder.decode(Buffer.from(JSON.stringify(value))), {
      code: 'KOOK_WEBHOOK_INVALID',
    });
  assert.throws(
    () =>
      new KookWebhookDecoder({
        verifyToken,
        encryptionKey: 'wrong-key',
        compressed: false,
      }).decode(Buffer.from(JSON.stringify(encrypted(challenge)))),
    { code: 'KOOK_WEBHOOK_INVALID' },
  );
});
test('KOOK decoding bounds compressed expansion, ignores groups and self-Bot messages, and preserves long IDs exactly', () => {
  const decoder = new KookWebhookDecoder({ verifyToken });
  assert.throws(() => decoder.decode(deflateSync('a'.repeat(1048577))), {
    code: 'KOOK_WEBHOOK_INVALID',
  });
  const input = command(),
    result = decoder.decode(deflateSync(JSON.stringify(input)));
  assert.ok('event' in result);
  assert.equal(result.event.userId, '12345678901234567890');
  assert.deepEqual(
    decoder.decode(
      deflateSync(
        JSON.stringify({ ...input, d: { ...input.d, channel_type: 'GROUP' } }),
      ),
    ),
    { ignored: true },
  );
  assert.deepEqual(
    decoder.decode(
      deflateSync(
        JSON.stringify({
          ...input,
          d: {
            ...input.d,
            extra: { author: { id: input.d.author_id, bot: true } },
          },
        }),
      ),
    ),
    { ignored: true },
  );
  assert.throws(
    () =>
      decoder.decode(
        deflateSync(
          JSON.stringify({ ...input, d: { ...input.d, author_id: '999' } }),
        ),
      ),
    { code: 'KOOK_WEBHOOK_INVALID' },
  );
});
test('KOOK button normalization trusts neither a mobile chat target nor callback-provided account IDs', () => {
  const input = command(),
    token = randomBytes(32).toString('base64url'),
    decoder = new KookWebhookDecoder({ verifyToken, compressed: false });
  const body = {
    ...input,
    d: {
      ...input.d,
      type: 255,
      extra: {
        type: 'message_btn_click',
        body: {
          user_id: input.d.author_id,
          msg_id: 'original-card',
          value: 'plk:' + token,
          target_id: '',
          accountId: 'forged-account',
        },
      },
    },
  };
  assert.deepEqual(decoder.decode(Buffer.from(JSON.stringify(body))), {
    event: {
      kind: 'button',
      id: 'event-1',
      userId: input.d.author_id,
      at: input.d.msg_timestamp,
      messageId: 'original-card',
      value: 'plk:' + token,
    },
  });
  body.d.extra.body.value = 'plk:buy-tool-1';
  assert.throws(() => decoder.decode(Buffer.from(JSON.stringify(body))), {
    code: 'KOOK_WEBHOOK_INVALID',
  });
});
test('KOOK Bot REST calls use only the fixed official origin and validate conversation recipient and message author metadata', async () => {
  const calls: { url: string; input?: RequestInit }[] = [],
    http = (async (url, input) => {
      calls.push({ url: String(url), ...(input ? { input } : {}) });
      const path = new URL(String(url)).pathname;
      return Response.json({
        code: 0,
        data: path.endsWith('user/me')
          ? { id: '1000' }
          : path.endsWith('user/view')
            ? { id: '2000', bot: false, roles: [4, 7] }
            : path.endsWith('user-chat/create')
              ? {
                  code: 'chat-with-a-long-mobile-code',
                  target_info: { id: '2000' },
                  is_blocked: false,
                  is_target_blocked: false,
                }
              : path.endsWith('direct-message/view')
                ? {
                    id: 'message-1',
                    author_id: '1000',
                    type: 10,
                    content: '[]',
                  }
                : { msg_id: 'message-2' },
      });
    }) as typeof fetch;
  const client = new KookBotClient('synthetic-bot-token', http);
  assert.equal(await client.me(), '1000');
  assert.equal(await client.admitted('2000', '3000', [7]), true);
  assert.equal(await client.admitted('2000', '3000', [9]), false);
  assert.equal(
    await client.conversation('2000'),
    'chat-with-a-long-mobile-code',
  );
  assert.equal(
    (await client.message('chat-with-a-long-mobile-code', 'message-1'))
      .authorId,
    '1000',
  );
  assert.equal(await client.send('2000', '[]', 'reference-1'), 'message-2');
  assert.ok(
    calls.every(
      (call) =>
        call.url.startsWith('https://www.kookapp.cn/api/v3/') &&
        call.input?.headers &&
        (call.input.headers as Record<string, string>).Authorization ===
          'Bot synthetic-bot-token' &&
        call.input.redirect === 'error' &&
        !call.url.includes('synthetic-bot-token'),
    ),
  );
  assert.deepEqual(JSON.parse(String(calls.at(-1)!.input!.body)), {
    target_id: '2000',
    type: 10,
    content: '[]',
    reply_msg_id: 'reference-1',
  });
});
test('KOOK API rejections are distinguishable from unknown sends and never retried by the client', async () => {
  for (const [status, definite] of [
    [403, true],
    [429, true],
    [408, false],
    [500, false],
  ] as const) {
    let count = 0;
    const client = new KookBotClient('synthetic', async () => {
      count++;
      return new Response('', { status });
    });
    await assert.rejects(
      client.send('2000', '[]'),
      (error) =>
        error instanceof KookApiError && error.definitelyNotSent === definite,
    );
    assert.equal(count, 1);
  }
  const malformed = new KookBotClient('synthetic', async () =>
    Response.json({ code: 0, data: {} }),
  );
  await assert.rejects(
    malformed.send('2000', '[]'),
    (error) => error instanceof KookApiError && !error.definitelyNotSent,
  );
  const huge = new KookBotClient(
    'synthetic',
    async () => new Response('x'.repeat(131073)),
  );
  await assert.rejects(
    huge.send('2000', '[]'),
    (error) => error instanceof KookApiError && !error.definitelyNotSent,
  );
  const denied = new KookBotClient('synthetic', async () =>
    Response.json({
      code: 0,
      data: {
        code: 'chat',
        target_info: { id: '9999' },
        is_blocked: false,
        is_target_blocked: false,
      },
    }),
  );
  await assert.rejects(denied.conversation('2000'), {
    code: 'KOOK_CONVERSATION_REJECTED',
  });
});
