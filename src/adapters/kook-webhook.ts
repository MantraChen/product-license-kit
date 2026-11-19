import { createDecipheriv } from 'node:crypto';
import { inflateSync } from 'node:zlib';
import { z } from 'zod';
import { requireThat } from '../core/model.js';
import { secretEqual } from '../core/crypto.js';
import { kookUserId } from './kook-bot-api.js';

const id = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/);
export const kookBotEventSchema = z.discriminatedUnion('kind', [
  z
    .object({
      kind: z.literal('command'),
      id,
      userId: kookUserId,
      at: z.number().int().nonnegative().safe(),
      command: z.enum(['menu', 'buy', 'account', 'register']),
    })
    .strict(),
  z
    .object({
      kind: z.literal('button'),
      id,
      userId: kookUserId,
      at: z.number().int().nonnegative().safe(),
      messageId: id,
      value: z.string().regex(/^plk:[A-Za-z0-9_-]{43}$/),
    })
    .strict(),
]);
export type KookBotEvent = z.infer<typeof kookBotEventSchema>;
export interface KookWebhookOptions {
  verifyToken: string;
  encryptionKey?: string;
  compressed?: boolean;
}
/** KOOK's token verification and optional CBC transport encryption are not digital signatures. */
export class KookWebhookDecoder {
  private readonly verifyToken: string;
  private readonly encryptionKey?: Buffer;
  readonly compressed: boolean;
  constructor(options: KookWebhookOptions) {
    this.verifyToken = z.string().min(16).max(200).parse(options.verifyToken);
    this.compressed = options.compressed ?? true;
    if (options.encryptionKey !== undefined) {
      const value = Buffer.from(options.encryptionKey);
      requireThat(
        value.length >= 1 && value.length <= 32,
        'KOOK_ENCRYPTION_KEY_INVALID',
      );
      this.encryptionKey = Buffer.alloc(32);
      value.copy(this.encryptionKey);
    }
  }
  private base64(value: unknown) {
    requireThat(
      typeof value === 'string' &&
        value.length > 0 &&
        value.length <= 1400000 &&
        /^[A-Za-z0-9+/]*={0,2}$/.test(value),
      'KOOK_WEBHOOK_INVALID',
      401,
    );
    const decoded = Buffer.from(value, 'base64');
    requireThat(
      decoded.toString('base64') === value,
      'KOOK_WEBHOOK_INVALID',
      401,
    );
    return decoded;
  }
  decode(
    raw: Buffer,
  ): { challenge: string } | { event: KookBotEvent } | { ignored: true } {
    try {
      requireThat(
        raw.length > 0 && raw.length <= 1048576,
        'KOOK_WEBHOOK_INVALID',
        401,
      );
      const bytes = this.compressed
        ? inflateSync(raw, { maxOutputLength: 1048576 })
        : raw;
      let body: unknown = JSON.parse(bytes.toString('utf8'));
      if (this.encryptionKey) {
        const envelope = z.object({ encrypt: z.string() }).strict().parse(body),
          outer = this.base64(envelope.encrypt);
        requireThat(outer.length > 16, 'KOOK_WEBHOOK_INVALID', 401);
        const ciphertext = this.base64(outer.subarray(16).toString('utf8'));
        requireThat(
          ciphertext.length > 0 && ciphertext.length % 16 === 0,
          'KOOK_WEBHOOK_INVALID',
          401,
        );
        const decrypt = createDecipheriv(
          'aes-256-cbc',
          this.encryptionKey,
          outer.subarray(0, 16),
        );
        // The official protocol uses PKCS#7 padding; malformed padding never falls back to plaintext.
        body = JSON.parse(
          Buffer.concat([decrypt.update(ciphertext), decrypt.final()]).toString(
            'utf8',
          ),
        );
      }
      const envelope = z
          .object({
            s: z.literal(0),
            d: z
              .object({
                verify_token: z.string().max(200),
                channel_type: z.string(),
                type: z.number().int(),
              })
              .passthrough(),
          })
          .passthrough()
          .parse(body),
        d = envelope.d;
      requireThat(
        secretEqual(d.verify_token, this.verifyToken),
        'KOOK_WEBHOOK_INVALID',
        401,
      );
      if (d.channel_type === 'WEBHOOK_CHALLENGE')
        return { challenge: z.string().min(1).max(512).parse(d.challenge) };
      if (d.channel_type !== 'PERSON') return { ignored: true };
      if (d.type === 255) {
        const extra = z
          .object({ type: z.string(), body: z.unknown() })
          .parse(d.extra);
        if (extra.type !== 'message_btn_click') return { ignored: true };
        const button = z
          .object({
            msg_id: id,
            user_id: kookUserId,
            value: z.string().max(512),
          })
          .parse(extra.body);
        if (!button.value.startsWith('plk:')) return { ignored: true };
        return {
          event: kookBotEventSchema.parse({
            kind: 'button',
            id: d.msg_id,
            at: d.msg_timestamp,
            userId: button.user_id,
            messageId: button.msg_id,
            value: button.value,
          }),
        };
      }
      if (d.type !== 1 && d.type !== 9) return { ignored: true };
      const author = z
        .object({ author: z.object({ id: kookUserId, bot: z.boolean() }) })
        .parse(d.extra).author;
      if (author.bot) return { ignored: true };
      requireThat(author.id === d.author_id, 'KOOK_WEBHOOK_INVALID', 401);
      const text = z.string().max(65536).parse(d.content).trim();
      const commands: Record<string, 'menu' | 'buy' | 'account' | 'register'> =
        {
          '/menu': 'menu',
          菜单: 'menu',
          '/buy': 'buy',
          购买: 'buy',
          '/account': 'account',
          我的账号: 'account',
          '/register': 'register',
          注册: 'register',
        };
      const command = commands[text];
      if (!command) return { ignored: true };
      return {
        event: kookBotEventSchema.parse({
          kind: 'command',
          id: d.msg_id,
          at: d.msg_timestamp,
          userId: author.id,
          command,
        }),
      };
    } catch {
      requireThat(false, 'KOOK_WEBHOOK_INVALID', 401);
    }
  }
}
