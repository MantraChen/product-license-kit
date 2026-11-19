import {
  createCipheriv,
  createDecipheriv,
  randomBytes,
  randomUUID,
} from 'node:crypto';
import { z } from 'zod';
import { AsyncFramework } from '../async-service.js';
import { StorageError, type AsyncStore } from '../core/async-store.js';
import {
  DomainError,
  NotificationNotSentError,
  requireThat,
  type Offer,
  type VerifiedIdentity,
} from '../core/model.js';
import { randomToken, sha256 } from '../core/crypto.js';
import { PostgresPortal } from './postgres-portal.js';
import { PostgresTaskQueue, type TaskLease } from './postgres-tasks.js';
import { PostgresNotificationWorker } from './postgres-notifications.js';
import { KookApiError, kookUserId, type KookBotApi } from './kook-bot-api.js';
import {
  KookWebhookDecoder,
  kookBotEventSchema,
  type KookBotEvent,
  type KookWebhookOptions,
} from './kook-webhook.js';

const short = 300000,
  uuid = z.string().uuid(),
  reason = z.string().trim().min(3).max(500),
  actor = z.string().min(1).max(128);
const actionSchema = z.discriminatedUnion('kind', [
  z.object({ kind: z.enum(['menu', 'account', 'register']) }).strict(),
  z
    .object({
      kind: z.literal('offers'),
      offset: z.number().int().min(0).max(100000),
    })
    .strict(),
  z
    .object({
      kind: z.literal('purchase'),
      offerId: z.string().min(1).max(128),
      offerHash: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .strict(),
]);
type Action = z.infer<typeof actionSchema>;
type StoredEvent =
  | Exclude<KookBotEvent, { kind: 'button' }>
  | {
      kind: 'button';
      id: string;
      userId: string;
      at: number;
      messageId: string;
      valueHash: string;
    };
const storedEventSchema = z.union([
  kookBotEventSchema.options[0],
  z
    .object({
      kind: z.literal('button'),
      id: z.string().min(1).max(128),
      userId: kookUserId,
      at: z.number().int().nonnegative().safe(),
      messageId: z.string().min(1).max(128),
      valueHash: z.string().regex(/^[a-f0-9]{64}$/),
    })
    .strict(),
]);
type Message = {
  id: string;
  namespace: string;
  epoch: number;
  user_id: string;
  content: string;
  content_hash: string;
  message_id: string | null;
  chat_code: string | null;
  created_at: number;
  expires_at: number;
};
type Button = {
  hash: string;
  message_key: string;
  action: string;
  expires_at: number;
  used_at: number | null;
  result: string | null;
};
type Module = Record<string, unknown>;
const text = (content: string) => ({ type: 'plain-text', content });
const paragraph = (content: string): Module => ({
  type: 'section',
  text: text(content),
});
const link = (label: string, url: string): Module => ({
  type: 'action-group',
  elements: [{ type: 'button', click: 'link', value: url, text: text(label) }],
});
const card = (title: string, modules: Module[]) =>
  JSON.stringify([
    {
      type: 'card',
      theme: 'primary',
      size: 'sm',
      modules: [{ type: 'header', text: text(title) }, ...modules],
    },
  ]);
const labels: Record<string, string> = {
  'account.registered': '账号已注册',
  'order.paid': '订单已核款',
  'entitlement.granted': '版本权益已开通',
  'entitlement.revoked': '版本权益已撤销',
  'device.bound': '设备已绑定',
  'device.reset': '设备换绑已确认',
  'distribution.ready': '个性化制品已准备',
  'identity.changed': '账号身份已调整',
};
export interface PostgresKookBotOptions {
  namespace: string;
  botId: string;
  webhook: KookWebhookOptions;
  api: KookBotApi;
  /** Explicit host policy. A guild/role change requires a new reviewed version. No product guild IDs are built in. */
  admission: (identity: VerifiedIdentity) => Promise<boolean>;
  admissionVersion: string;
  /** Fingerprint of the privately configured Bot API credential, not the credential itself. */
  credentialHash: string;
  sendEnabled?: boolean;
  notificationsEnabled?: boolean;
}
/** Durable, private-message-only Bot adapter. HTTP ingestion performs no platform calls. Sending is opt-in. */
export class PostgresKookBot {
  readonly namespace: string;
  readonly inbox: PostgresTaskQueue;
  readonly deliveries: PostgresTaskQueue;
  readonly notificationWorker: PostgresNotificationWorker;
  private readonly decoder: KookWebhookDecoder;
  private readonly key: Buffer;
  private readonly contextHash: string;
  private readonly api: KookBotApi;
  private readonly botId: string;
  private readonly admission: PostgresKookBotOptions['admission'];
  private readonly sendEnabled: boolean;
  private readonly notificationsEnabled: boolean;
  private constructor(
    readonly framework: AsyncFramework,
    private readonly store: AsyncStore,
    readonly portal: PostgresPortal,
    options: PostgresKookBotOptions,
  ) {
    requireThat(
      !store.transactionUnit &&
        framework.store === store &&
        portal.framework === framework &&
        portal.identityProvider === 'kook',
      'BOT_CONTEXT_INVALID',
    );
    this.namespace = z
      .string()
      .regex(/^[A-Za-z0-9._-]{1,80}$/)
      .parse(options.namespace);
    this.botId = kookUserId.parse(options.botId);
    this.decoder = new KookWebhookDecoder(options.webhook);
    this.api = options.api;
    requireThat(
      typeof options.admission === 'function',
      'BOT_ADMISSION_REQUIRED',
    );
    this.admission = options.admission;
    this.sendEnabled = options.sendEnabled === true;
    this.notificationsEnabled = options.notificationsEnabled === true;
    this.key = portal.deriveAdapterKey(this.namespace);
    this.contextHash = sha256(
      JSON.stringify([
        this.namespace,
        this.botId,
        portal.namespace,
        portal.origin,
        framework.issuer,
        sha256(this.key),
        z.string().min(1).max(128).parse(options.admissionVersion),
        z
          .string()
          .regex(/^[a-f0-9]{64}$/)
          .parse(options.credentialHash),
        sha256(options.webhook.verifyToken),
        options.webhook.encryptionKey === undefined
          ? null
          : sha256(options.webhook.encryptionKey),
        this.decoder.compressed,
      ]),
    );
    const suffix = sha256(this.namespace).slice(0, 24);
    this.inbox = new PostgresTaskQueue(store, {
      namespace: 'kook-in-' + suffix,
    });
    this.deliveries = new PostgresTaskQueue(store, {
      namespace: 'kook-out-' + suffix,
    });
    this.notificationWorker = new PostgresNotificationWorker(store, {
      providers: ['kook'],
      accountEnabled: (accountId) => framework.isAccountActive(accountId),
    });
  }
  static async create(
    framework: AsyncFramework,
    store: AsyncStore,
    portal: PostgresPortal,
    options: PostgresKookBotOptions,
  ) {
    const bot = new PostgresKookBot(framework, store, portal, options);
    await store.run(
      'INSERT INTO bot_settings VALUES($1,$2,$3,1,0) ON CONFLICT(namespace) DO NOTHING',
      bot.namespace,
      portal.namespace,
      bot.contextHash,
    );
    // Restored adapters may be inspected, but never resume on construction.
    await bot.tx(async () => {}, true);
    return bot;
  }
  private async bounded<T>(work: () => Promise<T>): Promise<T> {
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([
        work(),
        new Promise<never>((_resolve, reject) => {
          timer = setTimeout(
            () => reject(new Error('BOT_PLATFORM_TIMEOUT')),
            8000,
          );
        }),
      ]);
    } finally {
      clearTimeout(timer);
    }
  }
  private allowed(userId: string) {
    return this.bounded(() =>
      this.admission({ provider: 'kook', subject: userId }),
    );
  }
  async verifyBotIdentity() {
    requireThat(
      (await this.bounded(() => this.api.me())) === this.botId,
      'BOT_IDENTITY_MISMATCH',
      503,
    );
  }
  private seal(value: string, id: string) {
    const iv = randomBytes(12),
      cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(this.namespace + ':' + id));
    const content = Buffer.concat([
      cipher.update(value, 'utf8'),
      cipher.final(),
    ]);
    return Buffer.concat([
      Buffer.from([1]),
      iv,
      cipher.getAuthTag(),
      content,
    ]).toString('base64url');
  }
  private open(message: Message) {
    try {
      const bytes = Buffer.from(message.content, 'base64url');
      requireThat(
        bytes.length > 29 &&
          bytes.length <= 25000 &&
          bytes[0] === 1 &&
          bytes.toString('base64url') === message.content,
        'BOT_MESSAGE_INVALID',
        503,
      );
      const decrypt = createDecipheriv(
        'aes-256-gcm',
        this.key,
        bytes.subarray(1, 13),
      );
      decrypt.setAAD(Buffer.from(this.namespace + ':' + message.id));
      decrypt.setAuthTag(bytes.subarray(13, 29));
      const value = Buffer.concat([
        decrypt.update(bytes.subarray(29)),
        decrypt.final(),
      ]).toString('utf8');
      requireThat(
        sha256(value) === message.content_hash,
        'BOT_MESSAGE_INVALID',
        503,
      );
      return value;
    } catch {
      requireThat(false, 'BOT_MESSAGE_INVALID', 503);
    }
  }
  private async tx<T>(
    work: (
      unit: AsyncStore,
      framework: AsyncFramework,
      now: number,
      epoch: number,
    ) => Promise<T>,
    allowPaused = false,
  ): Promise<T> {
    for (let attempt = 0; ; attempt++)
      try {
        return await this.store.transaction(async (unit) => {
          const settings = await unit.get<{
            context_hash: string;
            epoch: number;
            paused: number;
          }>(
            'SELECT * FROM bot_settings WHERE namespace=$1 FOR SHARE',
            this.namespace,
          );
          requireThat(
            settings?.context_hash === this.contextHash,
            'BOT_CONTEXT_CHANGED',
            503,
          );
          requireThat(
            allowPaused || settings.paused === 0,
            'BOT_REVIEW_REQUIRED',
            503,
          );
          const now = (await unit.get<{ now: number }>(
            'SELECT floor(extract(epoch FROM clock_timestamp())*1000)::bigint AS now',
          ))!.now;
          return work(unit, this.framework.using(unit), now, settings.epoch);
        });
      } catch (error) {
        if (
          attempt >= 2 ||
          !(error instanceof StorageError) ||
          !error.retryable
        )
          throw error;
      }
  }
  /** The only ingestion API accepts original webhook bytes, not a submitted platform identity. */
  async acceptWebhook(raw: Buffer) {
    const decoded = this.decoder.decode(raw);
    if (!('event' in decoded)) return decoded;
    const event = decoded.event,
      stored: StoredEvent =
        event.kind === 'button'
          ? {
              kind: event.kind,
              id: event.id,
              userId: event.userId,
              at: event.at,
              messageId: event.messageId,
              valueHash: sha256(event.value.slice(4)),
            }
          : event;
    if (event.userId === this.botId) return { ignored: true };
    return this.tx(async (unit, _framework, now, epoch) => {
      requireThat(
        event.at >= now - short && event.at <= now + 30000,
        'BOT_EVENT_EXPIRED',
        401,
      );
      const result = await new PostgresTaskQueue(unit, {
        namespace: 'kook-in-' + sha256(this.namespace).slice(0, 24),
      }).enqueue({
        key: epoch + ':' + event.id,
        payload: { epoch, event: stored },
        ttlMs: short,
      });
      return { accepted: true, replayed: result.replayed };
    });
  }
  private keepAlive(queue: PostgresTaskQueue, lease: TaskLease) {
    let stopped = false,
      lost = false,
      pending: Promise<void> | undefined,
      timer: ReturnType<typeof setTimeout> | undefined;
    const tick = () => {
      timer = setTimeout(() => {
        pending = queue
          .heartbeat(lease)
          .then(
            () => {},
            () => {
              lost = true;
            },
          )
          .finally(() => {
            if (!stopped && !lost) tick();
          });
      }, 30000);
    };
    tick();
    return {
      lost: () => lost,
      stop: async () => {
        stopped = true;
        clearTimeout(timer);
        await pending;
      },
    };
  }
  private async audit(
    unit: AsyncStore,
    actorId: string,
    action: string,
    target: string,
    details: object,
    now: number,
  ) {
    await unit.run(
      'INSERT INTO audit VALUES($1,$2,$3,$4,$5,$6)',
      randomUUID(),
      actorId,
      action,
      target,
      JSON.stringify({ namespace: this.namespace, ...details }),
      now,
    );
  }
  private async plan(
    unit: AsyncStore,
    now: number,
    epoch: number,
    userId: string,
    title: string,
    build: (
      button: (label: string, action: Action) => Module,
    ) => Promise<Module[]> | Module[],
    replyId?: string,
  ) {
    const id = randomUUID(),
      actions: { token: string; action: Action }[] = [],
      expires = now + short;
    const modules = await build((label, action) => {
      const token = randomToken();
      actions.push({ token, action: actionSchema.parse(action) });
      return {
        type: 'action-group',
        elements: [
          {
            type: 'button',
            click: 'return-val',
            value: 'plk:' + token,
            text: text(label),
          },
        ],
      };
    });
    const content = card(title, modules);
    requireThat(
      modules.length < 50 && Buffer.byteLength(content) <= 24000,
      'KOOK_CARD_TOO_LARGE',
    );
    await unit.run(
      'INSERT INTO bot_messages VALUES($1,$2,$3,$4,$5,$6,NULL,NULL,$7,$8)',
      id,
      this.namespace,
      epoch,
      userId,
      this.seal(content, id),
      sha256(content),
      now,
      expires,
    );
    for (const entry of actions)
      await unit.run(
        'INSERT INTO bot_actions VALUES($1,$2,$3,$4,NULL,NULL)',
        sha256(entry.token),
        id,
        JSON.stringify(entry.action),
        expires,
      );
    await new PostgresTaskQueue(unit, {
      namespace: 'kook-out-' + sha256(this.namespace).slice(0, 24),
    }).enqueue({
      key: id,
      payload: { messageId: id, ...(replyId ? { replyId } : {}) },
      ttlMs: short,
    });
    return id;
  }
  private async handle(
    unit: AsyncStore,
    framework: AsyncFramework,
    now: number,
    epoch: number,
    event: StoredEvent,
    action: Action,
    actionKey: string,
  ) {
    const account = await unit.get<{ id: string }>(
      'SELECT id FROM accounts WHERE provider=$1 AND subject=$2',
      'kook',
      event.userId,
    );
    if (account) await framework.assertAccountActive(account.id);
    const plan = (
      title: string,
      build: (
        button: (label: string, action: Action) => Module,
      ) => Promise<Module[]> | Module[],
    ) =>
      this.plan(
        unit,
        now,
        epoch,
        event.userId,
        title,
        build,
        event.kind === 'command' ? event.id : undefined,
      );
    if (action.kind === 'menu')
      return {
        messageId: await plan('授权中心', (button) => [
          paragraph(
            account
              ? '通过下方入口查询账号或创建订单。'
              : '首次使用请注册，再通过网页完成身份与 MFA 验证。',
          ),
          ...(account
            ? [
                button('我的账号', { kind: 'account' }),
                button('购买入口', { kind: 'offers', offset: 0 }),
              ]
            : [button('注册账号', { kind: 'register' })]),
          link('打开用户中心', this.portal.origin + '/'),
        ]),
      };
    if (action.kind === 'register') {
      requireThat(!account, 'IDENTITY_ALREADY_REGISTERED', 409);
      const token = randomToken();
      await unit.run(
        'INSERT INTO bot_handoffs VALUES($1,$2,$3,$4,$5,$6,$7,NULL,NULL,NULL)',
        sha256(token),
        this.namespace,
        epoch,
        this.portal.namespace,
        'kook',
        event.userId,
        now + short,
      );
      const messageId = await plan('注册账号', () => [
        paragraph(
          '链接 5 分钟内有效，只能使用一次；请授权当前 KOOK 账号，并设置 MFA。不会自动开通付费权益。',
        ),
        link('确认身份并注册', this.portal.origin + '/#register=' + token),
      ]);
      await this.audit(
        unit,
        'kook:' + event.userId,
        'bot.registration-issued',
        messageId,
        { expiresAt: now + short },
        now,
      );
      return { messageId };
    }
    requireThat(account, 'IDENTITY_NOT_REGISTERED', 401);
    if (action.kind === 'account')
      return {
        messageId: await plan('我的账号', () => [
          paragraph('账号：' + account.id),
          link('查看权益、设备与订单', this.portal.origin + '/'),
        ]),
      };
    if (action.kind === 'offers') {
      const offers = framework.catalog.offers.slice(
        action.offset,
        action.offset + 12,
      );
      return {
        messageId: await plan('购买入口', (button) => [
          paragraph(
            '金额均为最小货币单位（例如 CNY 的分）。创建订单不会自动核款或开通权益。',
          ),
          ...offers.flatMap((offer) => [
            paragraph(offer.id + ' · ' + offer.amount + ' ' + offer.currency),
            button('创建订单：' + offer.id, {
              kind: 'purchase',
              offerId: offer.id,
              offerHash: sha256(JSON.stringify(offer)),
            }),
          ]),
          ...(action.offset
            ? [
                button('上一页', {
                  kind: 'offers',
                  offset: Math.max(0, action.offset - 12),
                }),
              ]
            : []),
          ...(framework.catalog.offers.length > action.offset + 12
            ? [button('下一页', { kind: 'offers', offset: action.offset + 12 })]
            : []),
          button('返回菜单', { kind: 'menu' }),
        ]),
      };
    }
    requireThat(action.kind === 'purchase', 'BOT_ACTION_INVALID');
    const offer: Offer | undefined = framework.catalog.offers.find(
      (item) => item.id === action.offerId,
    );
    requireThat(
      offer && sha256(JSON.stringify(offer)) === action.offerHash,
      'BOT_OFFER_CHANGED',
      409,
    );
    const order = await framework.createOrder(
      account.id,
      offer.id,
      'bot-' + actionKey,
    );
    const messageId = await plan('订单已创建', () => [
      paragraph('订单：' + order.orderId),
      paragraph(
        '金额：' +
          order.offer.amount +
          ' ' +
          order.offer.currency +
          '（最小货币单位）',
      ),
      paragraph('请按运营方提供的个人收款码流程付款，到账后由操作员核对。'),
      link('查看订单', this.portal.origin + '/'),
    ]);
    await this.audit(
      unit,
      'kook:' + event.userId,
      'bot.order-created',
      order.orderId,
      { messageId },
      now,
    );
    return { orderId: order.orderId, messageId };
  }
  private async proof(message: Message, platformMessageId: string) {
    const chatCode = await this.bounded(() =>
      this.api.conversation(message.user_id),
    );
    if (message.chat_code !== null)
      requireThat(chatCode === message.chat_code, 'BOT_BUTTON_REJECTED', 403);
    const actual = await this.bounded(() =>
      this.api.message(chatCode, platformMessageId),
    );
    requireThat(
      actual.id === platformMessageId &&
        actual.authorId === this.botId &&
        actual.type === 10 &&
        sha256(actual.content) === message.content_hash,
      'BOT_BUTTON_REJECTED',
      403,
    );
    return chatCode;
  }
  private limit(value: number) {
    requireThat(
      Number.isInteger(value) && value >= 1 && value <= 100,
      'INVALID_BOT_LIMIT',
    );
  }
  async runInbox(limit = 20) {
    this.limit(limit);
    let completed = 0,
      failed = 0;
    for (let i = 0; i < limit; i++) {
      const lease = await this.inbox.claim();
      if (!lease) break;
      const heartbeat = this.keepAlive(this.inbox, lease);
      try {
        const payload = z
            .object({
              epoch: z.number().int().positive().safe(),
              event: storedEventSchema,
            })
            .strict()
            .parse(lease.payload),
          event = payload.event;
        requireThat(
          await this.allowed(event.userId),
          'BOT_ADMISSION_DENIED',
          403,
        );
        let proven: Message | undefined;
        if (event.kind === 'button') {
          proven = await this.store.get<Message>(
            'SELECT m.* FROM bot_messages m JOIN bot_actions a ON a.message_key=m.id WHERE a.hash=$1 AND m.namespace=$2',
            event.valueHash,
            this.namespace,
          );
          requireThat(
            proven && proven.user_id === event.userId,
            'BOT_BUTTON_REJECTED',
            403,
          );
          if (proven.message_id === null)
            throw new Error('BOT_PUBLICATION_PENDING');
          requireThat(
            proven.message_id === event.messageId,
            'BOT_BUTTON_REJECTED',
            403,
          );
          await this.proof(proven, event.messageId);
        }
        requireThat(!heartbeat.lost(), 'TASK_LEASE_LOST', 409);
        await heartbeat.stop();
        await this.tx(async (unit, framework, now, epoch) => {
          requireThat(
            epoch === payload.epoch &&
              event.at >= now - short &&
              event.at <= now + 30000,
            'BOT_EVENT_EXPIRED',
            401,
          );
          let action: Action, button: Button | undefined;
          if (event.kind === 'button') {
            const message = await unit.get<Message>(
              'SELECT * FROM bot_messages WHERE id=$1 AND namespace=$2 FOR SHARE',
              proven!.id,
              this.namespace,
            );
            button = await unit.get<Button>(
              'SELECT * FROM bot_actions WHERE hash=$1 FOR UPDATE',
              event.valueHash,
            );
            requireThat(
              message &&
                button &&
                button.message_key === message.id &&
                message.epoch === epoch &&
                message.user_id === event.userId &&
                message.message_id === event.messageId &&
                message.content_hash === proven!.content_hash &&
                button.expires_at > now,
              'BOT_BUTTON_REJECTED',
              403,
            );
            if (button.used_at !== null) {
              await this.inbox.complete(
                lease,
                { replayed: true, receipt: JSON.parse(button.result!) },
                unit,
              );
              return;
            }
            action = actionSchema.parse(JSON.parse(button.action));
          } else
            action =
              event.command === 'buy'
                ? { kind: 'offers', offset: 0 }
                : { kind: event.command };
          let result: object;
          try {
            result = await this.handle(
              unit,
              framework,
              now,
              epoch,
              event,
              action,
              event.kind === 'button' ? event.valueHash : sha256(event.id),
            );
          } catch (error) {
            const messages: Record<string, string> = {
              IDENTITY_ALREADY_REGISTERED:
                '此 KOOK 账号已注册，请通过用户中心登录。',
              IDENTITY_NOT_REGISTERED: '请先通过注册入口创建账号。',
              BOT_OFFER_CHANGED: '商品信息已变化，请重新打开购买入口。',
              EDITION_ALREADY_OWNED: '你已拥有该版本。',
              CHANNEL_ALREADY_OWNED: '你已拥有该渠道。',
              UPGRADE_NOT_ELIGIBLE: '当前账号不符合升级条件。',
              GROUP_NOT_OWNED: '当前账号没有该设备组权益。',
              PENDING_ORDER_EXISTS: '已有待付款订单，请在用户中心查看。',
            };
            if (!(error instanceof DomainError) || !messages[error.code])
              throw error;
            result = {
              error: error.code,
              messageId: await this.plan(
                unit,
                now,
                epoch,
                event.userId,
                '操作未完成',
                () => [
                  paragraph(messages[error.code]!),
                  link('打开用户中心', this.portal.origin + '/'),
                ],
              ),
            };
          }
          if (button)
            await unit.run(
              'UPDATE bot_actions SET used_at=$2,result=$3 WHERE hash=$1',
              button.hash,
              now,
              JSON.stringify(result),
            );
          await this.inbox.complete(lease, result, unit);
        });
        completed++;
      } catch (error) {
        await heartbeat.stop();
        failed++;
        // No external business mutation occurs in this worker; DB-only transactions may be safely retried after a definite rollback.
        try {
          await this.inbox.fail(
            lease,
            error instanceof DomainError ? error.code : 'BOT_INBOX_FAILED',
            {
              retryable: !(
                error instanceof DomainError || error instanceof z.ZodError
              ),
              definitelyNotSent: true,
            },
          );
        } catch {
          /* A lost COMMIT receipt is reconciled by the durable job, never by replaying outside it. */
        }
      } finally {
        await heartbeat.stop();
      }
    }
    return { completed, failed };
  }
  async runDeliveries(limit = 20) {
    this.limit(limit);
    requireThat(this.sendEnabled, 'BOT_SENDING_DISABLED', 403);
    let delivered = 0,
      failed = 0,
      uncertain = 0;
    await this.tx(async () => {});
    for (let i = 0; i < limit; i++) {
      let lease = await this.deliveries.claim();
      if (!lease) break;
      const heartbeat = this.keepAlive(this.deliveries, lease);
      let called = false;
      try {
        const payload = z
          .object({
            messageId: uuid,
            replyId: z.string().min(1).max(128).optional(),
          })
          .strict()
          .parse(lease.payload);
        const deliveryKey = lease.key;
        const message = await this.tx(async (unit, _framework, now, epoch) => {
          const row = await unit.get<Message>(
            'SELECT * FROM bot_messages WHERE id=$1 AND namespace=$2',
            payload.messageId,
            this.namespace,
          );
          requireThat(
            row &&
              row.epoch === epoch &&
              row.expires_at > now &&
              row.message_id === null &&
              row.id === deliveryKey,
            'BOT_MESSAGE_INVALID',
            409,
          );
          return row;
        });
        requireThat(
          await this.allowed(message.user_id),
          'BOT_ADMISSION_DENIED',
          403,
        );
        const content = this.open(message),
          chatCode = await this.bounded(() =>
            this.api.conversation(message.user_id),
          );
        requireThat(!heartbeat.lost(), 'TASK_LEASE_LOST', 409);
        const initial = lease;
        lease = await this.tx(async (unit, _framework, _now, epoch) => {
          requireThat(epoch === message.epoch, 'BOT_REVIEW_REQUIRED', 503);
          return this.deliveries.beginExternal(initial, unit);
        });
        called = true;
        const messageId = await this.bounded(() =>
          this.api.send(message.user_id, content, payload.replyId),
        );
        await heartbeat.stop();
        requireThat(!heartbeat.lost(), 'TASK_LEASE_LOST', 409);
        const sending = lease;
        await this.tx(async (unit, _framework, _now, epoch) => {
          requireThat(epoch === message.epoch, 'BOT_REVIEW_REQUIRED', 503);
          await unit.run(
            'UPDATE bot_messages SET message_id=$2,chat_code=$3 WHERE id=$1',
            message.id,
            messageId,
            chatCode,
          );
          await this.deliveries.complete(sending, { messageId }, unit);
        });
        delivered++;
      } catch (error) {
        await heartbeat.stop();
        failed++;
        const safe =
          !called || (error instanceof KookApiError && error.definitelyNotSent);
        try {
          const state = await this.deliveries.fail(
            lease,
            error instanceof DomainError
              ? error.code
              : safe
                ? 'KOOK_SEND_REJECTED'
                : 'EXTERNAL_RESULT_UNCERTAIN',
            {
              retryable:
                safe &&
                !(error instanceof DomainError || error instanceof z.ZodError),
              ...(safe ? { definitelyNotSent: true as const } : {}),
            },
          );
          if (state.state === 'uncertain') uncertain++;
        } catch {
          if (called) uncertain++;
        }
      } finally {
        await heartbeat.stop();
      }
    }
    return { delivered, failed, uncertain };
  }
  /** Trusted operator only. Publishing requires API evidence; retry requires explicit proof that no message was sent. */
  async resolveDelivery(
    key: string,
    input:
      | {
          outcome: 'published';
          messageId: string;
          generation: number;
          actor: string;
          reason: string;
        }
      | {
          outcome: 'retry';
          confirmedNotSent: true;
          generation: number;
          actor: string;
          reason: string;
        }
      | {
          outcome: 'cancelled';
          generation: number;
          actor: string;
          reason: string;
        },
  ) {
    key = uuid.parse(key);
    input = structuredClone(input);
    actor.parse(input.actor);
    reason.parse(input.reason);
    const snapshot = await this.store.get<Message>(
      'SELECT * FROM bot_messages WHERE id=$1 AND namespace=$2',
      key,
      this.namespace,
    );
    requireThat(snapshot, 'BOT_MESSAGE_MISSING', 404);
    const chat =
      input.outcome === 'published'
        ? await this.proof(
            snapshot,
            z.string().min(1).max(128).parse(input.messageId),
          )
        : undefined;
    return this.tx(async (unit, _framework, now, epoch) => {
      if (input.outcome !== 'cancelled')
        requireThat(
          epoch === snapshot.epoch && snapshot.expires_at > now,
          'BOT_MESSAGE_EXPIRED',
          409,
        );
      const result = await this.deliveries.resolve(
        key,
        {
          actor: input.actor,
          reason: input.reason,
          generation: input.generation,
          outcome: input.outcome === 'published' ? 'succeeded' : input.outcome,
          ...(input.outcome === 'retry'
            ? { confirmedNotSent: input.confirmedNotSent }
            : {}),
          ...(input.outcome === 'published'
            ? { result: { messageId: input.messageId } }
            : {}),
        },
        unit,
      );
      if (input.outcome === 'published')
        await unit.run(
          'UPDATE bot_messages SET message_id=$2,chat_code=$3 WHERE id=$1',
          key,
          input.messageId,
          chat!,
        );
      return result;
    }, input.outcome === 'cancelled');
  }
  async runNotifications(limit = 20) {
    this.limit(limit);
    requireThat(
      this.sendEnabled && this.notificationsEnabled,
      'BOT_NOTIFICATIONS_DISABLED',
      403,
    );
    await this.tx(async (unit) => {
      await unit.run(
        'INSERT INTO bot_notification_owners VALUES($1,$2) ON CONFLICT(issuer) DO NOTHING',
        this.framework.issuer,
        this.namespace,
      );
      requireThat(
        (
          await unit.get<{ namespace: string }>(
            'SELECT namespace FROM bot_notification_owners WHERE issuer=$1',
            this.framework.issuer,
          )
        )?.namespace === this.namespace,
        'BOT_NOTIFICATION_OWNER_CONFLICT',
        409,
      );
    });
    return this.notificationWorker.run(
      {
        send: async (event, identity) => {
          try {
            requireThat(
              identity.provider === 'kook' &&
                (await this.allowed(identity.subject)),
              'BOT_ADMISSION_DENIED',
              403,
            );
            await this.tx(async (_unit, framework) => {
              await framework.assertAccountActive(event.accountId);
            });
          } catch {
            throw new NotificationNotSentError(
              'BOT_NOTIFICATION_PREPARATION_FAILED',
            );
          }
          const content = card(labels[event.topic] ?? '账号状态通知', [
            paragraph('事件：' + event.id),
            ...(event.resource
              ? [
                  paragraph(
                    '业务记录：' +
                      event.resource.kind +
                      ' / ' +
                      event.resource.id,
                  ),
                ]
              : []),
            link('查看用户中心', this.portal.origin + '/'),
          ]);
          try {
            await this.bounded(() => this.api.send(identity.subject, content));
          } catch (error) {
            if (error instanceof KookApiError && error.definitelyNotSent)
              throw new NotificationNotSentError('KOOK_SEND_REJECTED');
            throw error;
          }
        },
      },
      limit,
    );
  }
  /** Pause invalidates every existing action and handoff. Resumption always names a reviewer and current epoch. */
  async review(input: {
    paused: boolean;
    epoch: number;
    actor: string;
    reason: string;
  }) {
    input = z
      .object({
        paused: z.boolean(),
        epoch: z.number().int().positive().safe(),
        actor,
        reason,
      })
      .strict()
      .parse(input);
    return this.tx(async (unit, _framework, now, epoch) => {
      requireThat(input.epoch === epoch, 'BOT_REVIEW_STALE', 409);
      await unit.run(
        'UPDATE bot_settings SET paused=$2,epoch=epoch+$3 WHERE namespace=$1',
        this.namespace,
        input.paused ? 1 : 0,
        input.paused ? 1 : 0,
      );
      await this.audit(
        unit,
        input.actor,
        input.paused ? 'bot.paused' : 'bot.resumed',
        this.namespace,
        { epoch: epoch + (input.paused ? 1 : 0), reason: input.reason },
        now,
      );
      return { epoch: epoch + (input.paused ? 1 : 0), paused: input.paused };
    }, true);
  }
}
