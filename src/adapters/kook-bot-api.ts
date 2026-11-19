import { z } from 'zod';
import { requireThat } from '../core/model.js';

export const kookUserId = z.string().regex(/^[0-9]{1,32}$/);
const platformId = z
  .string()
  .min(1)
  .max(128)
  .regex(/^[A-Za-z0-9._:-]+$/);
/** A completed rejection is distinct from a timeout or an unparseable successful response. */
export class KookApiError extends Error {
  constructor(readonly definitelyNotSent: boolean) {
    super('KOOK_API_UNAVAILABLE');
  }
}
export interface KookPrivateMessage {
  id: string;
  authorId: string;
  content: string;
  type: number;
}
export interface KookBotApi {
  me(): Promise<string>;
  admitted(
    userId: string,
    guildId: string,
    anyRoleIds: readonly number[],
  ): Promise<boolean>;
  conversation(userId: string): Promise<string>;
  message(chatCode: string, messageId: string): Promise<KookPrivateMessage>;
  send(
    userId: string,
    content: string,
    replyMessageId?: string,
  ): Promise<string>;
}
/** Fixed official API origin, bounded responses, no redirect, no automatic request replay. */
export class KookBotClient implements KookBotApi {
  constructor(
    private readonly token: string,
    private readonly http: typeof fetch = fetch,
  ) {
    requireThat(
      token.length >= 1 && token.length <= 4096 && !/[\r\n]/.test(token),
      'KOOK_BOT_CONFIG_INVALID',
    );
  }
  private async request(
    path: string,
    data: Record<string, unknown> = {},
    method = 'GET',
  ): Promise<unknown> {
    try {
      const url = new URL('https://www.kookapp.cn/api/v3/' + path);
      if (method === 'GET')
        for (const [key, value] of Object.entries(data))
          url.searchParams.set(key, String(value));
      const response = await this.http(url.href, {
        method,
        redirect: 'error',
        signal: AbortSignal.timeout(8000),
        headers: {
          Authorization: 'Bot ' + this.token,
          Accept: 'application/json',
          ...(method === 'POST' ? { 'Content-Type': 'application/json' } : {}),
        },
        ...(method === 'POST' ? { body: JSON.stringify(data) } : {}),
      });
      // These responses reject the request itself; 408/5xx and broken success receipts remain unknown.
      if (!response.ok)
        throw new KookApiError(
          [400, 401, 403, 404, 405, 413, 415, 422, 429].includes(
            response.status,
          ),
        );
      requireThat(response.body, 'KOOK_API_RESPONSE_INVALID');
      const reader = response.body.getReader(),
        chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.length;
          requireThat(size <= 131072, 'KOOK_API_RESPONSE_INVALID');
          chunks.push(part.value);
        }
      } finally {
        await reader.cancel();
      }
      const body = z
        .object({ code: z.number().int(), data: z.unknown().optional() })
        .parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      if (body.code !== 0) throw new KookApiError(true);
      return body.data;
    } catch (error) {
      if (error instanceof KookApiError) throw error;
      throw new KookApiError(false);
    }
  }
  async me() {
    return kookUserId.parse(
      z.object({ id: kookUserId }).parse(await this.request('user/me')).id,
    );
  }
  async admitted(
    userId: string,
    guildId: string,
    anyRoleIds: readonly number[],
  ) {
    const data = z
      .object({
        id: kookUserId,
        bot: z.boolean(),
        roles: z.array(z.number().int().nonnegative().safe()).max(1000),
      })
      .parse(
        await this.request('user/view', {
          target_id: kookUserId.parse(userId),
          guild_id: kookUserId.parse(guildId),
        }),
      );
    return (
      data.id === userId &&
      !data.bot &&
      data.roles.some((role) => anyRoleIds.includes(role))
    );
  }
  async conversation(userId: string) {
    const data = z
      .object({
        code: platformId,
        target_info: z.object({ id: kookUserId }),
        is_blocked: z.boolean(),
        is_target_blocked: z.boolean(),
      })
      .parse(
        await this.request(
          'user-chat/create',
          { target_id: kookUserId.parse(userId) },
          'POST',
        ),
      );
    requireThat(
      data.target_info.id === userId &&
        !data.is_blocked &&
        !data.is_target_blocked,
      'KOOK_CONVERSATION_REJECTED',
      403,
    );
    return data.code;
  }
  async message(
    chatCode: string,
    messageId: string,
  ): Promise<KookPrivateMessage> {
    const data = z
      .object({
        id: platformId,
        author_id: kookUserId,
        content: z.string().max(65536),
        type: z.number().int(),
      })
      .parse(
        await this.request('direct-message/view', {
          chat_code: platformId.parse(chatCode),
          msg_id: platformId.parse(messageId),
        }),
      );
    requireThat(data.id === messageId, 'KOOK_MESSAGE_INVALID', 403);
    return {
      id: data.id,
      authorId: data.author_id,
      content: data.content,
      type: data.type,
    };
  }
  async send(userId: string, content: string, replyMessageId?: string) {
    requireThat(Buffer.byteLength(content) <= 24000, 'KOOK_CARD_TOO_LARGE');
    const data = await this.request(
      'direct-message/create',
      {
        target_id: kookUserId.parse(userId),
        type: 10,
        content,
        ...(replyMessageId
          ? { reply_msg_id: platformId.parse(replyMessageId) }
          : {}),
      },
      'POST',
    );
    try {
      return z.object({ msg_id: platformId }).parse(data).msg_id;
    } catch {
      throw new KookApiError(false);
    }
  }
}
