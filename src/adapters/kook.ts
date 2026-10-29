import { z } from 'zod';
import { DomainError, requireThat, type IdentityProvider, type Notification, type NotificationSink, type VerifiedIdentity } from '../core/model.js';

export class KookIdentityProvider implements IdentityProvider {
  readonly name = 'kook';
  constructor(private readonly http: typeof fetch = fetch) {}
  async verify(accessToken: string): Promise<VerifiedIdentity> {
    try {
      const response = await this.http('https://www.kookapp.cn/api/v3/user/me', {
        headers: { Authorization: `Bearer ${accessToken}` }, signal: AbortSignal.timeout(8000), redirect: 'error',
      });
      requireThat(response.ok, 'IDENTITY_VERIFICATION_FAILED', 401);
      const body = z.object({ code: z.literal(0), data: z.object({ id: z.string().min(1).max(128) }) }).parse(await response.json());
      return { provider: this.name, subject: body.data.id };
    } catch (error) {
      if (error instanceof DomainError) throw error;
      throw new DomainError('IDENTITY_PROVIDER_UNAVAILABLE', 503);
    }
  }
}

/** Opt-in adapter. Nothing sends messages unless a deployment calls dispatchNotifications. */
export class KookNotificationSink implements NotificationSink {
  constructor(private readonly botToken: string, private readonly http: typeof fetch = fetch) {}
  async send(event: Notification, identity: VerifiedIdentity): Promise<void> {
    requireThat(identity.provider === 'kook', 'UNSUPPORTED_NOTIFICATION_PROVIDER');
    const labels: Record<string, string> = {
      'account.registered': '账号已注册', 'order.fulfilled': '订单权益已发放',
      'device.activated': '设备绑定已更新', 'distribution.ready': '专属文件已准备完成',
      'entitlement.revoked': '版本授权状态已更新', 'identity.changed': '账号关联身份已更新',
    };
    const response = await this.http('https://www.kookapp.cn/api/v3/direct-message/create', {
      method: 'POST', headers: { Authorization: `Bot ${this.botToken}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 1, target_id: identity.subject,
        content: `${labels[event.topic] ?? '账号状态已更新'}。请到产品用户中心查看。通知编号：${event.id}` }),
      signal: AbortSignal.timeout(8000), redirect: 'error',
    });
    requireThat(response.ok, 'NOTIFICATION_FAILED', 502);
    z.object({ code: z.literal(0) }).parse(await response.json());
  }
}
