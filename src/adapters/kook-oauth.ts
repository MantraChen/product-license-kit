import { z } from 'zod';
import { requireThat, type VerifiedIdentity } from '../core/model.js';
import { KookIdentityProvider } from './kook.js';

/** Confidential server-side client. The host binds and consumes its own browser state. */
export class KookOAuthClient {
  constructor(
    private readonly clientId: string,
    private readonly clientSecret: string,
    private readonly callback: string,
    private readonly http: typeof fetch = fetch,
  ) {
    requireThat(clientId.length > 0 && clientId.length <= 200 && clientSecret.length > 0 && clientSecret.length <= 1024,
      'KOOK_OAUTH_CONFIG_INVALID');
    const url = new URL(callback);
    requireThat(!url.username && !url.password && !url.search && !url.hash &&
      (url.protocol === 'https:' || (url.protocol === 'http:' && ['127.0.0.1', 'localhost', '[::1]'].includes(url.hostname))),
      'KOOK_OAUTH_CALLBACK_INVALID');
  }
  authorizationUrl(state: string): string {
    requireThat(/^[A-Za-z0-9_-]{32,128}$/.test(state), 'INVALID_OAUTH_STATE');
    const url = new URL('https://www.kookapp.cn/app/oauth2/authorize');
    url.search = new URLSearchParams({ client_id: this.clientId, redirect_uri: this.callback,
      response_type: 'code', scope: 'get_user_info', state }).toString();
    return url.href;
  }
  async exchange(code: string): Promise<string> {
    requireThat(code.length > 0 && code.length <= 4096, 'INVALID_OAUTH_CODE');
    try {
      const response = await this.http('https://www.kookapp.cn/api/oauth2/token', {
        method: 'POST', redirect: 'error', signal: AbortSignal.timeout(8000),
        headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
        body: JSON.stringify({ grant_type: 'authorization_code', client_id: this.clientId,
          client_secret: this.clientSecret, redirect_uri: this.callback, code }),
      });
      requireThat(response.ok && response.body, 'KOOK_OAUTH_UNAVAILABLE', 503);
      const reader = response.body.getReader();
      const chunks: Uint8Array[] = [];
      let size = 0;
      try {
        for (;;) {
          const part = await reader.read();
          if (part.done) break;
          size += part.value.length;
          requireThat(size <= 32768, 'KOOK_OAUTH_RESPONSE_INVALID', 502);
          chunks.push(part.value);
        }
      } finally { await reader.cancel(); }
      const result = z.object({
        access_token: z.string().min(1).max(4096), token_type: z.literal('Bearer'),
        scope: z.string().max(1000).refine(value => value.split(' ').includes('get_user_info')),
      }).parse(JSON.parse(Buffer.concat(chunks).toString('utf8')));
      return result.access_token;
    } catch { requireThat(false, 'KOOK_OAUTH_UNAVAILABLE', 503); }
  }
  async verify(code: string): Promise<VerifiedIdentity> {
    const accessToken = await this.exchange(code);
    try { return await new KookIdentityProvider(this.http).verify(accessToken); }
    catch { requireThat(false, 'KOOK_OAUTH_UNAVAILABLE', 503); }
  }
}
