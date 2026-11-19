import test from 'node:test';
import assert from 'node:assert/strict';
import { KookOAuthClient, KookIdentityProvider } from '../src/index.js';
import { harness, key } from './helpers.js';

test('the public KOOK OAuth client exchanges a server-side code and verifies the resulting user identity', async () => {
  const callback = 'https://product.example/auth/callback';
  const calls: string[] = [];
  const client = new KookOAuthClient('test-client', 'fake-only-client-secret', callback, async (input, options) => {
    const url = String(input); calls.push(url);
    assert.equal(options?.redirect, 'error');
    if (url === 'https://www.kookapp.cn/api/oauth2/token') {
      assert.deepEqual(JSON.parse(String(options?.body)), {
        grant_type: 'authorization_code', client_id: 'test-client', client_secret: 'fake-only-client-secret',
        redirect_uri: callback, code: 'single-use-code',
      });
      return Response.json({access_token: 'temporary-user-token', token_type: 'Bearer', scope: 'get_user_info'});
    }
    assert.equal(url, 'https://www.kookapp.cn/api/v3/user/me');
    assert.equal((options?.headers as Record<string, string>).Authorization, 'Bearer temporary-user-token');
    return Response.json({code: 0, data: {id: '123456'}});
  });
  const state = key() + key();
  const url = new URL(client.authorizationUrl(state));
  assert.equal(url.origin, 'https://www.kookapp.cn');
  assert.equal(url.searchParams.get('state'), state);
  assert.equal(url.searchParams.get('scope'), 'get_user_info');
  assert.equal(url.searchParams.get('redirect_uri'), callback);
  assert.equal(url.searchParams.has('client_secret'), false);
  assert.deepEqual(await client.verify('single-use-code'), {provider: 'kook', subject: '123456'});
  assert.equal(calls.length, 2);
});

test('KOOK OAuth rejects weak state, unbounded codes and unverified user responses', async () => {
  let calls = 0;
  const client = new KookOAuthClient('test-client', 'fake-only-client-secret', 'https://product.example/auth/callback', async input => {
    calls++;
    if (String(input).endsWith('/token'))
      return Response.json({access_token: 'temporary-user-token', token_type: 'Bearer', scope: 'get_user_info'});
    return Response.json({code: 1, data: {id: 'forged-user'}});
  });
  assert.throws(() => client.authorizationUrl('predictable'), /INVALID_OAUTH_STATE/);
  await assert.rejects(client.verify(''), /INVALID_OAUTH_CODE/);
  await assert.rejects(client.verify('x'.repeat(4097)), /INVALID_OAUTH_CODE/);
  assert.equal(calls, 0);
  await assert.rejects(client.verify('code'), /KOOK_OAUTH_UNAVAILABLE/);
  assert.equal(calls, 2);
  assert.throws(() => new KookOAuthClient('id', 'secret', 'https://product.example/auth/callback?unexpected=1'), /KOOK_OAUTH_CALLBACK_INVALID/);
});

test('KOOK authorization codes work through normal framework registration and login', async t => {
  const h = harness(); t.after(h.close);
  const http: typeof fetch = async input => {
    if (String(input).endsWith('/token'))
      return Response.json({access_token: 'temporary-user-token', token_type: 'Bearer', scope: 'get_user_info'});
    return Response.json({code: 0, data: {id: '123456'}});
  };
  const client = new KookOAuthClient('test-client', 'fake-only-client-secret', 'https://product.example/auth/callback', http);
  h.framework.providers.set('kook', new KookIdentityProvider(http));
  const invitation = h.framework.issueInvitation('kook', '123456');
  const registered = await h.framework.register(invitation.ticket, await client.exchange('verified-registration-code'));
  const login = await h.framework.login('kook', await client.exchange('verified-login-code'));
  assert.equal(login.accountId, registered.accountId);
  assert.notEqual(login.accessToken, registered.accessToken);
  assert.deepEqual(h.framework.profile(login.accountId).entitlements, []);
});
