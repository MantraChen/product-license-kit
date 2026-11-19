import Fastify, { type FastifyRequest } from 'fastify';
import cookie from '@fastify/cookie';
import rateLimit from '@fastify/rate-limit';
import QRCode from 'qrcode';
import { z } from 'zod';
import { PostgresPortal } from '../adapters/postgres-portal.js';
import { DomainError, requireThat } from '../core/model.js';
import { StorageError } from '../core/async-store.js';
import { trustedProxies } from '../security/proxy.js';
import { portalHtml, portalCss, portalScript } from './portal-assets.js';

/** A separate same-origin browser server. The headless deployment administrator token is never accepted here. */
export async function createPortalApp(
  portal: PostgresPortal,
  options: { logger?: boolean; trustedProxyCidrs?: string } = {},
) {
  const app = Fastify({
    bodyLimit: 16384,
    requestTimeout: 15000,
    trustProxy: trustedProxies(options.trustedProxyCidrs),
    logger: options.logger
      ? {
          redact: [
            'req.headers.authorization',
            'req.headers.cookie',
            'res.headers.set-cookie',
          ],
          serializers: {
            req: (request: {
              method: string;
              url: string;
              hostname: string;
              ip: string;
            }) => ({
              method: request.method,
              url: request.url.split('?')[0] ?? '/',
              hostname: request.hostname,
              ip: request.ip,
            }),
          },
        }
      : false,
  });
  await app.register(cookie);
  await app.register(rateLimit, {
    global: true,
    max: 120,
    timeWindow: '1 minute',
    skipOnError: false,
    store: portal.rateLimiter.fastifyStore(),
  });
  const sessionName = portal.secureCookies ? '__Host-plk_portal' : 'plk_portal',
    stateName = portal.secureCookies ? '__Host-plk_oauth' : 'plk_oauth';
  const flags = {
    path: '/',
    httpOnly: true,
    secure: portal.secureCookies,
    sameSite: 'lax' as const,
  };
  const token = (request: FastifyRequest) => {
    const value = request.cookies[sessionName];
    requireThat(
      typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value),
      'PORTAL_AUTH_REQUIRED',
      401,
    );
    return value;
  };
  const csrf = (request: FastifyRequest) => {
    const value = request.headers['x-csrf-token'];
    requireThat(
      typeof value === 'string' && /^[A-Za-z0-9_-]{43}$/.test(value),
      'CSRF_REJECTED',
      403,
    );
    return value;
  };
  const page = z
    .object({
      limit: z.coerce.number().int().min(1).max(100).default(20),
      cursor: z.string().min(1).max(4096).optional(),
    })
    .strict();
  app.addHook('onRequest', async (request, reply) => {
    reply
      .header('Cache-Control', 'no-store')
      .header('X-Content-Type-Options', 'nosniff')
      .header('Referrer-Policy', 'no-referrer')
      .header(
        'Content-Security-Policy',
        "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'",
      )
      .header('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
    if (portal.secureCookies)
      reply.header('Strict-Transport-Security', 'max-age=31536000');
    if (request.headers.origin !== undefined)
      requireThat(
        request.headers.origin === portal.origin,
        'ORIGIN_REJECTED',
        403,
      );
    if (!['GET', 'HEAD', 'OPTIONS'].includes(request.method)) {
      requireThat(
        request.headers.origin === portal.origin,
        'ORIGIN_REQUIRED',
        403,
      );
      requireThat(
        /^application\/json(?:\s*;|$)/i.test(
          request.headers['content-type'] ?? '',
        ),
        'JSON_REQUIRED',
        415,
      );
    }
  });
  app.setErrorHandler(
    (error: Error & { statusCode?: number }, request, reply) => {
      if (error instanceof DomainError)
        return reply.code(error.status).send({ error: error.code });
      if (error instanceof StorageError)
        return reply.code(503).send({
          error: [
            'TRANSACTION_COMMIT_UNCERTAIN',
            'POSTGRES_RESULT_UNCERTAIN',
          ].includes(error.code)
            ? error.code
            : 'STORAGE_UNAVAILABLE',
          retryable: error.retryable,
        });
      if (error instanceof z.ZodError)
        return reply.code(400).send({ error: 'INVALID_REQUEST' });
      if (error.statusCode && error.statusCode >= 400 && error.statusCode < 500)
        return reply.code(error.statusCode).send({
          error: error.statusCode === 429 ? 'RATE_LIMITED' : 'INVALID_REQUEST',
        });
      request.log.error(
        { requestId: request.id, errorType: error.name },
        'Portal request failed',
      );
      return reply.code(500).send({ error: 'INTERNAL_ERROR' });
    },
  );
  app.get('/health', async () => ({ ok: true }));
  app.get('/', async (_request, reply) =>
    reply.type('text/html; charset=utf-8').send(portalHtml),
  );
  app.get('/admin', async (_request, reply) =>
    reply.type('text/html; charset=utf-8').send(portalHtml),
  );
  app.get('/portal.css', async (_request, reply) =>
    reply.type('text/css; charset=utf-8').send(portalCss),
  );
  app.get('/portal.js', async (_request, reply) =>
    reply.type('text/javascript; charset=utf-8').send(portalScript),
  );
  app.post(
    '/api/auth/start',
    { config: { rateLimit: { max: 15, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const input = z
          .object({
            remember: z.boolean().default(false),
            registration: z
              .string()
              .regex(/^[A-Za-z0-9_-]{43}$/)
              .optional(),
          })
          .strict()
          .parse(request.body),
        result = await portal.beginOAuth(input.remember, input.registration);
      reply.setCookie(stateName, result.browser, { ...flags, maxAge: 300 });
      return { authorizationUrl: result.authorizationUrl };
    },
  );
  app.get(
    '/auth/callback',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (request, reply) => {
      const input = z
        .object({
          state: z.string().min(32).max(128),
          code: z.string().min(1).max(4096),
        })
        .strict()
        .parse(request.query);
      const browser = request.cookies[stateName];
      requireThat(browser, 'OAUTH_STATE_INVALID', 401);
      const result = await portal.completeOAuth(
        input.state,
        browser,
        input.code,
      );
      reply.clearCookie(stateName, flags);
      reply.setCookie(sessionName, result.token, {
        ...flags,
        maxAge: result.maxAge,
      });
      return reply.redirect('/');
    },
  );
  app.get('/api/session', async (request) => portal.current(token(request)));
  app.get('/api/setup-qr', async (request, reply) => {
    const session = await portal.current(token(request));
    requireThat(
      session.stage === 'setup' && session.setup,
      'PORTAL_ENROLLMENT_REQUIRED',
      403,
    );
    return reply.type('image/png').send(
      await QRCode.toBuffer(session.setup.uri, {
        type: 'png',
        width: 240,
        margin: 2,
        errorCorrectionLevel: 'M',
      }),
    );
  });
  app.post(
    '/api/auth/mfa',
    { config: { rateLimit: { max: 20, timeWindow: '5 minutes' } } },
    async (request, reply) => {
      const input = z
          .object({ code: z.string().min(1).max(64) })
          .strict()
          .parse(request.body),
        result = await portal.verifyMfa(
          token(request),
          csrf(request),
          input.code,
        );
      reply.setCookie(sessionName, result.token, {
        ...flags,
        maxAge: result.maxAge,
      });
      return { ok: true, recoveryCodes: result.recoveryCodes };
    },
  );
  app.post('/api/auth/recovery-codes', async (request) =>
    portal.rotateRecoveryCodes(
      token(request),
      csrf(request),
      z
        .object({ code: z.string().regex(/^\d{6}$/) })
        .strict()
        .parse(request.body).code,
    ),
  );
  app.post('/api/auth/logout', async (request, reply) => {
    z.object({}).strict().parse(request.body);
    const result = await portal.logout(token(request), csrf(request));
    reply.clearCookie(sessionName, flags);
    return result;
  });
  app.get('/api/profile', async (request) =>
    portal.userData(token(request), 'profile'),
  );
  app.get('/api/orders', async (request) =>
    portal.userData(token(request), 'orders', page.parse(request.query)),
  );
  app.get('/api/distributions', async (request) =>
    portal.userData(token(request), 'distributions', page.parse(request.query)),
  );
  app.post('/api/orders', async (request) =>
    portal.createOrder(token(request), csrf(request), request.body),
  );
  app.post('/api/devices/reset-preview', async (request) =>
    portal.resetPreview(
      token(request),
      csrf(request),
      z
        .object({ groupId: z.string().min(1).max(80) })
        .strict()
        .parse(request.body).groupId,
    ),
  );
  app.post('/api/devices/reset-confirm', async (request) => {
    const input = z
      .object({
        intent: z.string().min(1).max(128),
        confirmed: z.literal(true),
      })
      .strict()
      .parse(request.body);
    return portal.resetConfirm(
      token(request),
      csrf(request),
      input.intent,
      input.confirmed,
    );
  });
  app.get('/api/admin/account/:id', async (request) =>
    portal.adminData(
      token(request),
      'account',
      z.object({ id: z.string().uuid() }).parse(request.params).id,
    ),
  );
  app.get('/api/admin/audit', async (request) =>
    portal.adminData(token(request), 'audit', page.parse(request.query)),
  );
  app.get('/api/admin/operators', async (request) =>
    portal.adminData(token(request), 'operators'),
  );
  app.post('/api/admin/actions/:action', async (request) =>
    portal.adminWrite(
      token(request),
      csrf(request),
      z
        .object({
          action: z.enum([
            'account-status',
            'revoke-entitlement',
            'grant-credits',
            'operator',
            'invitation',
            'payment',
          ]),
        })
        .parse(request.params).action,
      request.body,
    ),
  );
  return app;
}
