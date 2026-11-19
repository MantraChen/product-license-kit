import Fastify, { type FastifyRequest } from 'fastify';
import rateLimit from '@fastify/rate-limit';
import { z } from 'zod';
import { DomainError, requireThat } from '../core/model.js';
import { secretEqual } from '../core/crypto.js';
import type { Framework } from '../service.js';
import type { AsyncFramework } from '../async-service.js';
import { StorageError } from '../core/async-store.js';
import type { PostgresRateLimiter } from '../adapters/postgres-rate-limit.js';
import type { PostgresSigningCoordinator } from '../adapters/postgres-signing.js';
import { trustedProxies } from '../security/proxy.js';

const id = z.string().regex(/^[a-zA-Z0-9][a-zA-Z0-9._-]{0,79}$/);
const subject = z.string().min(1).max(128);
const proof = z.string().min(1).max(4096);
const reason = z.string().min(3).max(500);
const uuid = z.string().uuid();
const signature = z
  .string()
  .regex(/^(?:[A-Za-z0-9_-]{86}|[A-Za-z0-9_-]{342})$/);
const keySchema = z.string().regex(/^[A-Za-z0-9_-]{16,128}$/);
const paramsId = (request: FastifyRequest) =>
  z.object({ id: uuid }).parse(request.params).id;
const bearer = (request: FastifyRequest): string => {
  const match = /^Bearer ([A-Za-z0-9_-]{32,512})$/.exec(
    request.headers.authorization ?? '',
  );
  requireThat(match?.[1], 'UNAUTHORIZED', 401);
  return match[1];
};

export async function createApp(
  framework: Framework | AsyncFramework,
  options: {
    adminToken: string;
    logger?: boolean;
    rateLimitMax?: number;
    trustedProxyCidrs?: string;
    sharedRateLimiter?: PostgresRateLimiter;
    signingCoordinator?: PostgresSigningCoordinator;
  },
) {
  requireThat(
    options.adminToken.length >= 32 &&
      !options.adminToken.startsWith('replace-'),
    'INVALID_ADMIN_TOKEN',
  );
  const app = Fastify({
    logger: options.logger
      ? { redact: ['req.headers.authorization', 'req.headers.cookie'] }
      : false,
    bodyLimit: 16 * 1024,
    trustProxy: trustedProxies(options.trustedProxyCidrs),
    requestTimeout: 15_000,
  });
  await app.register(rateLimit, {
    global: true,
    max: options.rateLimitMax ?? 120,
    timeWindow: '1 minute',
    skipOnError: false,
    ...(options.sharedRateLimiter
      ? { store: options.sharedRateLimiter.fastifyStore() }
      : {}),
  });
  app.addHook('onRequest', async (request, reply) => {
    reply.header('Cache-Control', 'no-store');
    reply.header('X-Content-Type-Options', 'nosniff');
    reply.header('Referrer-Policy', 'no-referrer');
    // Headless bearer-token API. Browser portals should use their own same-origin BFF.
    requireThat(!request.headers.origin, 'BROWSER_ORIGIN_NOT_ALLOWED', 403);
  });
  app.setErrorHandler(
    (error: Error & { statusCode?: number }, request, reply) => {
      if (error instanceof StorageError) {
        const uncertain = [
          'TRANSACTION_COMMIT_UNCERTAIN',
          'POSTGRES_RESULT_UNCERTAIN',
        ].includes(error.code);
        if (error.retryable) reply.header('Retry-After', '1');
        return reply.code(503).send({
          error: uncertain ? error.code : 'STORAGE_UNAVAILABLE',
          retryable: error.retryable,
          requestId: request.id,
        });
      }
      if (error instanceof DomainError)
        return reply.code(error.status).send({ error: error.code });
      if (error instanceof z.ZodError)
        return reply.code(400).send({
          error: 'INVALID_REQUEST',
          fields: error.issues.map((i) => i.path.join('.')),
        });
      if (
        error.statusCode &&
        error.statusCode >= 400 &&
        error.statusCode < 500
      ) {
        return reply.code(error.statusCode).send({
          error: error.statusCode === 429 ? 'RATE_LIMITED' : 'INVALID_REQUEST',
        });
      }
      request.log.error(
        { requestId: request.id, errorType: error.name },
        'Request failed',
      );
      return reply
        .code(500)
        .send({ error: 'INTERNAL_ERROR', requestId: request.id });
    },
  );
  const user = async (request: FastifyRequest) =>
    await framework.authenticate(bearer(request));
  const admin = (request: FastifyRequest) =>
    requireThat(
      secretEqual(bearer(request), options.adminToken),
      'ADMIN_REQUIRED',
      403,
    );
  const commandKey = (request: FastifyRequest) =>
    keySchema.parse(request.headers['idempotency-key']);
  const authRate = {
    config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
  };

  app.get('/health', async () => ({
    status: 'ok',
    framework: 'product-license-kit',
    version: '0.5.0',
  }));
  app.get('/v1/catalog', async () => framework.catalog);
  app.get('/v1/signing-key', async () => ({
    ...('currentSigningKey' in framework
      ? await framework.currentSigningKey()
      : { kid: framework.signer.kid, publicKey: framework.signer.publicKey }),
    issuer: framework.issuer,
  }));
  app.post('/v1/auth/register', authRate, async (request) => {
    const body = z
      .object({ ticket: proof, proof })
      .strict()
      .parse(request.body);
    return await framework.register(body.ticket, body.proof);
  });
  app.post('/v1/auth/login', authRate, async (request) => {
    const body = z.object({ provider: id, proof }).strict().parse(request.body);
    return await framework.login(body.provider, body.proof);
  });
  app.post('/v1/auth/logout', async (request) => {
    await user(request);
    await framework.logout(bearer(request));
    return { ok: true };
  });
  app.get(
    '/v1/me',
    async (request) => await framework.profile(await user(request)),
  );
  app.get('/v1/orders', async (request) => {
    const accountId = await user(request);
    return Object.keys(request.query as object).length
      ? await framework.ordersPage(accountId, request.query)
      : await framework.orders(accountId);
  });
  app.post('/v1/orders', async (request) => {
    const accountId = await user(request);
    const body = z.object({ offerId: id }).strict().parse(request.body);
    return await framework.createOrder(
      accountId,
      body.offerId,
      commandKey(request),
    );
  });
  app.post('/v1/orders/:id/cancel', async (request) => {
    await framework.cancelOrder(await user(request), paramsId(request));
    return { ok: true };
  });
  app.get('/v1/devices/:groupId/reset', async (request) => {
    const { groupId } = z.object({ groupId: id }).parse(request.params);
    return await framework.deviceResetStatus(await user(request), groupId);
  });
  app.post('/v1/devices/:groupId/reset', async (request) => {
    const { groupId } = z.object({ groupId: id }).parse(request.params);
    const body = z
      .object({
        generation: z.number().int().positive(),
        cost: z.enum(['free', 'credit']),
        confirm: z.literal(true),
      })
      .strict()
      .parse(request.body);
    return await framework.resetDevice(
      await user(request),
      groupId,
      body.generation,
      body.cost,
      commandKey(request),
    );
  });
  app.post('/v1/devices/challenges', async (request) => {
    const accountId = await user(request);
    const body = z
      .object({
        groupId: id,
        publicKey: z.string().min(32).max(2048),
        fingerprint: z
          .object({ schema: id, digest: z.string().regex(/^[a-f0-9]{64}$/) })
          .strict(),
      })
      .strict()
      .parse(request.body);
    return await framework.enrollmentChallenge(
      accountId,
      body.groupId,
      body.publicKey,
      body.fingerprint,
    );
  });
  app.post('/v1/devices/activate', async (request) => {
    const accountId = await user(request);
    const body = z
      .object({ challengeId: uuid, signature })
      .strict()
      .parse(request.body);
    return await framework.activate(
      accountId,
      body.challengeId,
      body.signature,
      commandKey(request),
    );
  });
  app.post('/v1/licenses/challenges', async (request) => {
    const body = z
      .object({
        deviceId: uuid,
        editionId: id,
        channel: z.enum(['stable', 'beta']).default('stable'),
      })
      .strict()
      .parse(request.body);
    return await framework.licenseChallenge(
      body.deviceId,
      body.editionId,
      body.channel,
    );
  });
  app.post('/v1/licenses/issue', async (request) => {
    const body = z
      .object({ challengeId: uuid, signature })
      .strict()
      .parse(request.body);
    return await framework.issueLicense(body.challengeId, body.signature);
  });
  app.get('/v1/distributions', async (request) => {
    const accountId = await user(request);
    return Object.keys(request.query as object).length
      ? await framework.distributionsPage(accountId, request.query)
      : await framework.distributions(accountId);
  });

  app.register(
    async (protectedApp) => {
      protectedApp.addHook('preHandler', async (request) => {
        admin(request);
      });
      if (options.signingCoordinator) {
        const signing = options.signingCoordinator;
        protectedApp.get('/signing', async () => ({
          plan: (await signing.status()) ?? null,
        }));
        protectedApp.get('/signing/rotations/:id', async (request) => {
          const plan = await signing.status(paramsId(request));
          requireThat(plan, 'SIGNING_PLAN_NOT_FOUND', 404);
          return plan;
        });
        protectedApp.post('/signing/policy', async (request) =>
          signing.initialize(
            z
              .object({
                activeKid: z.string().regex(/^[a-f0-9]{24}$/),
                requiredNodes: z.array(z.string()).min(1).max(100),
                actor: z.string().max(128),
                reason,
              })
              .strict()
              .parse(request.body),
          ),
        );
        protectedApp.post('/signing/rotations', async (request) =>
          signing.schedule(
            z
              .object({
                publicKey: z.string().max(256),
                notBefore: z.number().int().safe(),
                expiresAt: z.number().int().safe(),
                actor: z.string().max(128),
                reason,
                clientsReady: z.literal(true),
              })
              .strict()
              .parse(request.body),
          ),
        );
        protectedApp.post('/signing/rotations/:id/pause', async (request) =>
          signing.pause(
            paramsId(request),
            z
              .object({
                actor: z.string().max(128),
                reason,
                revision: z.number().int().nonnegative().safe(),
              })
              .strict()
              .parse(request.body),
          ),
        );
        protectedApp.post('/signing/restore-review', async (request) =>
          signing.pauseRestored(
            z
              .object({ actor: z.string().max(128), reason })
              .strict()
              .parse(request.body),
          ),
        );
      }
      protectedApp.post('/invitations', async (request) => {
        const body = z
          .object({ provider: id, subject })
          .strict()
          .parse(request.body);
        return await framework.issueInvitation(body.provider, body.subject);
      });
      protectedApp.get(
        '/accounts/:id',
        async (request) => await framework.profile(paramsId(request)),
      );
      protectedApp.post('/accounts/:id/status', async (request) => {
        const body = z
          .object({ active: z.boolean(), reason })
          .strict()
          .parse(request.body);
        await framework.setAccountActive(
          paramsId(request),
          body.active,
          body.reason,
        );
        return { ok: true };
      });
      protectedApp.post('/accounts/:id/identity', async (request) => {
        const body = z
          .object({ provider: id, subject, reason })
          .strict()
          .parse(request.body);
        await framework.changeIdentity(
          paramsId(request),
          body.provider,
          body.subject,
          body.reason,
        );
        return { ok: true };
      });
      protectedApp.post('/accounts/:id/credits', async (request) => {
        const body = z
          .object({
            groupId: id,
            count: z.number().int().min(1).max(100),
            reason,
          })
          .strict()
          .parse(request.body);
        return await framework.grantCredits(
          paramsId(request),
          body.groupId,
          body.count,
          body.reason,
          commandKey(request),
        );
      });
      protectedApp.post('/accounts/:id/revoke', async (request) => {
        const body = z
          .object({ editionId: id, reason })
          .strict()
          .parse(request.body);
        await framework.revokeEntitlement(
          paramsId(request),
          body.editionId,
          body.reason,
        );
        return { ok: true };
      });
      protectedApp.post('/orders/:id/confirm', async (request) => {
        const body = z
          .object({
            method: z.enum(['manual-wechat', 'manual-alipay', 'manual-bank']),
            reference: z.string().min(3).max(128),
            amount: z.number().int().positive(),
            currency: z.string().regex(/^[A-Z]{3}$/),
            latePaymentReason: z.string().trim().min(3).max(500).optional(),
          })
          .strict()
          .parse(request.body);
        return await framework.confirmPayment(
          paramsId(request),
          body,
          body.latePaymentReason
            ? { latePaymentReason: body.latePaymentReason }
            : undefined,
        );
      });
      protectedApp.get(
        '/payment-exceptions',
        async () => await framework.paymentExceptions(),
      );
      protectedApp.post('/payment-exceptions', async (request) => {
        const body = z
          .object({
            orderId: uuid,
            method: z.enum(['manual-wechat', 'manual-alipay', 'manual-bank']),
            reference: z.string().trim().min(3).max(128),
            amount: z.number().int().positive(),
            currency: z.string().regex(/^[A-Z]{3}$/),
            reason,
          })
          .strict()
          .parse(request.body);
        return await framework.recordPaymentException(
          body.orderId,
          body,
          body.reason,
        );
      });
      protectedApp.post('/payment-exceptions/:id/resolve', async (request) => {
        const body = z
          .discriminatedUnion('action', [
            z
              .object({ action: z.literal('apply'), orderId: uuid, reason })
              .strict(),
            z
              .object({
                action: z.literal('refund'),
                refundReference: z.string().trim().min(3).max(128),
                reason,
              })
              .strict(),
          ])
          .parse(request.body);
        return await framework.resolvePaymentException(paramsId(request), body);
      });
      protectedApp.post('/distributions', async (request) => {
        const body = z
          .object({ accountId: uuid, editionId: id, releaseId: id })
          .strict()
          .parse(request.body);
        return await framework.reserveDistribution(
          body.accountId,
          body.editionId,
          body.releaseId,
          commandKey(request),
        );
      });
      protectedApp.post('/distributions/:id/finalize', async (request) => {
        const body = z
          .object({ sha256: z.string().regex(/^[a-f0-9]{64}$/) })
          .strict()
          .parse(request.body);
        return await framework.finalizeDistribution(
          paramsId(request),
          body.sha256,
        );
      });
      protectedApp.get(
        '/distributions/:id',
        async (request) => await framework.traceDistribution(paramsId(request)),
      );
      protectedApp.get('/audit', async (request) =>
        Object.keys(request.query as object).length
          ? await framework.auditPage(request.query)
          : await framework.auditLog(),
      );
    },
    { prefix: '/v1/admin' },
  );
  return app;
}
