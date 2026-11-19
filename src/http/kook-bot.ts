import Fastify from 'fastify';
import { DomainError } from '../core/model.js';
import { StorageError } from '../core/async-store.js';
import type { PostgresKookBot } from '../adapters/postgres-kook-bot.js';

/** Mount separately from the browser portal. Deployments must bound network concurrency at their reverse proxy. */
export function createKookBotApp(bot: PostgresKookBot) {
  const app = Fastify({
    bodyLimit: 1048576,
    requestTimeout: 10000,
    logger: false,
  });
  app.removeAllContentTypeParsers();
  app.addContentTypeParser('*', { parseAs: 'buffer' }, (_request, body, done) =>
    done(null, body),
  );
  app.addHook('onSend', async (_request, reply, payload) => {
    reply
      .header('Cache-Control', 'no-store')
      .header('X-Content-Type-Options', 'nosniff');
    return payload;
  });
  app.setErrorHandler(
    (error: Error & { statusCode?: number }, _request, reply) => {
      if (error instanceof DomainError)
        return reply.code(error.status).send({ error: error.code });
      if (error instanceof StorageError)
        return reply.code(503).send({ error: 'STORAGE_UNAVAILABLE' });
      return reply.code(error.statusCode === 413 ? 413 : 500).send({
        error: error.statusCode === 413 ? 'BODY_TOO_LARGE' : 'INTERNAL_ERROR',
      });
    },
  );
  app.get('/health', async () => ({ ok: true }));
  app.post('/webhook', async (request) => {
    const result = await bot.acceptWebhook(request.body as Buffer);
    return 'challenge' in result ? { challenge: result.challenge } : {};
  });
  return app;
}
