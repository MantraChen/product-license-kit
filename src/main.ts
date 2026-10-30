import { readFileSync } from 'node:fs';
import { dirname, resolve, join } from 'node:path';
import { z } from 'zod';
import { SqliteStore } from './adapters/sqlite.js';
import { KookIdentityProvider } from './adapters/kook.js';
import { LocalIdentityProvider } from './adapters/local-identity.js';
import { EnvelopeSigner } from './core/crypto.js';
import { parseCatalog, requireThat, type IdentityProvider } from './core/model.js';
import { Framework } from './service.js';
import { createApp } from './http/app.js';
import { privateDirectory, protectPrivatePath } from './security/private-storage.js';
import { acquireServiceLock } from './security/process-lock.js';

const env = z.object({
  HOST: z.string().default('127.0.0.1'), PORT: z.coerce.number().int().min(1).max(65535).default(3100),
  DATABASE_PATH: z.string().default('.data/framework.sqlite'), SIGNING_KEY_PATH: z.string().min(1),
  ADMIN_TOKEN: z.string().min(32), LICENSE_ISSUER: z.string().min(1).default('product-license-kit'),
  CATALOG_PATH: z.string().default('examples/catalog.json'), ENABLE_KOOK: z.enum(['true', 'false']).default('false'),
  TOKEN_IDENTITY_PATH: z.string().optional(), NODE_ENV: z.enum(['development', 'production', 'test']).default('development'),
  TRUSTED_PROXY_CIDRS: z.string().default(''),
}).parse(process.env);
const providers: IdentityProvider[] = [];
if (env.ENABLE_KOOK === 'true') providers.push(new KookIdentityProvider());
if (env.TOKEN_IDENTITY_PATH) {
  requireThat(env.NODE_ENV !== 'production', 'LOCAL_IDENTITY_FORBIDDEN_IN_PRODUCTION');
  const identities = z.array(z.object({ subject: z.string().min(1).max(128), proof: z.string().min(32) }).strict())
    .parse(JSON.parse(readFileSync(env.TOKEN_IDENTITY_PATH, 'utf8')));
  providers.push(new LocalIdentityProvider(identities));
}
requireThat(providers.length > 0, 'CONFIGURE_AN_IDENTITY_PROVIDER');
const database = resolve(env.DATABASE_PATH); privateDirectory(dirname(database));
protectPrivatePath(resolve(env.SIGNING_KEY_PATH));
const releaseLock = acquireServiceLock(join(dirname(database), 'framework.lock'));
const store = new SqliteStore(database);
const framework = new Framework({ store, providers, issuer: env.LICENSE_ISSUER,
  signer: new EnvelopeSigner(readFileSync(env.SIGNING_KEY_PATH, 'utf8')),
  catalog: parseCatalog(JSON.parse(readFileSync(env.CATALOG_PATH, 'utf8'))),
});
const app = await createApp(framework, { adminToken: env.ADMIN_TOKEN, logger: true, trustedProxyCidrs: env.TRUSTED_PROXY_CIDRS });
const cleanup = setInterval(() => framework.cleanupExpired(), 60_000); cleanup.unref();
let stopping = false;
async function stop() {
  if (stopping) return; stopping = true;
  clearInterval(cleanup); await app.close(); store.close(); releaseLock();
}
process.on('SIGINT', () => { void stop(); }); process.on('SIGTERM', () => { void stop(); });
try { await app.listen({ host: env.HOST, port: env.PORT }); }
catch (error) { await stop(); throw error; }
