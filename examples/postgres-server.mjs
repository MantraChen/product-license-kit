// Explicit PostgreSQL deployment entry point. Configuration and private keys stay outside the source tree.
import { readFileSync } from 'node:fs';
import { resolve, dirname } from 'node:path';
import { z } from 'zod';
import {
  PostgresStore,
  AsyncFramework,
  EnvelopeSigner,
  PostgresSigningCoordinator,
  PostgresRateLimiter,
  sha256,
  postgresSigningBackup,
  createApp,
  parseCatalog,
  KookIdentityProvider,
  protectPrivatePath,
} from '../dist/index.js';
import { LocalIdentityProvider } from '../dist/adapters/local-identity.js';
const configPath = resolve(process.env.PLK_POSTGRES_CONFIG_FILE ?? '');
if (!process.env.PLK_POSTGRES_CONFIG_FILE)
  throw new Error('PLK_POSTGRES_CONFIG_FILE_REQUIRED');
protectPrivatePath(configPath);
const config = z
  .object({
    connectionString: z.string().min(1),
    schema: z.string().default('plk'),
    caFile: z.string().optional(),
    migrate: z.boolean().default(false),
    host: z.string().default('127.0.0.1'),
    port: z.number().int().min(1).max(65535).default(3100),
    nodeEnv: z.enum(['production', 'development']).default('production'),
    issuer: z.string().min(1).max(128),
    nodeId: z.string().min(1).max(64),
    contextHash: z.string().regex(/^[a-f0-9]{64}$/),
    adminToken: z.string().min(32),
    rateLimitSecretFile: z.string(),
    catalogPath: z.string(),
    keyFiles: z.array(z.string()).min(1).max(31),
    enableKook: z.boolean().default(false),
    localIdentityPath: z.string().optional(),
    trustedProxyCidrs: z.string().default(''),
    rotationEnabled: z.boolean().default(false),
    backup: z
      .object({
        directory: z.string(),
        passwordFile: z.string(),
        portalKeys: z
          .array(
            z.object({ namespace: z.string(), keyFile: z.string() }).strict(),
          )
          .max(30)
          .default([]),
      })
      .strict()
      .optional(),
  })
  .strict()
  .parse(JSON.parse(readFileSync(configPath, 'utf8')));
const base = dirname(configPath),
  path = (value) => resolve(base, value),
  readPrivate = (value) => {
    const file = path(value);
    protectPrivatePath(file);
    return readFileSync(file, 'utf8');
  };
const material = config.keyFiles.map(readPrivate),
  signers = material.map((pem) => new EnvelopeSigner(pem)),
  providers = [];
if (config.enableKook) providers.push(new KookIdentityProvider());
if (config.localIdentityPath) {
  if (config.nodeEnv === 'production')
    throw new Error('LOCAL_IDENTITY_FORBIDDEN_IN_PRODUCTION');
  providers.push(
    new LocalIdentityProvider(
      z
        .array(
          z.object({ subject: z.string(), proof: z.string().min(32) }).strict(),
        )
        .parse(JSON.parse(readPrivate(config.localIdentityPath))),
    ),
  );
}
if (!providers.length) throw new Error('CONFIGURE_AN_IDENTITY_PROVIDER');
if (config.rotationEnabled && !config.backup)
  throw new Error('SIGNING_BACKUP_REQUIRED');
const store = await PostgresStore.connect({
  connectionString: config.connectionString,
  schema: config.schema,
  migrate: config.migrate,
  ...(config.caFile ? { ca: readFileSync(path(config.caFile), 'utf8') } : {}),
});
let app,
  worker,
  stopping = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  await worker?.stop();
  await app?.close();
  await store.close();
  if (process.connected) process.disconnect();
}
try {
  const framework = await AsyncFramework.create({
    store,
    signer: signers[0],
    additionalSigningKeys: signers.slice(1),
    signingContextHash: config.contextHash,
    issuer: config.issuer,
    providers,
    catalog: parseCatalog(
      JSON.parse(readFileSync(path(config.catalogPath), 'utf8')),
    ),
  });
  const coordinator = new PostgresSigningCoordinator(store, {
    namespace: config.issuer,
    contextHash: config.contextHash,
    primary: signers[0],
    additionalKeys: signers.slice(1),
    nodeId: config.nodeId,
    enabled: config.rotationEnabled,
    ...(config.backup
      ? {
          createBackup: postgresSigningBackup(store, {
            directory: path(config.backup.directory),
            password: readPrivate(config.backup.passwordFile).trim(),
            privateKeys: material,
            portalKeys: config.backup.portalKeys.map((item) => {
              const file = path(item.keyFile);
              protectPrivatePath(file);
              return { namespace: item.namespace, key: readFileSync(file) };
            }),
          }),
        }
      : {}),
  });
  app = await createApp(framework, {
    adminToken: config.adminToken,
    sharedRateLimiter: new PostgresRateLimiter(store, {
      namespace: 'api.' + sha256(config.issuer).slice(0, 32),
      secret: readPrivate(config.rateLimitSecretFile).trim(),
    }),
    trustedProxyCidrs: config.trustedProxyCidrs,
    signingCoordinator: coordinator,
  });
  await app.listen({ host: config.host, port: config.port });
  worker = coordinator.start({
    onError: (code) => process.stderr.write(code + '\n'),
  });
  process.on('SIGINT', () => void stop());
  process.on('SIGTERM', () => void stop());
  process.on('message', (message) => {
    if (message?.type === 'shutdown') void stop();
  });
  console.log(
    JSON.stringify({
      listening: true,
      port: config.port,
      nodeId: config.nodeId,
      rotationEnabled: config.rotationEnabled,
    }),
  );
} catch {
  await stop();
  throw new Error('POSTGRES_SERVER_START_FAILED');
}
