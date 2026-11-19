// Standalone browser deployment. The machine administrator bearer token is not read or exposed.
import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';
import {
  AsyncFramework,
  PostgresStore,
  PostgresPortal,
  EnvelopeSigner,
  KookIdentityProvider,
  KookOAuthClient,
  createPortalApp,
  parseCatalog,
  protectPrivatePath,
  portalPermissions,
  KookBotClient,
  PostgresKookBot,
  createKookBotApp,
} from '../dist/index.js';
import { createHash } from 'node:crypto';

let store,
  app,
  timer,
  sweep = Promise.resolve(),
  sweeping = false,
  stopping = false;
let botApp,
  botTimer,
  botWork = Promise.resolve(),
  botWorking = false;
async function stop() {
  if (stopping) return;
  stopping = true;
  clearInterval(timer);
  clearInterval(botTimer);
  await botApp?.close();
  await botWork;
  await sweep;
  await app?.close();
  await store?.close();
  if (process.connected) process.disconnect();
}
try {
  const configFile = resolve(
    z.string().min(1).parse(process.env.PLK_PORTAL_CONFIG_FILE),
  );
  protectPrivatePath(configFile);
  const config = z
    .object({
      connectionString: z.string().min(1),
      schema: z.string().default('plk'),
      caFile: z.string().optional(),
      migrate: z.boolean().default(false),
      host: z.string().default('127.0.0.1'),
      port: z.number().int().min(1).max(65535).default(3200),
      origin: z.string().min(1),
      issuer: z.string().min(1).max(128),
      namespace: z.string().min(1).max(80),
      catalogPath: z.string(),
      keyFiles: z.array(z.string()).min(1).max(31),
      signingContextHash: z
        .string()
        .regex(/^[a-f0-9]{64}$/)
        .optional(),
      portalKeyFile: z.string(),
      kookClientId: z.string().min(1),
      kookSecretFile: z.string(),
      trustedProxyCidrs: z.string().default(''),
      bootstrapOwner: z
        .object({ accountId: z.string().uuid(), reason: z.string().min(3) })
        .strict()
        .optional(),
      kookBot: z
        .object({
          namespace: z.string().regex(/^[A-Za-z0-9._-]{1,80}$/),
          botId: z.string().regex(/^[0-9]{1,32}$/),
          tokenFile: z.string(),
          verifyTokenFile: z.string(),
          encryptionKeyFile: z.string().optional(),
          compressed: z.boolean().default(true),
          guildId: z.string().regex(/^[0-9]{1,32}$/),
          anyRoleIds: z
            .array(z.number().int().nonnegative().safe())
            .min(1)
            .max(100),
          admissionVersion: z.string().min(1).max(128),
          host: z.string().default('127.0.0.1'),
          port: z.number().int().min(1).max(65535).default(3201),
          workerEnabled: z.boolean().default(false),
          sendEnabled: z.boolean().default(false),
          notificationsEnabled: z.boolean().default(false),
        })
        .strict()
        .optional(),
    })
    .strict()
    .parse(JSON.parse(readFileSync(configFile, 'utf8')));
  const path = (value) => resolve(dirname(configFile), value),
    privateFile = (value) => {
      const file = path(value);
      protectPrivatePath(file);
      return readFileSync(file);
    };
  store = await PostgresStore.connect({
    connectionString: config.connectionString,
    schema: config.schema,
    migrate: config.migrate,
    ...(config.caFile ? { ca: readFileSync(path(config.caFile), 'utf8') } : {}),
  });
  const keys = config.keyFiles.map(
      (file) => new EnvelopeSigner(privateFile(file).toString('utf8')),
    ),
    framework = await AsyncFramework.create({
      store,
      issuer: config.issuer,
      catalog: parseCatalog(
        JSON.parse(readFileSync(path(config.catalogPath), 'utf8')),
      ),
      signer: keys[0],
      additionalSigningKeys: keys.slice(1),
      providers: [new KookIdentityProvider()],
      ...(config.signingContextHash
        ? { signingContextHash: config.signingContextHash }
        : {}),
    });
  const botConfig = config.kookBot,
    botToken = botConfig
      ? privateFile(botConfig.tokenFile).toString('utf8').trimEnd()
      : undefined,
    botApi = botConfig ? new KookBotClient(botToken) : undefined,
    admission = botConfig
      ? async (identity) =>
          identity.provider === 'kook' &&
          (await botApi.admitted(
            identity.subject,
            botConfig.guildId,
            botConfig.anyRoleIds,
          ))
      : undefined;
  const origin = new URL(config.origin).origin,
    portal = await PostgresPortal.create(framework, store, {
      namespace: config.namespace,
      origin: config.origin,
      encryptionKey: privateFile(config.portalKeyFile),
      provider: 'kook',
      authorizationOrigin: 'https://www.kookapp.cn',
      oauth: new KookOAuthClient(
        config.kookClientId,
        privateFile(config.kookSecretFile).toString('utf8').trimEnd(),
        origin + '/auth/callback',
      ),
      ...(admission ? { registrationAdmission: admission } : {}),
    });
  if (botConfig) {
    const bot = await PostgresKookBot.create(framework, store, portal, {
      namespace: botConfig.namespace,
      botId: botConfig.botId,
      api: botApi,
      admission,
      admissionVersion: botConfig.admissionVersion,
      credentialHash: createHash('sha256').update(botToken).digest('hex'),
      webhook: {
        verifyToken: privateFile(botConfig.verifyTokenFile)
          .toString('utf8')
          .trimEnd(),
        compressed: botConfig.compressed,
        ...(botConfig.encryptionKeyFile
          ? {
              encryptionKey: privateFile(botConfig.encryptionKeyFile)
                .toString('utf8')
                .trimEnd(),
            }
          : {}),
      },
      sendEnabled: botConfig.sendEnabled,
      notificationsEnabled: botConfig.notificationsEnabled,
    });
    if (botConfig.workerEnabled) await bot.verifyBotIdentity();
    botApp = createKookBotApp(bot);
    await botApp.listen({ host: botConfig.host, port: botConfig.port });
    if (botConfig.workerEnabled) {
      botTimer = setInterval(() => {
        if (stopping || botWorking) return;
        botWorking = true;
        botWork = (async () => {
          await bot.runInbox(2);
          if (botConfig.sendEnabled) await bot.runDeliveries(2);
          if (botConfig.sendEnabled && botConfig.notificationsEnabled)
            await bot.runNotifications(2);
        })()
          .catch(() => console.error('KOOK_BOT_WORKER_FAILED'))
          .finally(() => {
            botWorking = false;
          });
      }, 1000);
      botTimer.unref();
    }
  }
  if (config.bootstrapOwner)
    await portal.bootstrapOperator(
      config.bootstrapOwner.accountId,
      portalPermissions,
      config.bootstrapOwner.reason,
    );
  app = await createPortalApp(portal, {
    logger: true,
    trustedProxyCidrs: config.trustedProxyCidrs,
  });
  process.on('SIGINT', () => {
    void stop();
  });
  process.on('SIGTERM', () => {
    void stop();
  });
  process.on('message', (message) => {
    if (message === 'stop') void stop();
  });
  await app.listen({ host: config.host, port: config.port });
  timer = setInterval(() => {
    if (stopping || sweeping) return;
    sweeping = true;
    sweep = (async () => {
      await portal.cleanup();
      await framework.cleanupExpired();
    })()
      .catch(() => {
        console.error('PORTAL_CLEANUP_FAILED');
      })
      .finally(() => {
        sweeping = false;
      });
  }, 60000);
  timer.unref();
  if (process.send) process.send({ type: 'ready', pid: process.pid });
} catch {
  console.error('PORTAL_STARTUP_FAILED');
  process.exitCode = 1;
  await stop();
}
