import { readFileSync } from 'node:fs';
import { dirname, resolve } from 'node:path';
import { z } from 'zod';
import {
  PostgresStore,
  inspectSqliteMigration,
  migrateSqliteToPostgres,
  reviewSqliteCutover,
  parseCatalog,
  protectPrivatePath,
} from '../dist/index.js';

// This operator tool has no production defaults and never imports files or credentials from .env.
let store;
try {
  const configFile = resolve(
    z.string().min(1).parse(process.env.PLK_SQLITE_MIGRATION_CONFIG_FILE),
  );
  protectPrivatePath(configFile);
  const config = z
    .object({
      database: z.string().min(1),
      issuer: z.string().min(1),
      catalogFile: z.string().min(1),
      signingKeyFile: z.string().min(1),
      historicalPublicKeyFiles: z.array(z.string().min(1)).max(31).default([]),
      backupDirectory: z.string().min(1),
      backupPasswordFile: z.string().min(1),
      actor: z.string().min(1),
      reason: z.string().min(3),
      postgres: z
        .object({
          connectionString: z.string().min(1),
          schema: z.string().min(1),
          caFile: z.string().min(1).optional(),
        })
        .strict(),
    })
    .strict()
    .parse(JSON.parse(readFileSync(configFile, 'utf8')));
  const path = (value) => resolve(dirname(configFile), value);
  const secret = (value) => {
    const file = path(value);
    protectPrivatePath(file);
    return readFileSync(file, 'utf8');
  };
  const options = {
    database: path(config.database),
    issuer: config.issuer,
    catalog: parseCatalog(
      JSON.parse(readFileSync(path(config.catalogFile), 'utf8')),
    ),
    privateKey: secret(config.signingKeyFile),
    historicalPublicKeys: config.historicalPublicKeyFiles.map((file) =>
      readFileSync(path(file), 'utf8'),
    ),
  };
  const [mode, expectedPlanHash, ...extra] = process.argv.slice(2);
  if (
    extra.length ||
    !['--review', '--apply', '--status'].includes(mode) ||
    (mode !== '--apply' && expectedPlanHash) ||
    (mode === '--apply' && !/^[a-f0-9]{64}$/.test(expectedPlanHash ?? ''))
  )
    throw new Error('MIGRATION_ARGUMENTS_INVALID');
  if (mode === '--review')
    console.log(JSON.stringify(inspectSqliteMigration(options), null, 2));
  else {
    store = await PostgresStore.connect({
      connectionString: config.postgres.connectionString,
      schema: config.postgres.schema,
      ...(config.postgres.caFile
        ? { ca: readFileSync(path(config.postgres.caFile), 'utf8') }
        : {}),
      maintenance: true,
      migrate: false,
      transactionTimeoutMs: 120000,
    });
    const result =
      mode === '--status'
        ? await reviewSqliteCutover(store, options)
        : await migrateSqliteToPostgres(store, {
            ...options,
            expectedPlanHash,
            actor: config.actor,
            reason: config.reason,
            backupDirectory: path(config.backupDirectory),
            backupPassword: secret(config.backupPasswordFile).trimEnd(),
          });
    console.log(JSON.stringify(result, null, 2));
  }
} catch (error) {
  // SQL text, connection URLs, private configuration and validation inputs never enter diagnostics.
  console.error(
    JSON.stringify({
      error:
        typeof error?.code === 'string' &&
        /^[A-Z][A-Z0-9_]{2,79}$/.test(error.code)
          ? error.code
          : 'SQLITE_POSTGRES_MIGRATION_FAILED',
    }),
  );
  process.exitCode = 1;
} finally {
  await store?.close();
}
