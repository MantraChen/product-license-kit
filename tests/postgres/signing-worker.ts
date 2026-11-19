import { readFileSync } from 'node:fs';
import { PostgresStore } from '../../src/adapters/postgres.js';
import { PostgresSigningCoordinator } from '../../src/adapters/postgres-signing.js';
import { postgresSigningBackup } from '../../src/security/postgres-backup.js';
import { EnvelopeSigner } from '../../src/core/crypto.js';
import { DomainError } from '../../src/core/model.js';
if (process.env.PLK_TEST_POSTGRES_SCOPED !== '1')
  throw new Error('SCOPED_TEST_REQUIRED');
const input = JSON.parse(
  readFileSync(process.env.PLK_SIGNING_TEST_CONFIG!, 'utf8'),
);
const store = await PostgresStore.connect({
  connectionString: process.env.PLK_TEST_POSTGRES_URL!,
  schema: input.schema,
});
try {
  const coordinator = new PostgresSigningCoordinator(store, {
    namespace: input.namespace,
    contextHash: input.contextHash,
    primary: new EnvelopeSigner(input.current),
    additionalKeys: [new EnvelopeSigner(input.next)],
    nodeId: process.env.PLK_SIGNING_TEST_NODE!,
    enabled: true,
    createBackup: postgresSigningBackup(store, {
      directory: input.directory,
      password: input.password,
      privateKeys: [input.current, input.next],
    }),
  });
  try {
    await coordinator.acknowledge(input.planId);
  } catch (error) {
    if (
      !(error instanceof DomainError) ||
      error.code !== 'SIGNING_PLAN_NOT_ACTIVE'
    )
      throw error;
  }
  const plan = await coordinator.tick();
  console.log(JSON.stringify({ pid: process.pid, status: plan?.status }));
} finally {
  await store.close();
}
