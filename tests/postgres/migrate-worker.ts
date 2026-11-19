import { PostgresStore } from '../../src/adapters/postgres.js';

const connectionString = process.env.PLK_TEST_POSTGRES_URL, schema = process.env.PLK_POSTGRES_TEST_SCHEMA;
if (process.env.PLK_TEST_POSTGRES_SCOPED !== '1' || !connectionString || !schema || !/^plk_test_[a-f0-9]{32}$/.test(schema))
  throw new Error('SCOPED_POSTGRES_FIXTURE_REQUIRED');
const store = await PostgresStore.connect({ connectionString, schema });
try {
  const row = await store.get<{ n: number }>('SELECT count(*) AS n FROM plk_pg_migrations');
  console.log(JSON.stringify({ pid: process.pid, migrations: row?.n }));
} finally { await store.close(); }
