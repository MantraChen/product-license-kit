import { existsSync, mkdirSync, writeFileSync } from 'node:fs';
import { generateKeyPairSync } from 'node:crypto';
import { randomToken } from '../core/crypto.js';
import { requireThat } from '../core/model.js';

requireThat(!existsSync('.env') && !existsSync('.data/signing.pem') && !existsSync('.data/local-identities.json'), 'LOCAL_CONFIG_ALREADY_EXISTS');
mkdirSync('.data', { recursive: true });
const keys = generateKeyPairSync('ed25519');
writeFileSync('.data/signing.pem', keys.privateKey.export({ type: 'pkcs8', format: 'pem' }), { flag: 'wx', mode: 0o600 });
writeFileSync('.data/signing-public.pem', keys.publicKey.export({ type: 'spki', format: 'pem' }), { flag: 'wx' });
writeFileSync('.data/local-identities.json', JSON.stringify([{ subject: 'demo-user', proof: randomToken() }], null, 2), { flag: 'wx', mode: 0o600 });
writeFileSync('.env', [
  'HOST=127.0.0.1', 'PORT=3100', 'DATABASE_PATH=.data/framework.sqlite',
  'SIGNING_KEY_PATH=.data/signing.pem', `ADMIN_TOKEN=${randomToken()}`, 'LICENSE_ISSUER=product-license-kit',
  'CATALOG_PATH=examples/catalog.json', 'ENABLE_KOOK=false', 'TOKEN_IDENTITY_PATH=.data/local-identities.json',
  'NODE_ENV=development', '',
].join('\n'), { flag: 'wx', mode: 0o600 });
console.log('Local configuration created. Secrets are in .env and .data (Git ignored). Start with pnpm start.');
console.log('Run pnpm demo for an isolated, synthetic purchase-to-license walkthrough.');
