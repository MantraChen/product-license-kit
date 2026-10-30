import { generateKeyPairSync } from 'node:crypto';
import { existsSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { EnvelopeSigner } from '../core/crypto.js';
import { writePrivateAtomic } from './private-storage.js';

/** Caller must stop issuance and take an encrypted backup before invoking. */
export function rotateSigningKey(dataDir: string): { previousKid: string; kid: string } {
  const path = join(dataDir, 'signing.pem');
  const previous = new EnvelopeSigner(readFileSync(path, 'utf8'));
  const pair = generateKeyPairSync('ed25519');
  const pem = pair.privateKey.export({ type: 'pkcs8', format: 'pem' }).toString();
  const current = new EnvelopeSigner(pem);
  const historyPath = join(dataDir, 'signing-public-history.json');
  const history = existsSync(historyPath) ? JSON.parse(readFileSync(historyPath, 'utf8')) as Record<string, string> : {};
  history[previous.kid] = previous.publicKey;
  writePrivateAtomic(historyPath, JSON.stringify(history, null, 2));
  writePrivateAtomic(path, pem);
  writePrivateAtomic(join(dataDir, 'signing-public.pem'), current.publicKey);
  return { previousKid: previous.kid, kid: current.kid };
}
