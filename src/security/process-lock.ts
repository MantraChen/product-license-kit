import { existsSync, readFileSync, writeFileSync, unlinkSync } from 'node:fs';
import { dirname } from 'node:path';
import { privateDirectory } from './private-storage.js';
import { requireThat } from '../core/model.js';

export function assertServiceStopped(path: string): void {
  if (!existsSync(path)) return;
  const pid = Number(readFileSync(path, 'utf8').trim());
  requireThat(Number.isSafeInteger(pid) && pid > 0, 'INVALID_SERVICE_LOCK');
  try { process.kill(pid, 0); }
  catch (error) { if ((error as NodeJS.ErrnoException).code === 'ESRCH') return; throw error; }
  requireThat(false, 'SERVICE_MUST_BE_STOPPED', 409);
}
export function acquireServiceLock(path: string): () => void {
  privateDirectory(dirname(path));
  // Serialize stale-lock reclamation; never remove another starter's new lock.
  // A crash while holding this short-lived guard fails closed for operator review.
  const guard = `${path}.guard`;
  writeFileSync(guard, String(process.pid), {flag:'wx', mode:0o600});
  try {
    assertServiceStopped(path);
    if (existsSync(path)) unlinkSync(path);
    writeFileSync(path, String(process.pid), {flag:'wx', mode:0o600});
  } finally { unlinkSync(guard); }
  return () => {
    if (existsSync(path) && readFileSync(path, 'utf8').trim() === String(process.pid)) unlinkSync(path);
  };
}
