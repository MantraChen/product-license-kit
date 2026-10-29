import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';

const tracked = execFileSync('git', ['ls-files', '-z'], { encoding: 'utf8' }).split('\0').filter(Boolean);
if (!tracked.length) throw new Error('No tracked files: stage the intended publication before running this check.');
const problems = [];
const credentialPatterns = [
  /-----BEGIN (?:RSA |EC |OPENSSH |ENCRYPTED )?PRIVATE KEY-----/,
  /\bgh[pousr]_[A-Za-z0-9]{30,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{30,}\b/,
];
for (const file of tracked) {
  if (/(^|\/)(node_modules|\.data|dist|\.test-build|artifacts)\//.test(file) ||
    /\.(sqlite(?:-.*)?|db(?:-.*)?|pem|key|pfx|p12|log)$/i.test(file) ||
    (/(^|\/)\.env(?:\..*)?$/.test(file) && !file.endsWith('.env.example'))) problems.push(`${file}: private/runtime file`);
  const content = readFileSync(file, 'utf8');
  if (credentialPatterns.some(pattern => pattern.test(content))) problems.push(`${file}: possible credential`);
}
const packageInfo = JSON.parse(readFileSync('package.json', 'utf8'));
if (packageInfo.license !== 'PolyForm-Noncommercial-1.0.0') problems.push('package.json: unexpected public license');
if (problems.length) { console.error(problems.join('\n')); process.exitCode = 1; }
else console.log(`Checked ${tracked.length} tracked files: no forbidden runtime files or recognized credential patterns.`);
