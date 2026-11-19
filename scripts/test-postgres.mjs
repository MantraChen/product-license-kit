import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { randomBytes } from 'node:crypto';
import { closeSync, existsSync, mkdtempSync, openSync, readFileSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:net';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

// Own a temporary cluster; never connect to a guessed local/production database or register a service.
const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
assert.equal(process.cwd(), root);
const binary = process.env.PLK_POSTGRES_BIN;
assert.ok(binary && existsSync(join(binary, process.platform === 'win32' ? 'initdb.exe' : 'initdb')), 'Set PLK_POSTGRES_BIN to the PostgreSQL bin directory.');
const openssl = process.env.PLK_OPENSSL ?? (process.platform === 'win32' ? 'C:/Program Files/Git/usr/bin/openssl.exe' : 'openssl');
const directory = mkdtempSync(join(tmpdir(), 'plk-postgres-'));
const data = join(directory, 'cluster'), passwordFile = join(directory, 'password');
const password = randomBytes(32).toString('base64url');
writeFileSync(passwordFile, password, { mode: 0o600 });
async function run(name, args, env = process.env) {
  const executable = name === 'node' ? process.execPath : name === 'openssl' ? openssl : join(binary, name + (process.platform === 'win32' ? '.exe' : ''));
  await new Promise((done, fail) => {
    // On Windows pg_ctl descendants can inherit pipe handles after pg_ctl exits. File handles do not delay Node's close event.
    const logFile = name === 'node' ? undefined : join(directory, `${name}.log`);
    let descriptor = logFile ? openSync(logFile, 'a', 0o600) : undefined;
    const child = spawn(executable, args, { cwd: root, env, windowsHide: true,
      stdio: descriptor === undefined ? ['ignore', 'pipe', 'pipe'] : ['ignore', descriptor, descriptor] });
    const closeLog = () => { if (descriptor !== undefined) { closeSync(descriptor); descriptor = undefined; } };
    let stdout = '', stderr = '';
    child.stdout?.on('data', value => { stdout += value; }); child.stderr?.on('data', value => { stderr += value; });
    child.once('error', error => { closeLog(); fail(error); });
    child.once('close', code => {
      closeLog();
      if (logFile) stderr += readFileSync(logFile, 'utf8');
      // Database credentials never appear in command arguments or emitted diagnostics.
      if (code !== 0) fail(new Error(`POSTGRES_TEST_FAILED:${name}:${code}\n${(stdout + stderr).replaceAll(password, '[redacted]').slice(-6000)}`));
      else { if (name === 'node') process.stdout.write(stdout); done(); }
    });
  });
}
const probe = createServer(); await new Promise(done => probe.listen(0, '127.0.0.1', done));
const port = probe.address().port; await new Promise(done => probe.close(done));
let initialized = false, started = false, stopped = false;
try {
  await run('initdb', ['-D', data, '--username=plk_test', '--auth=scram-sha-256', '--encoding=UTF8', '--locale=C', `--pwfile=${passwordFile}`, '--no-instructions']);
  initialized = true;
  // Connection-scoped trust only: no certificate is imported into the operating system.
  await run('openssl', ['req', '-x509', '-newkey', 'rsa:2048', '-sha256', '-nodes', '-days', '1', '-subj', '/CN=127.0.0.1',
    '-keyout', join(data, 'server.key'), '-out', join(data, 'server.crt'), '-addext', 'subjectAltName=IP:127.0.0.1',
    '-addext', 'basicConstraints=critical,CA:FALSE', '-addext', 'extendedKeyUsage=serverAuth']);
  await run('pg_ctl', ['-D', data, '-l', join(directory, 'server.log'), '-o', `-h 127.0.0.1,::1 -p ${port} -c max_connections=30 -c fsync=on -c log_statement=none -c ssl=on`, '-w', '-t', '30', 'start']);
  started = true;
  const env = { ...process.env, PLK_TEST_POSTGRES_SCOPED: '1', PLK_TEST_POSTGRES_CA_FILE: join(data, 'server.crt'),
    PLK_TEST_POSTGRES_URL: `postgresql://plk_test:${password}@127.0.0.1:${port}/postgres` };
  await run('node', ['--test', '.test-build/tests/postgres/transactions.js', '.test-build/tests/postgres/domain.js', '.test-build/tests/postgres/coordination.js', '.test-build/tests/postgres/signing.js', '.test-build/tests/postgres/compatibility.js', '.test-build/tests/postgres/portal.js', '.test-build/tests/postgres/kook-bot.js'], env);
  if (process.argv.includes('--native'))
    await run('node', ['scripts/check-native-clients.mjs'], { ...env, PLK_NATIVE_BACKEND: 'postgres' });
} finally {
  if (initialized) {
    try { await run('pg_ctl', ['-D', data, '-w', '-t', '30', '-m', 'fast', 'stop']); stopped = true; }
    catch (error) { if (started) throw error; }
  }
  // A failed start may still have left a server. Retain its scoped cluster unless shutdown was confirmed.
  if (!initialized || stopped) {
    const exact = realpathSync(directory), parent = realpathSync(tmpdir());
    assert.equal(dirname(exact).toLowerCase(), parent.toLowerCase());
    assert.ok(exact.toLowerCase().startsWith(join(parent, 'plk-postgres-').toLowerCase()));
    rmSync(exact, { recursive: true });
  }
}
