import { spawn } from 'node:child_process';
import { createServer } from 'node:net';
import assert from 'node:assert/strict';

const probe = createServer();
await new Promise(resolve => probe.listen(0, '127.0.0.1', resolve));
const port = probe.address().port;
await new Promise(resolve => probe.close(resolve));
const child = spawn(process.execPath, ['--env-file=.env', 'dist/main.js'], {
  env: { ...process.env, HOST: '127.0.0.1', PORT: String(port) }, stdio: ['ignore', 'pipe', 'pipe'], windowsHide: true,
});
let output = ''; child.stdout.on('data', b => { output += b; }); child.stderr.on('data', b => { output += b; });
let ready = false;
try {
  for (let attempt = 0; attempt < 50; attempt++) {
    if (child.exitCode !== null) throw new Error('Server exited before startup');
    try {
      const response = await fetch(`http://127.0.0.1:${port}/health`);
      assert.equal(response.status, 200); assert.equal((await response.json()).status, 'ok'); ready = true; break;
    } catch { await new Promise(resolve => setTimeout(resolve, 100)); }
  }
  assert.ok(ready, 'Server did not start');
  const catalog = await (await fetch(`http://127.0.0.1:${port}/v1/catalog`)).json();
  assert.equal(catalog.products.length, 3);
  console.log('Persistent server entry point started, health/catalog passed, stopping smoke-test process.');
} catch (error) {
  console.error(output); throw error;
} finally {
  const exited = child.exitCode !== null ? Promise.resolve() : new Promise(resolve => child.once('exit', resolve));
  child.kill(); await exited;
}
