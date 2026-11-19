import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..');
assert.equal(process.cwd(), root, 'Run from the framework root.');
assert.ok(existsSync(join(root, '.test-build/tests/helpers.js')), 'Run pnpm check before the native SDK checks.');
const requested = process.argv.slice(2).filter(value => value !== '--');
const languages = requested.length ? [...new Set(requested)] : ['dotnet', 'rust'];
assert.ok(languages.every(value => ['dotnet', 'rust'].includes(value)), 'Use dotnet and/or rust.');
const dotnet = process.env.PLK_DOTNET ?? 'dotnet', cargo = process.env.PLK_CARGO ?? 'cargo';
async function run(executable, arguments_) {
  await new Promise((done, fail) => {
    const child = spawn(executable, arguments_, { cwd: root, windowsHide: true, stdio: 'inherit' });
    child.once('error', fail);
    child.once('close', code => code === 0 ? done() : fail(new Error(`NATIVE_CHECK_FAILED:${code}`)));
  });
}
if (languages.includes('dotnet') || process.platform === 'win32') {
  await run(dotnet, ['build', 'clients/dotnet/ProductLicenseKit.Tests/ProductLicenseKit.Tests.csproj', '-c', 'Release', '-p:RestoreLockedMode=true', '--nologo']);
  await run(dotnet, ['clients/dotnet/ProductLicenseKit.Tests/bin/Release/net10.0/ProductLicenseKit.Tests.dll']);
}
if (languages.includes('rust')) {
  const manifest = ['--manifest-path', 'clients/rust/Cargo.toml'];
  await run(cargo, ['fmt', ...manifest, '--check']);
  await run(cargo, ['clippy', ...manifest, '--locked', '--all-targets', '--', '-D', 'warnings']);
  await run(cargo, ['test', ...manifest, '--locked', '--release']);
  await run(cargo, ['build', ...manifest, '--locked', '--release', '--example', 'interop']);
}
for (const language of languages) await run(process.execPath, ['scripts/test-native-clients.mjs', language]);
