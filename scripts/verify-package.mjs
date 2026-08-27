import assert from 'node:assert/strict';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { spawnSync } from 'node:child_process';

const root = process.cwd();
const sourcePkg = JSON.parse(await readFile(path.join(root, 'package.json'), 'utf8'));
const npmExecPath = process.env.npm_execpath;
assert.ok(npmExecPath, 'npm_execpath is required; run this verifier through npm run test:package');

const runNpm = (args, options = {}) => spawnSync(process.execPath, [npmExecPath, ...args], {
  encoding: 'utf8',
  windowsHide: true,
  ...options,
});

const packDir = await mkdtemp(path.join(tmpdir(), 'exec-policy-pack-'));
const work = await mkdtemp(path.join(tmpdir(), 'exec-policy-package-'));

try {
  // Pack outside the repository so this verifier cannot collide with an outer
  // `npm publish`/`npm publish --dry-run` lifecycle using the same tarball name.
  const pack = runNpm([
    'pack',
    '--json',
    '--ignore-scripts',
    '--pack-destination',
    packDir,
  ], { cwd: root });
  assert.equal(pack.status, 0, pack.error?.message || pack.stderr || pack.stdout);

  const parsed = JSON.parse(pack.stdout);
  const packed = parsed[0];
  const filename = packed?.filename;
  assert.ok(filename, 'npm pack did not return a filename');
  const tarballPath = path.join(packDir, filename);

  const packedFiles = new Set((packed.files ?? []).map((entry) => entry.path));
  for (const required of [
    'package.json',
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'THREAT_MODEL.md',
    'CHANGELOG.md',
    'dist/index.js',
    'dist/index.d.ts',
  ]) {
    assert.ok(packedFiles.has(required), `published package is missing ${required}`);
  }
  for (const file of packedFiles) {
    assert.equal(file.startsWith('tests/'), false, `tests must not be published: ${file}`);
    assert.equal(file.startsWith('.github/'), false, `GitHub workflow metadata must not be published: ${file}`);
    assert.equal(file.startsWith('src/'), false, `TypeScript source must not be published: ${file}`);
    assert.equal(file.startsWith('node_modules/'), false, `node_modules must not be published: ${file}`);
  }

  const init = runNpm(['init', '-y'], { cwd: work });
  assert.equal(init.status, 0, init.error?.message || init.stderr || init.stdout);
  const install = runNpm(['install', '--ignore-scripts', tarballPath], { cwd: work });
  assert.equal(install.status, 0, install.error?.message || install.stderr || install.stdout);

  const imported = spawnSync(process.execPath, ['--input-type=module', '-e', `
    import { createExecPolicy, PolicyDeniedError, ConcurrencyLimitError } from '@imedkablavi/exec-policy';
    if (typeof createExecPolicy !== 'function') process.exit(2);
    if (typeof PolicyDeniedError !== 'function') process.exit(3);
    if (typeof ConcurrencyLimitError !== 'function') process.exit(5);

    const policy = createExecPolicy({
      commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
      allowedCwdRoots: [process.cwd()],
    });
    const result = await policy.run('node', ['-e', 'process.stdout.write("package-ok")']);
    if (result.stdout !== 'package-ok' || result.exitCode !== 0) process.exit(4);
  `], { cwd: work, encoding: 'utf8', windowsHide: true });
  assert.equal(imported.status, 0, imported.error?.message || imported.stderr || imported.stdout);

  const pkg = JSON.parse(await readFile(path.join(work, 'node_modules/@imedkablavi/exec-policy/package.json'), 'utf8'));
  assert.equal(pkg.version, sourcePkg.version);
  assert.equal(pkg.type, 'module');
  assert.equal(pkg.sideEffects, false);
  assert.deepEqual(pkg.dependencies ?? {}, {});
  for (const forbidden of ['preinstall', 'install', 'postinstall']) {
    assert.equal(pkg.scripts?.[forbidden], undefined, `published package must not define ${forbidden}`);
  }
} finally {
  await rm(packDir, { recursive: true, force: true });
  await rm(work, { recursive: true, force: true });
}

console.log(`Verified clean-room install, runtime execution and package contents for @imedkablavi/exec-policy@${sourcePkg.version}.`);
