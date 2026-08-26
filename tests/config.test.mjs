import test from 'node:test';
import assert from 'node:assert/strict';
import process from 'node:process';
import { createExecPolicy } from '../dist/index.js';

test('rejects empty command policies', () => {
  assert.throws(() => createExecPolicy({ commands: {} }), /at least one/);
});

test('rejects relative cwd policy roots', () => {
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, allowedCwdRoots: ['relative'] }), /absolute/);
});

test('rejects unsafe command keys', () => {
  assert.throws(() => createExecPolicy({ commands: { 'node;rm': { executable: process.execPath } } }), /invalid command key/);
});

test('rejects oversized command keys before runtime lookup', () => {
  const key = 'a'.repeat(129);
  assert.throws(() => createExecPolicy({ commands: { [key]: { executable: process.execPath } } }), /invalid command key/);
});

test('rejects invalid policy limits', () => {
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, timeoutMs: 0 }), /timeoutMs/);
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, maxOutputBytes: 0 }), /maxOutputBytes/);
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, maxTotalArgBytes: 0 }), /maxTotalArgBytes/);
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, maxEnvBytes: 0 }), /maxEnvBytes/);
  assert.throws(() => createExecPolicy({ commands: { node: { executable: process.execPath } }, maxConcurrent: 0 }), /maxConcurrent/);
});


test('rejects reserved command keys', () => {
  for (const key of ['__proto__', 'prototype', 'constructor']) {
    const commands = Object.create(null);
    commands[key] = { executable: process.execPath, defaultRisk: 'read' };
    assert.throws(() => createExecPolicy({ commands }), /invalid command key/);
  }
});

test('rejects non-array argv at runtime', async () => {
  const policy = createExecPolicy({ commands: { node: { executable: process.execPath, defaultRisk: 'read' } } });
  await assert.rejects(() => policy.preview('node', 'not-an-array'), /array of strings/);
});

test('Windows refuses shell-script executables to preserve shell:false', { skip: process.platform !== 'win32' }, async () => {
  const path = await import('node:path');
  const { mkdtemp, writeFile, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const root = await mkdtemp(path.default.join(tmpdir(), 'exec-policy-win-'));
  try {
    const script = path.default.join(root, 'unsafe.cmd');
    await writeFile(script, '@echo off\r\necho unsafe\r\n', 'utf8');
    assert.throws(() => createExecPolicy({
      commands: { unsafe: { executable: script, defaultRisk: 'read' } },
      allowedCwdRoots: [root],
    }), /shell-script executables are not supported/);

    const previousPath = process.env.PATH;
    process.env.PATH = root;
    try {
      const policy = createExecPolicy({
        commands: { unsafe: { executable: 'unsafe.cmd', defaultRisk: 'read' } },
        allowedCwdRoots: [root],
      });
      await assert.rejects(() => policy.preview('unsafe', [], { cwd: root }), /shell-script executables are not supported/);
    } finally {
      if (previousPath === undefined) delete process.env.PATH;
      else process.env.PATH = previousPath;
    }
  } finally {
    await rm(root, { recursive: true, force: true });
  }
});
