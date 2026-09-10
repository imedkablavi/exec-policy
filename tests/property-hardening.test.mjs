import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { PolicyDeniedError, createExecPolicy } from '../dist/index.js';

async function workspace(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'exec-policy-property-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function nextRandom(state) {
  return (state * 1664525 + 1013904223) >>> 0;
}

test('deterministic command-identifier fuzzing never crosses the logical allowlist boundary', async (t) => {
  const root = await workspace(t);
  const instance = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
    allowedCwdRoots: [root],
  });
  const alphabet = ' /\\;:$%\t\n\r\0_+-.''';
  let state = 0x5eedc0de;

  for (let i = 0; i < 256; i += 1) {
    let candidate = `x${i}/`;
    for (let j = 0; j < 8; j += 1) {
      state = nextRandom(state);
      candidate += alphabet[state % alphabet.length];
    }
    await assert.rejects(
      () => instance.preview(candidate, [], { cwd: root }),
      PolicyDeniedError,
      `candidate ${JSON.stringify(candidate)} must be denied`,
    );
  }
});

test('stateful global and sticky deny regexes are reset between arguments and executions', async (t) => {
  const root = await workspace(t);
  const instance = createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
        denyArgPatterns: [/blocked/g, /^unsafe/y],
      },
    },
    allowedCwdRoots: [root],
  });

  await assert.rejects(() => instance.preview('node', ['blocked'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => instance.preview('node', ['blocked'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => instance.preview('node', ['unsafe'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => instance.preview('node', ['unsafe'], { cwd: root }), PolicyDeniedError);
});

test('multibyte command identifiers are rejected even when byte length is below the logical key limit', async (t) => {
  const root = await workspace(t);
  const instance = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
    allowedCwdRoots: [root],
  });

  await assert.rejects(() => instance.preview('nœde', [], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => instance.preview('节点', [], { cwd: root }), PolicyDeniedError);
});
