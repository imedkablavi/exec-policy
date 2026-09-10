import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import { ExecutionAbortedError, createExecPolicy } from '../dist/index.js';

async function workspace(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'exec-policy-abort-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

test('abort requested immediately after spawn handoff terminates execution', async (t) => {
  const root = await workspace(t);
  const controller = new AbortController();
  const policy = createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
      },
    },
    allowedCwdRoots: [root],
    timeoutMs: 10_000,
  });

  const execution = policy.run('node', ['-e', 'setTimeout(() => {}, 10_000)'], {
    cwd: root,
    signal: controller.signal,
  });
  setImmediate(() => controller.abort());

  await assert.rejects(execution, ExecutionAbortedError);
});
