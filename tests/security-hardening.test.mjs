import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {
  ApprovalDeniedError,
  ExecutionAbortedError,
  OutputLimitError,
  PolicyDeniedError,
  createExecPolicy,
} from '../dist/index.js';

async function workspace(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'exec-policy-hardening-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function policy(root, extra = {}) {
  return createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
      },
    },
    allowedCwdRoots: [root],
    ...extra,
  });
}

test('clones policy configuration so later command/validator mutations cannot weaken enforcement', async (t) => {
  const root = await workspace(t);
  const commands = {
    node: {
      executable: process.execPath,
      defaultRisk: 'read',
      denyArgPatterns: [/blocked/],
    },
  };
  const policyInstance = createExecPolicy({ commands, allowedCwdRoots: [root] });

  commands.node.executable = process.execPath;
  commands.node.denyArgPatterns = [];
  commands.node.defaultRisk = 'destructive';

  await assert.rejects(
    () => policyInstance.preview('node', ['blocked'], { cwd: root }),
    PolicyDeniedError,
  );
  const decision = await policyInstance.preview('node', ['-v'], { cwd: root });
  assert.equal(decision.risk, 'read');
});

test('snapshots environment inheritance before approval and ignores later process.env changes', async (t) => {
  const root = await workspace(t);
  const key = 'EXEC_POLICY_SNAPSHOT_TEST';
  const original = process.env[key];
  t.after(() => {
    if (original === undefined) delete process.env[key];
    else process.env[key] = original;
  });

  process.env[key] = 'before-approval';
  let approved = false;
  let seen = '';
  const instance = policy(root, {
    inheritEnv: ['PATH', key],
    approval: 'always',
    approve() {
      process.env[key] = 'after-approval';
      approved = true;
      return true;
    },
  });
  const result = await instance.run('node', ['-e', `process.stdout.write(process.env[${JSON.stringify(key)}])`], { cwd: root });
  seen = result.stdout;

  assert.equal(approved, true);
  assert.equal(seen, 'before-approval');
});

test('pre-aborted signals are rejected without invoking approval', async (t) => {
  const root = await workspace(t);
  const controller = new AbortController();
  controller.abort();
  let approvalCalls = 0;
  const instance = policy(root, {
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'destructive',
      },
    },
    approve() {
      approvalCalls += 1;
      return true;
    },
  });

  await assert.rejects(
    () => instance.run('node', ['-v'], { cwd: root, signal: controller.signal }),
    ExecutionAbortedError,
  );
  assert.equal(approvalCalls, 0);
});

test('approval denial does not consume a concurrency slot', async (t) => {
  const root = await workspace(t);
  let approvals = 0;
  const instance = policy(root, {
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'destructive',
      },
    },
    maxConcurrent: 1,
    approve() {
      approvals += 1;
      return false;
    },
  });

  await assert.rejects(() => instance.run('node', ['-v'], { cwd: root }), ApprovalDeniedError);
  await assert.rejects(() => instance.run('node', ['-v'], { cwd: root }), ApprovalDeniedError);
  assert.equal(approvals, 2);
});

test('output limits fail closed and preserve UTF-8 decoding for accepted chunks', async (t) => {
  const root = await workspace(t);
  const instance = policy(root, { maxOutputBytes: 16 });
  const text = '✓'.repeat(4);
  const result = await instance.run('node', ['-e', `process.stdout.write(${JSON.stringify(text)})`], { cwd: root });
  assert.equal(result.stdout, text);

  const limited = policy(root, { maxOutputBytes: 8 });
  await assert.rejects(
    () => limited.run('node', ['-e', `process.stdout.write(${JSON.stringify(text.repeat(4))})`], { cwd: root }),
    OutputLimitError,
  );
});

test('unsafe command identifiers are denied consistently across randomized inputs', async (t) => {
  const root = await workspace(t);
  const instance = policy(root);
  const candidates = [
    '',
    ' ',
    '../node',
    './node',
    'node/extra',
    'node\\extra',
    '$HOME',
    ';node',
    'node\0',
    'constructor',
    '__proto__',
    'prototype',
    'x'.repeat(129),
  ];

  for (const command of candidates) {
    await assert.rejects(() => instance.preview(command, [], { cwd: root }), PolicyDeniedError);
  }
});
