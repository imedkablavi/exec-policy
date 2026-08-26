import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, readFile, rm, symlink } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {
  ApprovalDeniedError,
  ApprovalRequiredError,
  ConcurrencyLimitError,
  ExecutionAbortedError,
  ExecutionTimeoutError,
  OutputLimitError,
  PolicyDeniedError,
  createExecPolicy,
} from '../dist/index.js';

async function workspace(t) {
  const root = await mkdtemp(path.join(tmpdir(), 'exec-policy-test-'));
  t.after(() => rm(root, { recursive: true, force: true }));
  return root;
}

function nodePolicy(root, extra = {}) {
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

test('environment inheritance and overrides are explicit', async (t) => {
  const root = await workspace(t);
  process.env.EXEC_POLICY_TEST_SECRET = 'parent-secret';
  t.after(() => delete process.env.EXEC_POLICY_TEST_SECRET);

  const restrictive = nodePolicy(root);
  const hidden = await restrictive.run('node', ['-e', 'process.stdout.write(String(process.env.EXEC_POLICY_TEST_SECRET))'], { cwd: root });
  assert.equal(hidden.stdout, 'undefined');
  await assert.rejects(() => restrictive.preview('node', ['-v'], { cwd: root, env: { EXEC_POLICY_TEST_SECRET: 'override' } }), PolicyDeniedError);

  const explicit = nodePolicy(root, {
    inheritEnv: ['PATH', 'EXEC_POLICY_TEST_SECRET'],
    envOverrideAllowlist: ['EXEC_POLICY_TEST_SECRET'],
  });
  const inherited = await explicit.run('node', ['-e', 'process.stdout.write(process.env.EXEC_POLICY_TEST_SECRET ?? "")'], { cwd: root });
  assert.equal(inherited.stdout, 'parent-secret');
  const overridden = await explicit.run('node', ['-e', 'process.stdout.write(process.env.EXEC_POLICY_TEST_SECRET ?? "")'], {
    cwd: root,
    env: { EXEC_POLICY_TEST_SECRET: 'override' },
  });
  assert.equal(overridden.stdout, 'override');
});

test('child environment is snapshotted before approval', async (t) => {
  const root = await workspace(t);
  const key = 'EXEC_POLICY_ENV_SNAPSHOT';
  process.env[key] = 'before';
  t.after(() => delete process.env[key]);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    inheritEnv: ['PATH', key],
    approve() {
      process.env[key] = 'after';
      return true;
    },
  });
  const result = await policy.run('node', ['-e', `process.stdout.write(process.env.${key} ?? '')`], { cwd: root });
  assert.equal(result.stdout, 'before');
});

test('environment values and total environment size are bounded', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, {
    inheritEnv: [],
    envOverrideAllowlist: ['A', 'B'],
    maxEnvValueBytes: 8,
    maxEnvBytes: 12,
  });
  await assert.rejects(() => policy.preview('node', ['-v'], { cwd: root, env: { A: '123456789' } }), /environment value exceeds/);
  await assert.rejects(() => policy.preview('node', ['-v'], { cwd: root, env: { A: '123456', B: 'abcdef' } }), /combined environment bytes/);
});

test('per-execution resource overrides can only tighten policy limits', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { timeoutMs: 500, maxOutputBytes: 1024 });
  const tighter = await policy.run('node', ['-e', 'process.stdout.write("ok")'], {
    cwd: root,
    timeoutMs: 250,
    maxOutputBytes: 512,
  });
  assert.equal(tighter.stdout, 'ok');
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root, timeoutMs: 501 }), PolicyDeniedError);
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root, maxOutputBytes: 1025 }), PolicyDeniedError);
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root, timeoutMs: 501, dryRun: true }), PolicyDeniedError);
});

test('direct child concurrency is bounded per policy instance', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { maxConcurrent: 1, timeoutMs: 10_000 });
  const controller = new AbortController();
  const first = policy.run('node', ['-e', 'setTimeout(() => {}, 10_000)'], { cwd: root, signal: controller.signal });
  await new Promise((resolve) => setTimeout(resolve, 30));
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root }), ConcurrencyLimitError);
  controller.abort();
  await assert.rejects(() => first, ExecutionAbortedError);
  const after = await policy.run('node', ['-e', 'process.stdout.write("ok")'], { cwd: root });
  assert.equal(after.stdout, 'ok');
});

test('timeout terminates long-running commands', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { timeoutMs: 100 });
  await assert.rejects(
    () => policy.run('node', ['-e', 'setTimeout(() => {}, 10_000)'], { cwd: root }),
    ExecutionTimeoutError,
  );
});

test('pre-aborted execution is rejected before approval is requested', async (t) => {
  const root = await workspace(t);
  let approvals = 0;
  const events = [];
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve() {
      approvals += 1;
      return true;
    },
    audit(event) {
      events.push(event);
    },
  });
  const controller = new AbortController();
  controller.abort();
  await assert.rejects(
    () => policy.run('node', ['-v'], { cwd: root, signal: controller.signal }),
    ExecutionAbortedError,
  );
  assert.equal(approvals, 0);
  assert.equal(events.some((event) => event.type === 'approval.requested'), false);
  assert.equal(events.some((event) => event.type === 'execution.rejected'), true);
});

test('AbortSignal cancels execution', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { timeoutMs: 10_000 });
  const controller = new AbortController();
  setTimeout(() => controller.abort(), 50);
  await assert.rejects(
    () => policy.run('node', ['-e', 'setTimeout(() => {}, 10_000)'], { cwd: root, signal: controller.signal }),
    ExecutionAbortedError,
  );
});

test('output capture is bounded', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { maxOutputBytes: 64 });
  await assert.rejects(
    () => policy.run('node', ['-e', 'process.stdout.write("x".repeat(1024))'], { cwd: root }),
    OutputLimitError,
  );
});

test('preserves UTF-8 characters split across output chunks', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root);
  const script = [
    'const bytes = Buffer.from("€");',
    'process.stdout.write(bytes.subarray(0, 1));',
    'setTimeout(() => process.stdout.write(bytes.subarray(1)), 20);',
  ].join('');
  const result = await policy.run('node', ['-e', script], { cwd: root });
  assert.equal(result.stdout, '€');
});

test('non-zero exit codes are returned without shell-style throwing', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root);
  const result = await policy.run('node', ['-e', 'process.stderr.write("bad"); process.exit(7)'], { cwd: root });
  assert.equal(result.exitCode, 7);
  assert.equal(result.stderr, 'bad');
});
