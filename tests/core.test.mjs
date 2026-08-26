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

test('runs an explicitly allowed executable without a shell', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root);
  const result = await policy.run('node', ['-e', 'process.stdout.write("ok")'], { cwd: root });
  assert.equal(result.exitCode, 0);
  assert.equal(result.stdout, 'ok');
  assert.equal(result.stderr, '');
  assert.equal(result.dryRun, false);
});

test('denies commands missing from the allowlist', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root);
  await assert.rejects(() => policy.run('sh', ['-c', 'echo nope'], { cwd: root }), PolicyDeniedError);
});

test('unclassified commands default to destructive risk', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath } },
    allowedCwdRoots: [root],
  });
  const decision = await policy.preview('node', ['-v'], { cwd: root });
  assert.equal(decision.risk, 'destructive');
  assert.equal(decision.requiresApproval, true);
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root }), ApprovalRequiredError);
});

test('prototype-like command names cannot bypass the allowlist', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root);
  for (const command of ['toString', 'constructor', '__proto__']) {
    await assert.rejects(() => policy.preview(command, [], { cwd: root }), PolicyDeniedError);
  }
});

test('denies working directories outside allowed roots', async (t) => {
  const root = await workspace(t);
  const outside = await workspace(t);
  const policy = nodePolicy(root);
  await assert.rejects(() => policy.preview('node', ['-v'], { cwd: outside }), PolicyDeniedError);
});

test('resolves cwd symlinks before enforcing root boundaries', async (t) => {
  const root = await workspace(t);
  const outside = await workspace(t);
  const link = path.join(root, 'escape');
  await symlink(outside, link, process.platform === 'win32' ? 'junction' : 'dir');
  const policy = nodePolicy(root);
  await assert.rejects(() => policy.preview('node', ['-v'], { cwd: link }), PolicyDeniedError);
});

test('rejects NUL bytes and overlong argv', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { maxArgs: 2, maxArgBytes: 8 });
  await assert.rejects(() => policy.preview('node', ['abc\0def'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => policy.preview('node', ['123456789'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => policy.preview('node', ['a', 'b', 'c'], { cwd: root }), PolicyDeniedError);
});

test('combined argv bytes are bounded', async (t) => {
  const root = await workspace(t);
  const policy = nodePolicy(root, { maxArgBytes: 16, maxTotalArgBytes: 10 });
  await assert.rejects(() => policy.preview('node', ['123456', 'abcdef'], { cwd: root }), /combined argument bytes/);
});

test('supports command-specific deny patterns and validators', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        denyArgPatterns: [/danger/i],
        validateArgs(args) {
          return args.includes('--blocked') ? 'blocked flag' : true;
        },
      },
    },
    allowedCwdRoots: [root],
  });
  await assert.rejects(() => policy.preview('node', ['danger'], { cwd: root }), PolicyDeniedError);
  await assert.rejects(() => policy.preview('node', ['--blocked'], { cwd: root }), /blocked flag/);
});

test('async or otherwise invalid argument validators fail closed', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
        async validateArgs() {
          return true;
        },
      },
    },
    allowedCwdRoots: [root],
  });
  await assert.rejects(() => policy.preview('node', ['-v'], { cwd: root }), /async validators are not supported/);
});

test('classifies risk and requires approval at the configured threshold', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: {
      node: {
        executable: process.execPath,
        classify(args) {
          return args.includes('--write') ? 'write' : 'read';
        },
      },
    },
    allowedCwdRoots: [root],
    approval: 'write',
  });
  const readDecision = await policy.preview('node', ['-v'], { cwd: root });
  const writeDecision = await policy.preview('node', ['--write'], { cwd: root });
  assert.equal(readDecision.requiresApproval, false);
  assert.equal(writeDecision.requiresApproval, true);
  assert.equal(writeDecision.risk, 'write');
});

test('fails closed when approval is required but no approver exists', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
  });
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root }), ApprovalRequiredError);
});

test('approval handler can deny and allow execution', async (t) => {
  const root = await workspace(t);
  const denied = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve: () => false,
  });
  await assert.rejects(() => denied.run('node', ['-v'], { cwd: root }), ApprovalDeniedError);

  let seenRisk;
  const allowed = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve(request) {
      seenRisk = request.risk;
      return true;
    },
  });
  const result = await allowed.run('node', ['-e', 'process.stdout.write("approved")'], { cwd: root });
  assert.equal(seenRisk, 'destructive');
  assert.equal(result.stdout, 'approved');
});

test('non-boolean approval results fail closed', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve() {
      return 'yes';
    },
  });
  await assert.rejects(() => policy.run('node', ['-v'], { cwd: root }), ApprovalDeniedError);
});

test('approval handler failures fail closed with a typed error', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve() {
      throw new Error('approval backend unavailable');
    },
  });
  await assert.rejects(
    () => policy.run('node', ['-v'], { cwd: root }),
    (error) => error instanceof ApprovalDeniedError && error.cause instanceof Error,
  );
});

test('dry-run reports approval requirements without invoking approval or spawning', async (t) => {
  const root = await workspace(t);
  const marker = path.join(root, 'marker.txt');
  let approvalCalls = 0;
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve() {
      approvalCalls += 1;
      return true;
    },
  });
  const result = await policy.run('node', ['-e', `require('node:fs').writeFileSync(${JSON.stringify(marker)}, 'x')`], {
    cwd: root,
    dryRun: true,
  });
  assert.equal(result.dryRun, true);
  assert.equal(result.requiresApproval, true);
  assert.equal(approvalCalls, 0);
  await assert.rejects(() => readFile(marker), /ENOENT/);
});
