import test from 'node:test';
import assert from 'node:assert/strict';
import { mkdtemp, mkdir, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import process from 'node:process';
import {
  ApprovalDeniedError,
  ConcurrencyLimitError,
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

test('policy snapshots command rules and ignores later caller mutation', async (t) => {
  const root = await workspace(t);
  const commands = {
    node: {
      executable: process.execPath,
      defaultRisk: 'read',
      denyArgPatterns: [/blocked/],
    },
  };
  const policyInstance = createExecPolicy({ commands, allowedCwdRoots: [root] });

  commands.node.denyArgPatterns = [];
  commands.node.defaultRisk = 'destructive';

  await assert.rejects(
    () => policyInstance.preview('node', ['blocked'], { cwd: root }),
    PolicyDeniedError,
  );
  const decision = await policyInstance.preview('node', ['-v'], { cwd: root });
  assert.equal(decision.risk, 'read');
});

test('policy snapshots path arrays and does not follow later caller mutation', async (t) => {
  const root = await workspace(t);
  const outside = await workspace(t);
  const roots = [root];
  const policyInstance = createExecPolicy({
    commands: {
      node: { executable: process.execPath, defaultRisk: 'read' },
    },
    allowedCwdRoots: roots,
  });

  roots.push(outside);

  const decision = await policyInstance.preview('node', ['-v'], { cwd: root });
  assert.equal(decision.cwd, root);
  await assert.rejects(() => policyInstance.preview('node', ['-v'], { cwd: outside }), PolicyDeniedError);
});

test('approval denial leaves capacity available for a later execution', async (t) => {
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

test('audit events do not contain raw arguments or environment override values', async (t) => {
  const root = await workspace(t);
  const events = [];
  const secretArg = 'super-secret-argument';
  const secretEnv = 'super-secret-environment';
  const instance = policy(root, {
    inheritEnv: [],
    envOverrideAllowlist: ['EXEC_POLICY_AUDIT_SECRET'],
    audit(event) {
      events.push(event);
    },
  });

  const result = await instance.run('node', ['-e', 'process.stdout.write("ok")', secretArg], {
    cwd: root,
    env: { EXEC_POLICY_AUDIT_SECRET: secretEnv },
  });
  assert.equal(result.stdout, 'ok');

  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes(secretArg), false);
  assert.equal(serialized.includes(secretEnv), false);
  assert.ok(events.some((event) => typeof event.argvSha256 === 'string' && event.argvSha256.length === 64));
});

test('command policy remains usable with a growing caller-owned command object', async (t) => {
  const root = await workspace(t);
  const commands = {
    node: {
      executable: process.execPath,
      defaultRisk: 'read',
    },
  };
  const instance = createExecPolicy({ commands, allowedCwdRoots: [root] });
  commands.sh = {
    executable: process.execPath,
    defaultRisk: 'read',
  };

  await assert.rejects(() => instance.preview('sh', ['-v'], { cwd: root }), PolicyDeniedError);
  const result = await instance.run('node', ['-e', 'process.stdout.write("ok")'], { cwd: root });
  assert.equal(result.stdout, 'ok');
});

test('read-only policy denies execution when a classifier raises', async (t) => {
  const root = await workspace(t);
  const instance = policy(root, {
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
        classify() {
          throw new Error('classifier failed');
        },
      },
    },
  });

  await assert.rejects(() => instance.preview('node', ['-v'], { cwd: root }), /classifier failed/);
});

test('trusted executable roots reject a resolved binary outside the configured root', async (t) => {
  const root = await workspace(t);
  const fakeRoot = await workspace(t);
  const bin = path.join(fakeRoot, 'bin');
  await mkdir(bin);
  const instance = policy(root, {
    commands: {
      node: {
        executable: process.execPath,
        defaultRisk: 'read',
      },
    },
    trustedExecutableRoots: [bin],
  });

  await assert.rejects(() => instance.preview('node', ['-v'], { cwd: root }), PolicyDeniedError);
});
