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

test('invalid command identifiers are sanitized in denial audit events', async (t) => {
  const root = await workspace(t);
  const events = [];
  const policy = nodePolicy(root, { audit(event) { events.push(event); } });
  for (const invalid of ['bad\ncommand', 'bad;command', 'a'.repeat(129), 'constructor']) {
    await assert.rejects(() => policy.preview(invalid, [], { cwd: root }), PolicyDeniedError);
  }
  const denied = events.filter((event) => event.type === 'policy.denied');
  assert.equal(denied.length, 4);
  assert.deepEqual(denied.map((event) => event.command), Array(4).fill('[invalid-command]'));
});

test('audit events omit raw arguments and environment values', async (t) => {
  const root = await workspace(t);
  const events = [];
  const secret = 'super-secret-value-123';
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
    allowedCwdRoots: [root],
    envOverrideAllowlist: ['TOKEN'],
    audit(event) {
      events.push(event);
    },
  });
  await policy.run('node', ['-e', 'process.stdout.write("ok")', secret], { cwd: root, env: { TOKEN: secret } });
  const serialized = JSON.stringify(events);
  assert.equal(serialized.includes(secret), false);
  assert.ok(events.some((event) => event.type === 'execution.completed'));
  assert.ok(events.every((event) => typeof event.argvSha256 === 'string'));
});

test('audit sink failures do not change authorization or execution', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
    allowedCwdRoots: [root],
    audit() {
      throw new Error('logging backend unavailable');
    },
  });
  const result = await policy.run('node', ['-e', 'process.stdout.write("ok")'], { cwd: root });
  assert.equal(result.stdout, 'ok');
});

test('an unresolved async audit sink cannot block command execution', async (t) => {
  const root = await workspace(t);
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'read' } },
    allowedCwdRoots: [root],
    audit() {
      return new Promise(() => {});
    },
  });
  const result = await policy.run('node', ['-e', 'process.stdout.write("ok")'], { cwd: root });
  assert.equal(result.stdout, 'ok');
});

test('bare executable resolution ignores relative PATH entries', async (t) => {
  const root = await workspace(t);
  const originalPath = process.env.PATH;
  const executableDir = path.dirname(process.execPath);
  process.env.PATH = `relative-bin${path.delimiter}${executableDir}`;
  t.after(() => {
    if (originalPath === undefined) delete process.env.PATH;
    else process.env.PATH = originalPath;
  });

  const logicalName = path.basename(process.execPath, path.extname(process.execPath));
  const policy = createExecPolicy({
    commands: { [logicalName]: { defaultRisk: 'read' } },
    allowedCwdRoots: [root],
  });
  const decision = await policy.preview(logicalName, ['-v'], { cwd: root });
  const { realpath } = await import('node:fs/promises');
  assert.equal(decision.resolvedExecutable, await realpath(process.execPath));
});

test('trustedExecutableRoots can pin executable location', async (t) => {
  const root = await workspace(t);
  const trusted = path.dirname(await import('node:fs/promises').then(({ realpath }) => realpath(process.execPath)));
  const policy = nodePolicy(root, { trustedExecutableRoots: [trusted] });
  const decision = await policy.preview('node', ['-v'], { cwd: root });
  assert.ok(decision.resolvedExecutable.startsWith(trusted));

  const untrustedRoot = await workspace(t);
  const blocked = nodePolicy(root, { trustedExecutableRoots: [untrustedRoot] });
  await assert.rejects(() => blocked.preview('node', ['-v'], { cwd: root }), PolicyDeniedError);
});

test('policy configuration is snapshotted and cannot be weakened after construction', async (t) => {
  const root = await workspace(t);
  const commands = { node: { executable: process.execPath } };
  const roots = [root];
  const policy = createExecPolicy({ commands, allowedCwdRoots: roots });

  commands.sh = { executable: process.execPath };
  roots.push(await workspace(t));

  await assert.rejects(() => policy.preview('sh', ['-v'], { cwd: root }), PolicyDeniedError);
});

test('approval receives frozen argv so approval cannot change what is executed', async (t) => {
  const root = await workspace(t);
  let frozen = false;
  const policy = createExecPolicy({
    commands: { node: { executable: process.execPath, defaultRisk: 'destructive' } },
    allowedCwdRoots: [root],
    approve(request) {
      frozen = Object.isFrozen(request.args);
      assert.throws(() => request.args.push('MUTATED'), TypeError);
      return true;
    },
  });

  const result = await policy.run('node', ['-e', 'process.stdout.write(process.argv.includes("MUTATED") ? "bad" : "good")'], { cwd: root });
  assert.equal(frozen, true);
  assert.equal(result.stdout, 'good');
});

test('shell metacharacters in argv remain literal data', async (t) => {
  const root = await workspace(t);
  const marker = path.join(root, 'should-not-exist');
  const payload = `hello; touch ${marker}`;
  const policy = nodePolicy(root);
  const result = await policy.run('node', ['-e', 'process.stdout.write(process.argv[1])', payload], { cwd: root });
  assert.equal(result.stdout, payload);
  await assert.rejects(() => readFile(marker), /ENOENT/);
});
