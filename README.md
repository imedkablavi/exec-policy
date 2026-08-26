# @imedkablavi/exec-policy

**Policy-gated command execution for Node.js automation and AI agents.**

`exec-policy` puts an explicit authorization layer in front of `child_process.spawn()`. It is designed for services, CLIs, automation and agentic workflows that need to run a small set of operating-system commands without accepting arbitrary shell execution.

- explicit command allowlist
- no shell-string API; execution uses `shell: false`
- canonical working-directory boundaries
- optional trusted executable roots
- per-command argument validation and deny rules
- `read` / `write` / `destructive` risk classification with a fail-closed `destructive` default
- explicit approval gates
- environment inheritance and override allowlists
- timeout, cancellation, captured-output limits and per-policy direct-child concurrency limits
- relative `PATH` entries ignored during bare executable resolution
- dry-run/preview mode
- structured audit events that omit raw argv and environment values
- zero runtime dependencies

> This package is a **policy gate**, not an operating-system sandbox. Use containers, namespaces, VMs, seccomp/AppArmor/SELinux and egress controls when you need process isolation.

## Requirements

- Node.js 20+
- ESM

## Install

```bash
npm install @imedkablavi/exec-policy
```

**Requirements:** Node.js 20 or newer. The package is published as an ES module.

### GitHub Packages

The same package can also be distributed through GitHub Packages under the personal GitHub scope `@imedkablavi`. If you intentionally use GitHub Packages, configure the scope registry and authenticate with a GitHub token that has package-read permission:

```bash
npm config set @imedkablavi:registry https://npm.pkg.github.com
npm install @imedkablavi/exec-policy
```

Do not commit registry tokens to a repository.

## Quick start

```ts
import { createExecPolicy } from '@imedkablavi/exec-policy';

const exec = createExecPolicy({
  commands: {
    git: {
      defaultRisk: 'read',
      classify(args) {
        const action = args[0];
        if (action === 'push' || action === 'reset' || action === 'clean') {
          return 'destructive';
        }
        if (action === 'add' || action === 'commit' || action === 'switch') {
          return 'write';
        }
        return 'read';
      },
      denyArgPatterns: [/^--upload-pack=/],
    },
  },
  allowedCwdRoots: ['/srv/my-project'],
  approval: 'destructive',
});

const result = await exec.run('git', ['status', '--short'], {
  cwd: '/srv/my-project',
});

console.log(result.stdout);
```

Only command keys present in `commands` can run. The package never exposes an API that accepts a shell command string. In this example, read-only Git operations can run while destructive operations fail closed because no approval handler is configured.

## Preview before execution

Use `preview()` to resolve the executable, canonicalize the working directory, validate arguments and determine whether approval is required without spawning a process.

```ts
const decision = await exec.preview('git', ['status'], {
  cwd: '/srv/my-project',
});

console.log({
  executable: decision.resolvedExecutable,
  cwd: decision.cwd,
  risk: decision.risk,
  requiresApproval: decision.requiresApproval,
});
```

Use `dryRun` when you want the same policy decision as `run()` without spawning a process. It reports whether approval would be required, but it does not invoke the approval callback:

```ts
const result = await exec.run('git', ['status'], {
  cwd: '/srv/my-project',
  dryRun: true,
});

console.log(result.dryRun); // true
```

## Command policies

Each command has its own rule:

```ts
const exec = createExecPolicy({
  commands: {
    node: {
      executable: '/usr/bin/node',
      defaultRisk: 'read',
      denyArgPatterns: [/^--inspect(?:-brk)?=/],
      validateArgs(args) {
        if (args.length > 8) return 'too many node arguments';
        return true;
      },
    },
  },
  allowedCwdRoots: ['/srv/tasks'],
});
```

The object key (`node` above) is the logical command requested by application code. `executable` may pin it to a specific absolute binary. If omitted, the command key is resolved using the inherited `PATH`.

### Risk and approval

Risk levels are intentionally small:

| Risk | Typical use |
| --- | --- |
| `read` | inspect status, read metadata, list files |
| `write` | modify local state |
| `destructive` | deletion, force/reset operations, externally impactful actions |

Approval modes:

| Mode | Approval required for |
| --- | --- |
| `never` | nothing |
| `write` | write + destructive |
| `destructive` | destructive only |
| `always` | every execution |

The approval-mode default is `destructive`. Separately, an unclassified command also defaults to the `destructive` risk level. This means a newly allowlisted command does not silently become a non-approved read operation. Set `defaultRisk: 'read'` only when that is genuinely the correct baseline, or provide `classify()` for command-specific semantics.

```ts
const exec = createExecPolicy({
  commands: {
    deploy: {
      executable: '/usr/local/bin/deploy-tool',
      defaultRisk: 'destructive',
      approval: 'always',
    },
  },
  allowedCwdRoots: ['/srv/app'],
  approve: async (request) => {
    return await askOperatorForApproval(request);
  },
});
```

If approval is required and no `approve` handler exists, execution fails closed with `ApprovalRequiredError`.

## Working-directory boundaries

`allowedCwdRoots` restricts where a command may run:

```ts
const exec = createExecPolicy({
  commands: { git: { defaultRisk: 'read' } },
  allowedCwdRoots: [
    '/srv/repos/project-a',
    '/srv/repos/project-b',
  ],
});
```

Both configured roots and requested working directories are canonicalized with `realpath()` before comparison. A symlink inside an allowed root cannot be used to escape to another directory.

## Pin executable locations

An allowlisted name such as `git` still depends on `PATH` resolution. For stronger control, either configure an absolute executable per command or restrict resolved binaries to trusted roots:

```ts
const exec = createExecPolicy({
  commands: {
    git: { executable: '/usr/bin/git', defaultRisk: 'read' },
    node: { executable: '/usr/bin/node', defaultRisk: 'read' },
  },
  allowedCwdRoots: ['/srv/app'],
  trustedExecutableRoots: ['/usr/bin'],
});
```

For high-trust deployments, absolute executable paths are preferable to a mutable `PATH`. When a bare executable name is used, relative `PATH` entries such as `.` are ignored; only absolute entries participate in resolution. This removes a common current-directory hijack path, but it does not make a writable absolute `PATH` directory trustworthy.

### Windows executable note

The package intentionally keeps `shell: false`. On Windows, `.bat` and `.cmd` files require a command shell and therefore are not treated as directly executable policy targets. Use a real executable such as `.exe`/`.com`, or wrap script behavior in an explicitly reviewed executable boundary.

This avoids silently weakening the no-shell security property for platform convenience.

## Environment control

By default, the child process inherits only `PATH`, and callers cannot override any environment variable.

```ts
const exec = createExecPolicy({
  commands: { tool: { executable: '/usr/local/bin/tool', defaultRisk: 'read' } },
  allowedCwdRoots: ['/srv/app'],
  inheritEnv: ['PATH', 'LANG'],
  envOverrideAllowlist: ['TASK_MODE'],
});

await exec.run('tool', ['run'], {
  cwd: '/srv/app',
  env: {
    TASK_MODE: 'safe',
  },
});
```

An override for a key that is not in `envOverrideAllowlist` is denied.

Avoid passing long-lived secrets through child-process environments when a narrower mechanism is available.

## Timeouts, cancellation and output limits

```ts
const controller = new AbortController();

const resultPromise = exec.run('tool', ['work'], {
  cwd: '/srv/app',
  timeoutMs: 15_000,
  maxOutputBytes: 256 * 1024,
  signal: controller.signal,
});

// Later:
controller.abort();
```

Defaults:

- timeout: 30 seconds
- combined stdout/stderr capture: 1 MiB
- max argv entries: 128
- max bytes per argument: 16 KiB
- max combined argv bytes: 128 KiB
- max environment value: 64 KiB
- max combined child environment: 256 KiB
- max concurrent direct children per policy instance: 16

Per-execution `timeoutMs` and `maxOutputBytes` may only tighten the policy-level limits. A caller cannot use execution options to raise the resource budget above what the policy owner configured.

A timeout, abort or output overflow terminates the direct child and rejects with a typed error. `maxConcurrent` limits direct children launched through one policy instance. This package does not promise to terminate every descendant process a child may have created, nor does it impose a host-wide process limit; use OS/container process-group and resource controls when those properties matter.

## Audit events without raw arguments

`audit` receives lifecycle events suitable for structured logs or tracing:

```ts
const exec = createExecPolicy({
  commands: { git: { defaultRisk: 'read' } },
  allowedCwdRoots: ['/srv/app'],
  audit(event) {
    logger.info(event);
  },
});
```

Audit events include the logical command, resolved executable, canonical cwd, risk, argument count and an `argvSha256` fingerprint. Audit delivery is best-effort and non-blocking by design: a slow or broken logging sink cannot change authorization or hold command execution open. **Raw arguments and environment values are intentionally omitted** so tokens passed as arguments are not copied into audit logs by this package.

The approval callback does receive the original arguments because an approver may need them to make a decision. Treat that callback as security-sensitive application code. Non-boolean approval results and approval-handler exceptions fail closed with `ApprovalDeniedError`.

## Error handling

```ts
import {
  ApprovalDeniedError,
  ApprovalRequiredError,
  ExecutionAbortedError,
  ExecutionTimeoutError,
  OutputLimitError,
  ConcurrencyLimitError,
  PolicyDeniedError,
} from '@imedkablavi/exec-policy';

try {
  await exec.run('git', ['clean', '-fd'], { cwd: '/srv/app' });
} catch (error) {
  if (error instanceof PolicyDeniedError) {
    // Command, argv, cwd, executable or environment policy rejected it.
  } else if (error instanceof ApprovalRequiredError) {
    // No approver was configured for a gated operation.
  } else if (error instanceof ApprovalDeniedError) {
    // The approver rejected it.
  } else if (error instanceof ExecutionTimeoutError) {
    // The child exceeded its timeout.
  } else if (error instanceof ExecutionAbortedError) {
    // AbortSignal cancelled it.
  } else if (error instanceof OutputLimitError) {
    // Captured stdout/stderr exceeded the policy limit.
  } else if (error instanceof ConcurrencyLimitError) {
    // This policy instance is already running its configured maximum children.
  }
}
```

A command exiting with a non-zero exit code is not itself a policy failure. The exit code and stderr are returned in `ExecutionResult` so the caller can apply application-specific semantics.

## Security model

`exec-policy` is intended to reduce common command-execution mistakes:

- arbitrary executable selection
- shell interpolation and shell metacharacter execution
- cwd traversal/symlink escapes
- unexpected environment propagation
- unreviewed destructive operations
- unbounded execution time, captured output, argv/environment size or direct-child concurrency
- audit logs that duplicate raw argv values

It does **not** provide kernel-level isolation, syscall filtering, filesystem namespaces, network isolation or a guarantee that an allowed executable is safe for every possible argument sequence.

If untrusted users can influence arguments, define command-specific `validateArgs` rules rather than relying only on the executable allowlist.

See [THREAT_MODEL.md](THREAT_MODEL.md) for the trust boundaries and known limitations.

### Safer defaults worth keeping

- Pin absolute executable paths for high-trust automation.
- Keep `maxConcurrent`, argv/environment byte limits, timeout and output limits conservative for agentic workloads.
- Treat `classify()` and `validateArgs()` as security-sensitive policy code.
- Keep approval handlers fail-closed when an approval backend is unavailable. `exec-policy` converts an approval-handler exception into `ApprovalDeniedError`.
- Prefer `preview()` or `dryRun` before presenting a command to a human operator.
- Do not interpret a successful policy decision as proof that the allowed executable itself is safe.
- Do not pass secrets in argv when the executable offers a safer credential channel. Audit events omit raw argv, but operating systems and child processes may expose arguments through other mechanisms.

## API

```ts
createExecPolicy(options): ExecPolicy

policy.preview(command, args?, options?): Promise<PreviewDecision>
policy.run(command, args?, options?): Promise<ExecutionResult>
```

Main configuration types are exported from the package root:

- `ExecPolicyOptions`
- `CommandRule`
- `ExecutionOptions`
- `ExecutionResult`
- `PreviewDecision`
- `ApprovalRequest`
- `AuditEvent`
- `RiskLevel`
- `ApprovalMode`

## License

MIT
