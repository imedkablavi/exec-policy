# @imedkablavi/exec-policy

[![npm](https://img.shields.io/npm/v/%40imedkablavi%2Fexec-policy)](https://www.npmjs.com/package/@imedkablavi/exec-policy)
[![CI](https://github.com/imedkablavi/exec-policy/actions/workflows/ci.yml/badge.svg)](https://github.com/imedkablavi/exec-policy/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

**Policy-gated command execution for Node.js services, automation and AI agents.**

`exec-policy` is the authorization layer between application/tool input and `child_process.spawn()`. It lets trusted application code expose a small, explicit set of operating-system commands without accepting arbitrary shell execution.

```text
AI agent / automation
        |
        v
 structured tool request
        |
        v
  exec-policy preview()
        |
   +----+----+
   |         |
 denied   approval?
   |         |
   |      trusted gate
   |         |
   +----v----+
        run()
        |
        v
   shell:false child
```

## Why use it?

Passing a model-generated string to a shell makes the operating system command boundary part of the prompt surface. `exec-policy` makes the boundary explicit instead:

- **Allowlist commands** — only configured logical command keys can run.
- **No shell strings** — execution uses argv arrays with `shell: false`.
- **Validate arguments** — add per-command deny patterns and synchronous validators.
- **Classify risk** — `read`, `write` and `destructive`, with unclassified commands defaulting to `destructive`.
- **Gate risky work** — require approval for writes, destructive actions or every execution.
- **Constrain the working directory** — canonicalize and enforce allowed roots, including symlink-aware containment checks.
- **Constrain the executable** — pin an absolute binary or require resolved executables to live under trusted roots.
- **Minimize environment access** — inherit only explicitly selected variables and allow overrides only for explicitly approved keys.
- **Bound resources** — timeout, cancellation, output, argv/environment size and direct-child concurrency limits.
- **Preview safely** — inspect the decision before spawning anything.
- **Audit without copying secrets** — structured lifecycle events include an argv fingerprint, not raw argv or environment values.

> **Important:** `exec-policy` is a policy gate, not an operating-system sandbox. It does not provide kernel isolation, namespaces, syscall filtering, filesystem isolation or network egress controls. Use containers, VMs, namespaces, seccomp/AppArmor/SELinux and network controls when those properties matter.

## Install

```bash
npm install @imedkablavi/exec-policy
```

Requirements: **Node.js 20+** and **ESM**.

## Quick start

```ts
import { createExecPolicy } from '@imedkablavi/exec-policy';

const exec = createExecPolicy({
  commands: {
    git: {
      executable: '/usr/bin/git',
      defaultRisk: 'read',
    },
  },
  allowedCwdRoots: ['/srv/my-project'],
});

const result = await exec.run('git', ['status', '--short'], {
  cwd: '/srv/my-project',
});

console.log(result.stdout);
```

Only command keys present in `commands` can run. There is deliberately no API that accepts a shell command string.

## Secure command policy

For commands whose behavior changes meaningfully based on arguments, classify and validate them explicitly:

```ts
const exec = createExecPolicy({
  commands: {
    git: {
      executable: '/usr/bin/git',
      defaultRisk: 'read',
      classify(args) {
        const action = args[0];
        if (action === 'push' || action === 'reset' || action === 'clean') return 'destructive';
        if (action === 'add' || action === 'commit' || action === 'switch') return 'write';
        return 'read';
      },
      denyArgPatterns: [/^--upload-pack=/],
      validateArgs(args) {
        return args.length <= 16 || 'too many git arguments';
      },
    },
  },
  allowedCwdRoots: ['/srv/my-project'],
  approval: 'destructive',
});
```

The default risk for a command without `classify()` or `defaultRisk` is `destructive`, so a newly allowlisted command does not silently become an approval-free operation.

### Approval

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
    return askOperatorForApproval(request);
  },
});
```

Approval modes are `never`, `write`, `destructive` and `always`. Missing approval handlers fail closed with `ApprovalRequiredError`.

## Preview before execution

Use `preview()` to resolve the executable, canonicalize the working directory, validate arguments and determine whether approval is required without spawning the process:

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

Use `dryRun: true` on `run()` when you need an `ExecutionResult`-shaped authorization result without invoking the approver or spawning the child.

## AI agents and tool calling

Keep the model/tool protocol separate from the process boundary. Map structured tool input to a **fixed logical command** and an argv array; never pass a model-generated shell string through an execution API.

```ts
export async function runGitTool(input: { args: string[]; cwd: string }) {
  const decision = await exec.preview('git', input.args, { cwd: input.cwd });

  if (decision.requiresApproval) {
    return {
      status: 'approval_required',
      command: decision.command,
      executable: decision.resolvedExecutable,
      cwd: decision.cwd,
      risk: decision.risk,
      argvSha256: decision.argvSha256,
    };
  }

  return exec.run('git', input.args, { cwd: input.cwd });
}
```

This pattern applies to OpenAI tool calls, MCP tools, agent loops, background workers and CI automation. The library handles command authorization; your application still owns user permissions, tool selection, output handling and any sandbox/container boundary.

See [`docs/AI_AGENTS.md`](docs/AI_AGENTS.md) and [`examples/ai-agent-tool.mjs`](examples/ai-agent-tool.mjs).

## Working-directory and executable boundaries

`allowedCwdRoots` is canonicalized with `realpath()` before containment checks, so a symlink inside an allowed root cannot be used to redirect the working directory outside that root during authorization.

For high-trust workloads, pin executable paths:

```ts
const exec = createExecPolicy({
  commands: {
    node: {
      executable: '/usr/bin/node',
      defaultRisk: 'read',
    },
  },
  allowedCwdRoots: ['/srv/app'],
  trustedExecutableRoots: ['/usr/bin'],
});
```

Bare executable names are resolved only from absolute `PATH` entries. Relative `PATH` entries such as `.` are ignored. This reduces common current-directory hijacking paths, but a writable absolute `PATH` directory is still not a trusted executable source.

On Windows, `.bat` and `.cmd` targets are intentionally rejected because direct execution of those files requires shell mediation. Use a real executable such as `.exe`/`.com` or an explicitly reviewed executable wrapper.

## Environment control

By default, only `PATH` is inherited. Additional variables and per-execution overrides must be explicitly allowed:

```ts
const exec = createExecPolicy({
  commands: {
    tool: {
      executable: '/usr/local/bin/tool',
      defaultRisk: 'read',
    },
  },
  allowedCwdRoots: ['/srv/app'],
  inheritEnv: ['PATH', 'LANG'],
  envOverrideAllowlist: ['TASK_MODE'],
});

await exec.run('tool', ['run'], {
  cwd: '/srv/app',
  env: { TASK_MODE: 'safe' },
});
```

Avoid putting long-lived secrets in argv. Audit events intentionally omit raw argv and environment values, but operating systems and child processes may expose them through other channels.

## Resource controls

Policy-wide defaults are conservative bounds for common automation workloads:

| Control | Default |
| --- | ---: |
| Timeout | 30 s |
| Captured stdout/stderr | 1 MiB combined |
| Argument count | 128 |
| One argument | 16 KiB |
| Combined argv | 128 KiB |
| One environment value | 64 KiB |
| Combined environment | 256 KiB |
| Direct children per policy | 16 |

Per-execution `timeoutMs` and `maxOutputBytes` can only tighten the configured policy limit.

A timeout, abort or output overflow terminates the direct child. The package does not promise recursive cleanup of every descendant process, nor does it impose host-wide CPU/RAM/network/process limits.

## Audit events

The optional `audit` callback receives structured lifecycle events such as `policy.allowed`, `approval.requested`, `execution.started` and `execution.completed`.

Audit data intentionally excludes raw argv and environment values. It includes a SHA-256 `argvSha256` fingerprint, argument count, command metadata, risk and execution outcome so applications can correlate events without this package copying likely secrets into logs.

Audit delivery is best-effort and non-blocking. An approval handler is different: it is part of the security boundary and fails closed when it throws or returns a non-boolean value.

## Errors

The package exports typed errors for policy and execution failures:

```ts
import {
  PolicyDeniedError,
  ApprovalRequiredError,
  ApprovalDeniedError,
  ExecutableResolutionError,
  ExecutionTimeoutError,
  ExecutionAbortedError,
  OutputLimitError,
  ProcessSpawnError,
  ConcurrencyLimitError,
} from '@imedkablavi/exec-policy';
```

A non-zero child exit code is returned in `ExecutionResult`; it is not automatically converted into a policy error.

## Documentation

- [Getting started](docs/GETTING_STARTED.md) — practical configuration patterns.
- [AI agent integration](docs/AI_AGENTS.md) — structured tool/agent execution patterns.
- [Architecture](docs/ARCHITECTURE.md) — policy preparation, execution and audit paths.
- [Threat model](THREAT_MODEL.md) — security properties, trust boundaries and limitations.
- [Security policy](SECURITY.md) — vulnerability reporting and security-sensitive areas.
- [Releasing](docs/RELEASING.md) — package/release checklist.

## Security model

`exec-policy` is designed to reduce common application-layer command-execution mistakes:

- arbitrary executable selection
- shell interpolation and shell metacharacter execution
- cwd traversal and simple symlink escapes
- unexpected environment propagation
- unreviewed destructive operations
- unbounded execution time, captured output, argv/environment size and direct-child concurrency

It does **not** make an allowed executable safe for every possible argument sequence. When untrusted input reaches an allowed executable, use command-specific `validateArgs()` rules and an external isolation boundary when required.

## Compatibility

- Node.js 20+
- ESM
- Zero runtime dependencies
- MIT License

## License

MIT
