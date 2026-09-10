# Getting started

`@imedkablavi/exec-policy` is a policy gate for Node.js process execution. It is useful when application code, automation or an AI agent needs to run a small, explicitly reviewed set of operating-system commands without exposing a general-purpose shell.

## Install

```bash
npm install @imedkablavi/exec-policy
```

Requirements: Node.js 20+ and ESM.

## Minimal policy

Start by naming exactly which logical commands the application may execute. Pin executables to absolute paths for high-trust deployments.

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

There is no API that accepts a shell command string. Arguments are passed as an argv array and execution uses `shell: false`.

## Add argument-aware policy

An executable allowlist is not enough when arguments can be influenced by untrusted input. Add a command-specific validator and classify risky operations.

```ts
const exec = createExecPolicy({
  commands: {
    git: {
      executable: '/usr/bin/git',
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
      validateArgs(args) {
        if (args.includes('--upload-pack=/bin/sh')) {
          return 'unsafe upload-pack override';
        }
        return true;
      },
    },
  },
  allowedCwdRoots: ['/srv/my-project'],
  approval: 'destructive',
});
```

Unclassified commands default to `destructive`, so newly allowlisted commands do not silently become approval-free operations.

## Preview before execution

Use `preview()` when you want to show a human the exact decision without starting a process.

```ts
const decision = await exec.preview('git', ['status', '--short'], {
  cwd: '/srv/my-project',
});

console.log({
  executable: decision.resolvedExecutable,
  cwd: decision.cwd,
  risk: decision.risk,
  requiresApproval: decision.requiresApproval,
});
```

Use `dryRun: true` on `run()` when you need the same authorization result shape without invoking the approval callback or spawning the child.

## Keep the child environment narrow

The default inherited environment is only `PATH`. Opt into additional variables explicitly and separately allow per-call overrides.

```ts
const exec = createExecPolicy({
  commands: {
    deploy: {
      executable: '/usr/local/bin/deploy-tool',
      defaultRisk: 'destructive',
    },
  },
  allowedCwdRoots: ['/srv/app'],
  inheritEnv: ['PATH', 'LANG'],
  envOverrideAllowlist: ['DEPLOY_ENV'],
});

await exec.run('deploy', ['release'], {
  cwd: '/srv/app',
  env: { DEPLOY_ENV: 'staging' },
});
```

Avoid inheriting process-control or dynamic-loader variables unless they are an explicit, trusted requirement. Examples include `NODE_OPTIONS`, `NODE_PATH`, `NODE_EXTRA_CA_CERTS`, `LD_PRELOAD`, `LD_LIBRARY_PATH`, `DYLD_INSERT_LIBRARIES` and `DYLD_LIBRARY_PATH`. Tool-specific variables such as `GIT_SSH_COMMAND` can also change how an otherwise allowlisted command behaves. Treat the inherited environment as part of the security policy, not as general application configuration.

Avoid putting long-lived secrets in argv. Audit events intentionally omit raw argv and environment values, but the operating system or child process may still expose argv/environment through other mechanisms.

## Resource limits

Keep limits conservative for agentic workloads. The library supports policy-wide defaults for timeout, captured output, argv/environment size and direct-child concurrency, with per-execution timeout/output overrides that can only tighten the policy.

```ts
const exec = createExecPolicy({
  commands: {
    tool: {
      executable: '/usr/local/bin/tool',
      defaultRisk: 'read',
    },
  },
  allowedCwdRoots: ['/srv/app'],
  timeoutMs: 15_000,
  maxOutputBytes: 256 * 1024,
  maxConcurrent: 4,
});
```

## What this does not provide

`exec-policy` is not an operating-system sandbox. It does not provide kernel isolation, filesystem namespaces, network egress controls, syscall filtering, host-wide resource limits or protection from a malicious executable that the operating system already trusts.

Use containers, namespaces, VMs, seccomp/AppArmor/SELinux and network controls when those properties are required.

See [THREAT_MODEL.md](../THREAT_MODEL.md) for the trust boundaries and known limitations.
