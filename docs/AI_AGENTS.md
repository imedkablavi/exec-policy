# AI agent integration

The safest way to give an AI agent operating-system tools is to keep the agent's requested action separate from the process policy that authorizes it.

Recommended flow:

```text
Model/tool request
      |
      v
Application maps tool -> logical command
      |
      v
exec.preview(command, args, { cwd })
      |
      +---- denied ----> return a policy error to the agent
      |
      +---- approval required ----> ask a trusted human/service
      |
      v
exec.run(command, args, { cwd })
      |
      v
bounded child process
```

## Generic tool wrapper

A tool implementation should not pass a model-generated shell string to a process API. Map structured tool inputs to a known command key and an argv array.

```ts
import { createExecPolicy } from '@imedkablavi/exec-policy';

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
      validateArgs(args) {
        if (args.some((arg) => arg.startsWith('--upload-pack='))) {
          return 'custom upload-pack arguments are not allowed';
        }
        return true;
      },
    },
  },
  allowedCwdRoots: ['/srv/workspaces'],
  approval: 'destructive',
});

export async function runGitTool(input: { args: string[]; cwd: string }) {
  const decision = await exec.preview('git', input.args, { cwd: input.cwd });

  if (decision.requiresApproval) {
    return {
      status: 'approval_required',
      decision: {
        command: decision.command,
        executable: decision.resolvedExecutable,
        cwd: decision.cwd,
        risk: decision.risk,
        argvSha256: decision.argvSha256,
      },
    };
  }

  const result = await exec.run('git', input.args, { cwd: input.cwd });
  return {
    status: 'completed',
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}
```

The important boundary is the mapping from structured agent input to a logical command key. Do not expose an escape hatch such as `exec({ command: modelText })`, `spawn(modelText, { shell: true })`, or a policy rule that accepts arbitrary executable paths.

## Approval design

For interactive systems, use `preview()` to create the approval payload first. Show operators the logical command, resolved executable, canonical working directory and risk level. The built-in approval request also contains a fingerprint (`argvSha256`) for correlation.

For unattended agents, keep destructive operations disabled unless the application has an explicit, independently enforced approval workflow. A missing approval handler fails closed when the selected policy requires approval.

## Output handling

Treat child stdout/stderr as untrusted data. A child process can print secrets, prompt-injection text or machine-readable content that changes the next agent decision. Apply your application's output parsing and content policy before returning it to the model.

Use small `maxOutputBytes` and `timeoutMs` values for agent workloads. The policy-level limits cannot be weakened by individual execution requests.

## MCP and other tool protocols

The same pattern applies to MCP tools, OpenAI tool calls, background job runners and CI automation:

1. Parse a structured tool request.
2. Select a fixed logical command.
3. Build a bounded argv array.
4. Call `preview()`.
5. Apply the application's approval decision when required.
6. Call `run()` only after the policy decision is still valid.
7. Return bounded stdout/stderr and the exit code to the caller.

`exec-policy` controls process authorization; it does not replace a container/VM sandbox or your model/tool permission system.
