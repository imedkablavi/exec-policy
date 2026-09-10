import process from 'node:process';
import { createExecPolicy } from '@imedkablavi/exec-policy';

// In a real service, keep the workspace roots tenant/job-specific and pin
// executable paths to directories controlled by the deployment.
const workspaceRoot = '/srv/workspaces/example';

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
      denyArgPatterns: [/^--upload-pack=/, /^--exec-path=/],
    },
  },
  allowedCwdRoots: [workspaceRoot],
  approval: 'destructive',
  timeoutMs: 15_000,
  maxOutputBytes: 256 * 1024,
  maxConcurrent: 4,
});

/**
 * Convert a structured model/tool request into a policy decision.
 * Never accept an arbitrary shell command string from the model.
 */
export async function executeAgentTool(input) {
  if (!input || !Array.isArray(input.args) || typeof input.cwd !== 'string') {
    throw new TypeError('invalid tool input');
  }

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

  const result = await exec.run('git', input.args, {
    cwd: input.cwd,
  });

  return {
    status: 'completed',
    exitCode: result.exitCode,
    stdout: result.stdout,
    stderr: result.stderr,
  };
}

if (import.meta.url === `file://${process.argv[1]}`) {
  console.log(await executeAgentTool({
    args: ['status', '--short'],
    cwd: workspaceRoot,
  }));
}
