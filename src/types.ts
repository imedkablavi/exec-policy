export type RiskLevel = 'read' | 'write' | 'destructive';
export type ApprovalMode = 'never' | 'write' | 'destructive' | 'always';

export interface CommandRule {
  /** Executable to resolve and spawn. Defaults to the command key. */
  executable?: string;
  /** Risk used when classify() is not provided. Defaults to destructive (fail-closed). */
  defaultRisk?: RiskLevel;
  /** Optional command-specific risk classifier. */
  classify?: (args: readonly string[]) => RiskLevel;
  /** Optional command-specific argument validator. Return true/undefined to allow, false/string to deny. */
  validateArgs?: (args: readonly string[]) => boolean | string | undefined;
  /** Reject an argument if any pattern matches it. */
  denyArgPatterns?: readonly RegExp[];
  /** Approval threshold for this command. Defaults to the policy setting. */
  approval?: ApprovalMode;
}

export interface ApprovalRequest {
  command: string;
  executable: string;
  resolvedExecutable: string;
  args: readonly string[];
  cwd: string;
  risk: RiskLevel;
  argvSha256: string;
}

export type ApprovalHandler = (request: ApprovalRequest) => boolean | Promise<boolean>;

export interface AuditEvent {
  type:
    | 'policy.allowed'
    | 'policy.denied'
    | 'approval.requested'
    | 'approval.denied'
    | 'execution.rejected'
    | 'execution.started'
    | 'execution.completed'
    | 'execution.failed';
  timestamp: string;
  command: string;
  resolvedExecutable?: string;
  cwd?: string;
  risk?: RiskLevel;
  argvSha256: string;
  argCount: number;
  durationMs?: number;
  exitCode?: number | null;
  signal?: NodeJS.Signals | null;
  reason?: string;
}

export type AuditHandler = (event: Readonly<AuditEvent>) => void | Promise<void>;

export interface ExecPolicyOptions {
  /** Commands that may be requested. Any missing command is denied. */
  commands: Readonly<Record<string, Readonly<CommandRule>>>;
  /** Real filesystem roots a command may use as cwd. Defaults to process.cwd(). */
  allowedCwdRoots?: readonly string[];
  /** Optional roots that resolved executables must live under. */
  trustedExecutableRoots?: readonly string[];
  /** Environment variables inherited from process.env. Defaults to PATH only. */
  inheritEnv?: readonly string[];
  /** Environment variables callers may override per execution. Defaults to none. */
  envOverrideAllowlist?: readonly string[];
  /** Default approval threshold. Defaults to destructive. */
  approval?: ApprovalMode;
  /** Approval callback. Required at runtime when approval is needed. */
  approve?: ApprovalHandler;
  /** Structured audit callback. Raw args and environment values are intentionally omitted. */
  audit?: AuditHandler;
  /** Default timeout. Defaults to 30 seconds. */
  timeoutMs?: number;
  /** Combined stdout/stderr capture limit. Defaults to 1 MiB. */
  maxOutputBytes?: number;
  /** Maximum argv length. Defaults to 128 entries. */
  maxArgs?: number;
  /** Maximum UTF-8 size of one argument. Defaults to 16 KiB. */
  maxArgBytes?: number;
  /** Maximum combined UTF-8 size of argv. Defaults to 128 KiB. */
  maxTotalArgBytes?: number;
  /** Maximum UTF-8 size of one inherited/overridden environment value. Defaults to 64 KiB. */
  maxEnvValueBytes?: number;
  /** Maximum combined UTF-8 size of the child environment. Defaults to 256 KiB. */
  maxEnvBytes?: number;
  /** Maximum direct child processes running concurrently through one policy instance. Defaults to 16. */
  maxConcurrent?: number;
}

export interface ExecutionOptions {
  cwd?: string;
  env?: Readonly<Record<string, string | undefined>>;
  signal?: AbortSignal;
  /** Per-execution timeout override. May only tighten the policy-level timeout. */
  timeoutMs?: number;
  /** Per-execution output override. May only tighten the policy-level capture limit. */
  maxOutputBytes?: number;
  /** Evaluate policy and report approval requirements, but do not call the approver or spawn. */
  dryRun?: boolean;
}

export interface PreviewDecision {
  allowed: true;
  command: string;
  executable: string;
  resolvedExecutable: string;
  args: readonly string[];
  cwd: string;
  risk: RiskLevel;
  requiresApproval: boolean;
  argvSha256: string;
}

export interface ExecutionResult {
  command: string;
  executable: string;
  resolvedExecutable: string;
  args: readonly string[];
  cwd: string;
  risk: RiskLevel;
  argvSha256: string;
  stdout: string;
  stderr: string;
  exitCode: number | null;
  signal: NodeJS.Signals | null;
  durationMs: number;
  dryRun: boolean;
}
