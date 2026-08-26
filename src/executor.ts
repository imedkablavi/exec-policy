import { spawn } from 'node:child_process';
import process from 'node:process';
import { StringDecoder } from 'node:string_decoder';
import {
  ApprovalDeniedError,
  ApprovalRequiredError,
  ExecutionAbortedError,
  ExecutionTimeoutError,
  OutputLimitError,
  PolicyDeniedError,
  ProcessSpawnError,
  ConcurrencyLimitError,
} from './errors.js';
import {
  auditBase,
  prepareExecution,
  preparePolicy,
  type PreparedExecution,
  type PreparedPolicy,
} from './policy.js';
import type {
  AuditEvent,
  ExecPolicyOptions,
  ExecutionOptions,
  ExecutionResult,
  PreviewDecision,
} from './types.js';

function safeAuditCommand(command: unknown): string {
  if (typeof command !== 'string') return '[invalid-command]';
  if (Buffer.byteLength(command, 'utf8') > 128 || !/^[A-Za-z0-9._+-]+$/.test(command)) return '[invalid-command]';
  if (command === '__proto__' || command === 'prototype' || command === 'constructor') return '[invalid-command]';
  return command;
}

export class ExecPolicy {
  readonly #policy: PreparedPolicy;
  #activeExecutions = 0;

  /** Create an immutable policy snapshot from the supplied configuration. */
  constructor(options: Readonly<ExecPolicyOptions>) {
    this.#policy = preparePolicy(options);
  }

  #audit(event: AuditEvent): void {
    try {
      const result = this.#policy.options.audit?.(Object.freeze({ ...event }));
      if (result !== undefined) void Promise.resolve(result).catch(() => {});
    } catch {
      // Audit sinks are best-effort and must not alter authorization or process control.
    }
  }

  async #prepare(command: string, args: readonly string[], options: Readonly<ExecutionOptions>): Promise<PreparedExecution> {
    let prepared: PreparedExecution;
    try {
      prepared = await prepareExecution(this.#policy, command, args, options);
    } catch (error) {
      const reason = error instanceof Error ? error.message : String(error);
      this.#audit({
        type: 'policy.denied',
        timestamp: new Date().toISOString(),
        command: safeAuditCommand(command),
        argvSha256: 'unavailable',
        argCount: Array.isArray(args) ? args.length : 0,
        reason,
      });
      throw error;
    }
    this.#audit({
      type: 'policy.allowed',
      timestamp: new Date().toISOString(),
      ...auditBase(prepared.decision),
    });
    return prepared;
  }

  /** Authorize and preview a command without invoking approval or spawning a process. */
  async preview(command: string, args: readonly string[] = [], options: Readonly<ExecutionOptions> = {}): Promise<PreviewDecision> {
    return (await this.#prepare(command, args, options)).decision;
  }

  /** Authorize, optionally approve, and execute one command under this policy. */
  async run(command: string, args: readonly string[] = [], options: Readonly<ExecutionOptions> = {}): Promise<ExecutionResult> {
    const prepared = await this.#prepare(command, args, options);
    const { decision, env } = prepared;
    const timeoutMs = options.timeoutMs ?? this.#policy.timeoutMs;
    const maxOutputBytes = options.maxOutputBytes ?? this.#policy.maxOutputBytes;

    if (options.dryRun) {
      return {
        ...decision,
        stdout: '',
        stderr: '',
        exitCode: null,
        signal: null,
        durationMs: 0,
        dryRun: true,
      };
    }

    if (options.signal?.aborted) {
      const failure = new ExecutionAbortedError(`execution aborted before approval or spawn: ${command}`);
      this.#audit({
        type: 'execution.rejected',
        timestamp: new Date().toISOString(),
        ...auditBase(decision),
        durationMs: 0,
        reason: failure.message,
      });
      throw failure;
    }

    if (decision.requiresApproval) {
      this.#audit({
        type: 'approval.requested',
        timestamp: new Date().toISOString(),
        ...auditBase(decision),
      });
      const approve = this.#policy.options.approve;
      if (!approve) {
        this.#audit({
          type: 'approval.denied',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          reason: 'approval handler is not configured',
        });
        throw new ApprovalRequiredError(`command requires explicit approval: ${command}`);
      }
      let approved: boolean;
      try {
        approved = await approve(Object.freeze({
          command: decision.command,
          executable: decision.executable,
          resolvedExecutable: decision.resolvedExecutable,
          args: decision.args,
          cwd: decision.cwd,
          risk: decision.risk,
          argvSha256: decision.argvSha256,
        }));
      } catch (error) {
        this.#audit({
          type: 'approval.denied',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          reason: 'approval handler failed',
        });
        throw new ApprovalDeniedError(`approval handler failed for command: ${command}`, { cause: error });
      }
      if (typeof approved !== 'boolean') {
        this.#audit({
          type: 'approval.denied',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          reason: 'approval handler returned a non-boolean value',
        });
        throw new ApprovalDeniedError(`approval handler returned a non-boolean value for command: ${command}`);
      }
      if (!approved) {
        this.#audit({
          type: 'approval.denied',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          reason: 'approval handler denied execution',
        });
        throw new ApprovalDeniedError(`approval denied for command: ${command}`);
      }
    }

    if (this.#activeExecutions >= this.#policy.maxConcurrent) {
      const failure = new ConcurrencyLimitError(`concurrent execution limit reached (${this.#policy.maxConcurrent})`);
      this.#audit({
        type: 'execution.rejected',
        timestamp: new Date().toISOString(),
        ...auditBase(decision),
        durationMs: 0,
        reason: failure.message,
      });
      throw failure;
    }
    this.#activeExecutions += 1;

    if (options.signal?.aborted) {
      this.#activeExecutions -= 1;
      const failure = new ExecutionAbortedError(`execution aborted before spawn: ${command}`);
      this.#audit({
        type: 'execution.rejected',
        timestamp: new Date().toISOString(),
        ...auditBase(decision),
        durationMs: 0,
        reason: failure.message,
      });
      throw failure;
    }
    const started = Date.now();

    this.#audit({
      type: 'execution.started',
      timestamp: new Date().toISOString(),
      ...auditBase(decision),
    });

    return await new Promise<ExecutionResult>((resolve, reject) => {
      let stdout = '';
      let stderr = '';
      const stdoutDecoder = new StringDecoder('utf8');
      const stderrDecoder = new StringDecoder('utf8');
      let outputBytes = 0;
      let terminationReason: 'timeout' | 'aborted' | 'output' | undefined;
      let spawnError: Error | undefined;
      let killTimer: NodeJS.Timeout | undefined;
      let settled = false;

      let child: ReturnType<typeof spawn>;
      try {
        child = spawn(decision.resolvedExecutable, [...decision.args], {
          cwd: decision.cwd,
          env,
          shell: false,
          windowsHide: true,
          stdio: ['ignore', 'pipe', 'pipe'],
        });
      } catch (error) {
        this.#activeExecutions -= 1;
        const failure = new ProcessSpawnError(`failed to spawn ${command}`, { cause: error });
        this.#audit({
          type: 'execution.failed',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          durationMs: Date.now() - started,
          reason: failure.message,
        });
        reject(failure);
        return;
      }

      const forceKill = (): void => {
        if (child.exitCode === null && child.signalCode === null) child.kill('SIGKILL');
      };
      const stop = (reason: 'timeout' | 'aborted' | 'output'): void => {
        if (terminationReason !== undefined) return;
        terminationReason = reason;
        if (child.exitCode === null && child.signalCode === null) {
          child.kill('SIGTERM');
          killTimer = setTimeout(forceKill, 500);
          killTimer.unref?.();
        }
      };

      const onAbort = (): void => {
        stop('aborted');
      };
      options.signal?.addEventListener('abort', onAbort, { once: true });

      const timeout = setTimeout(() => {
        stop('timeout');
      }, timeoutMs);
      timeout.unref?.();

      const capture = (target: 'stdout' | 'stderr', chunk: Buffer): void => {
        if (terminationReason === 'output') return;
        outputBytes += chunk.byteLength;
        if (outputBytes > maxOutputBytes) {
          stop('output');
          return;
        }
        if (target === 'stdout') stdout += stdoutDecoder.write(chunk);
        else stderr += stderrDecoder.write(chunk);
      };

      child.stdout?.on('data', (chunk: Buffer) => capture('stdout', chunk));
      child.stderr?.on('data', (chunk: Buffer) => capture('stderr', chunk));
      child.once('error', (error) => {
        spawnError = error;
      });

      child.once('close', (code, signal) => {
        if (settled) return;
        settled = true;
        clearTimeout(timeout);
        if (killTimer) clearTimeout(killTimer);
        options.signal?.removeEventListener('abort', onAbort);
        const durationMs = Date.now() - started;
        this.#activeExecutions -= 1;
        stdout += stdoutDecoder.end();
        stderr += stderrDecoder.end();

        let failure: Error | undefined;
        if (spawnError) failure = new ProcessSpawnError(`failed to spawn ${command}`, { cause: spawnError });
        else if (terminationReason === 'aborted') failure = new ExecutionAbortedError(`execution aborted: ${command}`);
        else if (terminationReason === 'timeout') failure = new ExecutionTimeoutError(`execution exceeded timeout of ${timeoutMs}ms: ${command}`);
        else if (terminationReason === 'output') failure = new OutputLimitError(`captured output exceeded ${maxOutputBytes} bytes: ${command}`);

        if (failure) {
          this.#audit({
            type: 'execution.failed',
            timestamp: new Date().toISOString(),
            ...auditBase(decision),
            durationMs,
            exitCode: code,
            signal,
            reason: failure.message,
          });
          reject(failure);
          return;
        }

        const result: ExecutionResult = {
          ...decision,
          stdout,
          stderr,
          exitCode: code,
          signal,
          durationMs,
          dryRun: false,
        };
        this.#audit({
          type: 'execution.completed',
          timestamp: new Date().toISOString(),
          ...auditBase(decision),
          durationMs,
          exitCode: code,
          signal,
        });
        resolve(result);
      });
    });
  }
}

/** Create a policy-gated process executor. */
export function createExecPolicy(options: Readonly<ExecPolicyOptions>): ExecPolicy {
  return new ExecPolicy(options);
}

export { PolicyDeniedError };
