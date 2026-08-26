export class ExecPolicyError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export class PolicyDeniedError extends ExecPolicyError {}
export class ApprovalRequiredError extends ExecPolicyError {}
export class ApprovalDeniedError extends ExecPolicyError {}
export class ExecutableResolutionError extends ExecPolicyError {}
export class ExecutionTimeoutError extends ExecPolicyError {}
export class ExecutionAbortedError extends ExecPolicyError {}
export class OutputLimitError extends ExecPolicyError {}
export class ProcessSpawnError extends ExecPolicyError {}
export class ConcurrencyLimitError extends ExecPolicyError {}
