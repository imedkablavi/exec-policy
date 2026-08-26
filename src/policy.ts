import { access, realpath, stat } from 'node:fs/promises';
import { constants as fsConstants } from 'node:fs';
import { createHash } from 'node:crypto';
import path from 'node:path';
import process from 'node:process';
import {
  ExecutableResolutionError,
  PolicyDeniedError,
} from './errors.js';
import type {
  ApprovalMode,
  AuditEvent,
  CommandRule,
  ExecPolicyOptions,
  ExecutionOptions,
  PreviewDecision,
  RiskLevel,
} from './types.js';

const ENV_KEY = /^[A-Za-z_][A-Za-z0-9_]*$/;
const SAFE_COMMAND_KEY = /^[A-Za-z0-9._+-]+$/;
const MAX_COMMAND_KEY_BYTES = 128;
const RESERVED_COMMAND_KEYS = new Set(['__proto__', 'prototype', 'constructor']);
const WINDOWS_DIRECT_EXECUTABLE_EXTENSIONS = new Set(['.exe', '.com']);

function positiveInteger(value: number, name: string, max: number): number {
  if (!Number.isInteger(value) || value <= 0 || value > max) {
    throw new RangeError(`${name} must be an integer between 1 and ${max}`);
  }
  return value;
}

function validateRisk(value: RiskLevel): RiskLevel {
  if (value !== 'read' && value !== 'write' && value !== 'destructive') {
    throw new TypeError(`invalid risk level: ${String(value)}`);
  }
  return value;
}

function validateApproval(value: ApprovalMode): ApprovalMode {
  if (!['never', 'write', 'destructive', 'always'].includes(value)) {
    throw new TypeError(`invalid approval mode: ${String(value)}`);
  }
  return value;
}

function approvalNeeded(mode: ApprovalMode, risk: RiskLevel): boolean {
  if (mode === 'always') return true;
  if (mode === 'never') return false;
  if (mode === 'destructive') return risk === 'destructive';
  return risk === 'write' || risk === 'destructive';
}

function isInside(root: string, candidate: string): boolean {
  const relative = path.relative(root, candidate);
  return relative === '' || (!relative.startsWith(`..${path.sep}`) && relative !== '..' && !path.isAbsolute(relative));
}

function validateEnvKeys(keys: readonly string[], name: string): readonly string[] {
  const unique = [...new Set(keys)];
  for (const key of unique) {
    if (!ENV_KEY.test(key)) throw new TypeError(`${name} contains invalid environment key: ${key}`);
  }
  return unique;
}

function validateExecutableText(executable: string): void {
  if (typeof executable !== 'string' || !executable || /[\u0000-\u001f\u007f]/.test(executable)) {
    throw new PolicyDeniedError('executable contains control characters or is not a string');
  }
  if (!path.isAbsolute(executable) && (!SAFE_COMMAND_KEY.test(executable) || executable.includes('/') || executable.includes('\\'))) {
    throw new PolicyDeniedError(`bare executable name is not safe: ${executable}`);
  }
  if (process.platform === 'win32' && path.isAbsolute(executable)) {
    const extension = path.extname(executable).toLowerCase();
    if (extension && !WINDOWS_DIRECT_EXECUTABLE_EXTENSIONS.has(extension)) {
      throw new PolicyDeniedError(`Windows shell-script executables are not supported with shell:false: ${extension}`);
    }
  }
}

function isSafeCommandKey(command: string): boolean {
  return SAFE_COMMAND_KEY.test(command) && Buffer.byteLength(command, 'utf8') <= MAX_COMMAND_KEY_BYTES;
}

function validateCommandRequest(command: string): void {
  if (typeof command !== 'string' || !isSafeCommandKey(command)) {
    throw new PolicyDeniedError('command key is not a safe logical command name');
  }
  if (RESERVED_COMMAND_KEYS.has(command)) {
    throw new PolicyDeniedError(`reserved command key is not allowed: ${command}`);
  }
}

async function executableCandidate(candidate: string): Promise<string | null> {
  try {
    const canonical = await realpath(candidate);
    const info = await stat(canonical);
    if (!info.isFile()) return null;
    if (process.platform !== 'win32') await access(canonical, fsConstants.X_OK);
    return canonical;
  } catch {
    return null;
  }
}

async function resolveExecutable(executable: string, pathValue: string | undefined): Promise<string> {
  validateExecutableText(executable);
  if (process.platform === 'win32' && !path.isAbsolute(executable)) {
    const explicitExtension = path.extname(executable).toLowerCase();
    if (explicitExtension && !WINDOWS_DIRECT_EXECUTABLE_EXTENSIONS.has(explicitExtension)) {
      throw new PolicyDeniedError(`Windows shell-script executables are not supported with shell:false: ${explicitExtension}`);
    }
  }
  if (path.isAbsolute(executable)) {
    const resolved = await executableCandidate(executable);
    if (!resolved) throw new ExecutableResolutionError(`executable is not an accessible file: ${executable}`);
    return resolved;
  }

  if (!pathValue) throw new ExecutableResolutionError(`cannot resolve ${executable}: PATH is not inherited`);
  const extensions = process.platform === 'win32'
    ? (process.env.PATHEXT ?? '.EXE;.COM')
      .split(';')
      .map((value) => value.trim().toLowerCase())
      .filter((value) => WINDOWS_DIRECT_EXECUTABLE_EXTENSIONS.has(value))
    : [''];

  let sawAbsolutePathEntry = false;
  for (const rawEntry of pathValue.split(path.delimiter)) {
    let entry = rawEntry.trim();
    if (entry.length >= 2 && entry.startsWith('"') && entry.endsWith('"')) entry = entry.slice(1, -1);
    if (!entry || !path.isAbsolute(entry)) continue;
    sawAbsolutePathEntry = true;
    for (const extension of extensions) {
      const suffix = process.platform === 'win32' && !path.extname(executable) ? extension : '';
      const resolved = await executableCandidate(path.join(entry, `${executable}${suffix}`));
      if (resolved) return resolved;
    }
  }
  if (!sawAbsolutePathEntry) {
    throw new ExecutableResolutionError(`cannot resolve ${executable}: inherited PATH contains no absolute entries`);
  }
  throw new ExecutableResolutionError(`executable not found on inherited PATH: ${executable}`);
}

function validateArgs(args: readonly string[], maxArgs: number, maxArgBytes: number, maxTotalArgBytes: number, rule: Readonly<CommandRule>): void {
  if (args.length > maxArgs) throw new PolicyDeniedError(`argument count exceeds policy limit (${maxArgs})`);
  let totalArgBytes = 0;
  for (const arg of args) {
    if (typeof arg !== 'string') throw new PolicyDeniedError('all arguments must be strings');
    if (arg.includes('\u0000')) throw new PolicyDeniedError('arguments must not contain NUL bytes');
    const argBytes = Buffer.byteLength(arg, 'utf8');
    if (argBytes > maxArgBytes) {
      throw new PolicyDeniedError(`argument exceeds policy byte limit (${maxArgBytes})`);
    }
    totalArgBytes += argBytes;
    if (totalArgBytes > maxTotalArgBytes) {
      throw new PolicyDeniedError(`combined argument bytes exceed policy limit (${maxTotalArgBytes})`);
    }
    for (const pattern of rule.denyArgPatterns ?? []) {
      pattern.lastIndex = 0;
      if (pattern.test(arg)) throw new PolicyDeniedError(`argument rejected by command policy`);
    }
  }
  const validation = rule.validateArgs?.(args);
  if (validation === false) throw new PolicyDeniedError('arguments rejected by command policy');
  if (typeof validation === 'string') throw new PolicyDeniedError(validation);
  if (validation !== undefined && validation !== true) {
    throw new PolicyDeniedError('argument validator returned an unsupported value; async validators are not supported');
  }
}

function argvDigest(command: string, executable: string, args: readonly string[]): string {
  const hash = createHash('sha256');
  for (const part of [command, executable, ...args]) {
    const bytes = Buffer.from(part, 'utf8');
    hash.update(String(bytes.byteLength));
    hash.update('\0');
    hash.update(bytes);
    hash.update('\0');
  }
  return hash.digest('hex');
}

export interface PreparedPolicy {
  options: Readonly<ExecPolicyOptions>;
  defaultApproval: ApprovalMode;
  timeoutMs: number;
  maxOutputBytes: number;
  maxArgs: number;
  maxArgBytes: number;
  maxTotalArgBytes: number;
  maxEnvValueBytes: number;
  maxEnvBytes: number;
  maxConcurrent: number;
  inheritEnv: readonly string[];
  envOverrideAllowlist: readonly string[];
  allowedCwdRoots: readonly string[];
  trustedExecutableRoots: readonly string[];
}

export function preparePolicy(options: Readonly<ExecPolicyOptions>): PreparedPolicy {
  if (!options.commands || Object.keys(options.commands).length === 0) {
    throw new TypeError('commands must contain at least one allowed command');
  }

  const commands = Object.create(null) as Record<string, Readonly<CommandRule>>;
  for (const [command, rule] of Object.entries(options.commands)) {
    if (!isSafeCommandKey(command) || RESERVED_COMMAND_KEYS.has(command)) throw new TypeError(`invalid command key: ${command}`);
    if (rule.defaultRisk !== undefined) validateRisk(rule.defaultRisk);
    if (rule.approval !== undefined) validateApproval(rule.approval);
    if (rule.executable !== undefined) validateExecutableText(rule.executable);
    const denyArgPatterns = (rule.denyArgPatterns ?? []).map((pattern) => {
      if (!(pattern instanceof RegExp)) throw new TypeError(`denyArgPatterns for ${command} must contain RegExp values`);
      return new RegExp(pattern.source, pattern.flags);
    });
    commands[command] = Object.freeze({
      ...rule,
      ...(denyArgPatterns.length ? { denyArgPatterns: Object.freeze(denyArgPatterns) } : {}),
    });
  }

  const snapshotOptions = Object.freeze({
    ...options,
    commands: Object.freeze(commands),
    ...(options.allowedCwdRoots ? { allowedCwdRoots: Object.freeze([...options.allowedCwdRoots]) } : {}),
    ...(options.trustedExecutableRoots ? { trustedExecutableRoots: Object.freeze([...options.trustedExecutableRoots]) } : {}),
    ...(options.inheritEnv ? { inheritEnv: Object.freeze([...options.inheritEnv]) } : {}),
    ...(options.envOverrideAllowlist ? { envOverrideAllowlist: Object.freeze([...options.envOverrideAllowlist]) } : {}),
  }) as Readonly<ExecPolicyOptions>;

  const allowedCwdRoots = snapshotOptions.allowedCwdRoots?.length ? [...snapshotOptions.allowedCwdRoots] : [process.cwd()];
  const trustedExecutableRoots = snapshotOptions.trustedExecutableRoots?.length ? [...snapshotOptions.trustedExecutableRoots] : [];
  for (const root of [...allowedCwdRoots, ...trustedExecutableRoots]) {
    if (!path.isAbsolute(root)) throw new TypeError(`policy roots must be absolute paths: ${root}`);
  }

  return {
    options: snapshotOptions,
    defaultApproval: validateApproval(snapshotOptions.approval ?? 'destructive'),
    timeoutMs: positiveInteger(snapshotOptions.timeoutMs ?? 30_000, 'timeoutMs', 3_600_000),
    maxOutputBytes: positiveInteger(snapshotOptions.maxOutputBytes ?? 1_048_576, 'maxOutputBytes', 134_217_728),
    maxArgs: positiveInteger(snapshotOptions.maxArgs ?? 128, 'maxArgs', 4096),
    maxArgBytes: positiveInteger(snapshotOptions.maxArgBytes ?? 16_384, 'maxArgBytes', 1_048_576),
    maxTotalArgBytes: positiveInteger(snapshotOptions.maxTotalArgBytes ?? 131_072, 'maxTotalArgBytes', 16_777_216),
    maxEnvValueBytes: positiveInteger(snapshotOptions.maxEnvValueBytes ?? 65_536, 'maxEnvValueBytes', 1_048_576),
    maxEnvBytes: positiveInteger(snapshotOptions.maxEnvBytes ?? 262_144, 'maxEnvBytes', 16_777_216),
    maxConcurrent: positiveInteger(snapshotOptions.maxConcurrent ?? 16, 'maxConcurrent', 1024),
    inheritEnv: validateEnvKeys(snapshotOptions.inheritEnv ?? ['PATH'], 'inheritEnv'),
    envOverrideAllowlist: validateEnvKeys(snapshotOptions.envOverrideAllowlist ?? [], 'envOverrideAllowlist'),
    allowedCwdRoots,
    trustedExecutableRoots,
  };
}

async function canonicalRoots(roots: readonly string[]): Promise<readonly string[]> {
  const result: string[] = [];
  for (const root of roots) {
    try {
      result.push(await realpath(root));
    } catch (error) {
      throw new PolicyDeniedError(`configured policy root does not exist: ${root}`, { cause: error });
    }
  }
  return result;
}

function validateExecutionOverrides(policy: PreparedPolicy, execution: Readonly<ExecutionOptions>): void {
  if (execution.timeoutMs !== undefined) {
    const timeout = positiveInteger(execution.timeoutMs, 'timeoutMs', 3_600_000);
    if (timeout > policy.timeoutMs) throw new PolicyDeniedError(`timeoutMs override cannot exceed policy limit (${policy.timeoutMs})`);
  }
  if (execution.maxOutputBytes !== undefined) {
    const output = positiveInteger(execution.maxOutputBytes, 'maxOutputBytes', 134_217_728);
    if (output > policy.maxOutputBytes) throw new PolicyDeniedError(`maxOutputBytes override cannot exceed policy limit (${policy.maxOutputBytes})`);
  }
}

export async function buildEnvironment(policy: PreparedPolicy, overrides: ExecutionOptions['env']): Promise<NodeJS.ProcessEnv> {
  const env: NodeJS.ProcessEnv = {};
  for (const key of policy.inheritEnv) {
    const value = process.env[key];
    if (value !== undefined) env[key] = value;
  }
  if (overrides) {
    const allowed = new Set(policy.envOverrideAllowlist);
    for (const [key, value] of Object.entries(overrides)) {
      if (!ENV_KEY.test(key)) throw new PolicyDeniedError(`invalid environment key: ${key}`);
      if (!allowed.has(key)) throw new PolicyDeniedError(`environment override is not allowed: ${key}`);
      if (value === undefined) delete env[key];
      else {
        if (typeof value !== 'string') throw new PolicyDeniedError(`environment value must be a string: ${key}`);
        if (value.includes('\u0000')) throw new PolicyDeniedError(`environment value contains NUL byte: ${key}`);
        env[key] = value;
      }
    }
  }
  let totalBytes = 0;
  for (const [key, value] of Object.entries(env)) {
    if (value === undefined) continue;
    const valueBytes = Buffer.byteLength(value, 'utf8');
    if (valueBytes > policy.maxEnvValueBytes) {
      throw new PolicyDeniedError(`environment value exceeds policy byte limit (${policy.maxEnvValueBytes}): ${key}`);
    }
    totalBytes += Buffer.byteLength(key, 'utf8') + valueBytes + 2;
    if (totalBytes > policy.maxEnvBytes) {
      throw new PolicyDeniedError(`combined environment bytes exceed policy limit (${policy.maxEnvBytes})`);
    }
  }
  return env;
}

export interface PreparedExecution {
  decision: PreviewDecision;
  env: NodeJS.ProcessEnv;
}

export async function prepareExecution(
  policy: PreparedPolicy,
  command: string,
  args: readonly string[],
  execution: Readonly<ExecutionOptions>,
): Promise<PreparedExecution> {
  validateExecutionOverrides(policy, execution);
  validateCommandRequest(command);
  if (!Array.isArray(args)) throw new PolicyDeniedError('arguments must be provided as an array of strings');
  // Reject oversized arrays before cloning them so maxArgs also acts as a memory/CPU guard.
  if (args.length > policy.maxArgs) throw new PolicyDeniedError(`argument count exceeds policy limit (${policy.maxArgs})`);
  if (!Object.hasOwn(policy.options.commands, command)) throw new PolicyDeniedError(`command is not allowed by policy: ${command}`);
  const rule = policy.options.commands[command]!;
  const safeArgs = Object.freeze([...args]);
  validateArgs(safeArgs, policy.maxArgs, policy.maxArgBytes, policy.maxTotalArgBytes, rule);

  const cwdRoots = await canonicalRoots(policy.allowedCwdRoots);
  const requestedCwd = execution.cwd ?? cwdRoots[0]!;
  if (typeof requestedCwd !== 'string') throw new PolicyDeniedError('working directory must be a string');
  let cwd: string;
  try {
    cwd = await realpath(requestedCwd);
  } catch (error) {
    throw new PolicyDeniedError(`working directory does not exist: ${requestedCwd}`, { cause: error });
  }
  if (!cwdRoots.some((root) => isInside(root, cwd))) {
    throw new PolicyDeniedError(`working directory is outside allowed roots: ${requestedCwd}`);
  }

  const env = await buildEnvironment(policy, execution.env);
  const executable = rule.executable ?? command;
  const resolvedExecutable = await resolveExecutable(executable, env.PATH);

  if (policy.trustedExecutableRoots.length > 0) {
    const roots = await canonicalRoots(policy.trustedExecutableRoots);
    if (!roots.some((root) => isInside(root, resolvedExecutable))) {
      throw new PolicyDeniedError(`resolved executable is outside trusted roots: ${resolvedExecutable}`);
    }
  }

  const risk = validateRisk(rule.classify?.(safeArgs) ?? rule.defaultRisk ?? 'destructive');
  const mode = validateApproval(rule.approval ?? policy.defaultApproval);
  const decision: PreviewDecision = {
    allowed: true,
    command,
    executable,
    resolvedExecutable,
    args: safeArgs,
    cwd,
    risk,
    requiresApproval: approvalNeeded(mode, risk),
    argvSha256: argvDigest(command, resolvedExecutable, safeArgs),
  };
  return { decision, env: { ...env } };
}

export async function previewExecution(
  policy: PreparedPolicy,
  command: string,
  args: readonly string[],
  execution: Readonly<ExecutionOptions>,
): Promise<PreviewDecision> {
  return (await prepareExecution(policy, command, args, execution)).decision;
}

export function auditBase(decision: PreviewDecision): Pick<AuditEvent, 'command' | 'resolvedExecutable' | 'cwd' | 'risk' | 'argvSha256' | 'argCount'> {
  return {
    command: decision.command,
    resolvedExecutable: decision.resolvedExecutable,
    cwd: decision.cwd,
    risk: decision.risk,
    argvSha256: decision.argvSha256,
    argCount: decision.args.length,
  };
}
