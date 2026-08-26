# Architecture

The package is intentionally split into a small authorization path and a process runner.

## Policy preparation

`createExecPolicy()` snapshots the supplied command rules and policy arrays so later mutation by application code cannot silently weaken an existing policy instance.

## Preview path

`preview()` performs the security-sensitive checks before execution:

1. validate the logical command and select it through an own-property lookup on a null-prototype map;
2. freeze and validate argv;
3. canonicalize configured roots and requested cwd;
4. enforce cwd containment;
5. build and snapshot the minimal child environment, enforcing per-value and total byte ceilings;
6. resolve the executable from absolute `PATH` entries only and optionally enforce trusted executable roots;
7. classify risk, defaulting unclassified commands to destructive, and calculate approval requirements;
8. validate per-execution resource overrides as tighten-only limits;
9. calculate a non-secret argv fingerprint for audit correlation.

## Execution path

`run()` reuses the preview decision, obtains approval when required, then launches the resolved executable through `child_process.spawn()` with an argv array and `shell: false`.

The child has bounded captured output, a timeout, optional `AbortSignal` cancellation and a per-policy direct-child concurrency ceiling. Termination reasons are first-wins so an output overflow, timeout and abort cannot race to produce a misleading error classification.

## Audit path

Audit events intentionally contain no raw argv array and no environment values. They use `argvSha256` plus command metadata for correlation. Audit delivery is non-blocking and best-effort so a logging backend cannot influence authorization or process scheduling.

The approval callback is different: it receives raw argv so a trusted approver can make a decision. Approval exceptions and non-boolean responses fail closed.


## Cross-platform boundary

The implementation uses Node.js process APIs without a shell. On Windows this deliberately excludes `.bat`/`.cmd` policy targets because those require shell mediation. Linux is the local development environment; CI is configured to qualify Node 24 on macOS and Windows in addition to the Node 20/22/24 Linux matrix.
