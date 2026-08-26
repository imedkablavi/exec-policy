# Threat Model

## Purpose

`@imedkablavi/exec-policy` is an application-layer authorization gate for launching operating-system processes from Node.js. It is designed to make command execution explicit, reviewable and bounded.

It is not a sandbox and does not claim to contain a compromised or malicious executable.

## Assets

The package aims to protect:

- the host filesystem reachable by the parent process
- credentials and configuration in the parent environment
- application integrity against arbitrary command selection
- operator control over destructive operations
- service availability against runaway children/output
- audit logs from unnecessary raw argv/environment duplication

## Trust boundaries

### Application code

The application creating the policy is trusted to define correct allowlists, argument rules and approval logic.

### Command arguments

Arguments may be partially or fully influenced by untrusted input. The package passes arguments directly to `spawn()` without a shell, but an allowed executable may itself interpret dangerous arguments. Command-specific `validateArgs` rules are required when this matters.

### Executables and PATH

A bare executable name is resolved from the inherited `PATH`. If an attacker can replace binaries in that path, executable allowlisting by name is insufficient. High-trust deployments should pin absolute executable paths and/or `trustedExecutableRoots`.

### Approval handler

The approval callback receives raw arguments and is trusted not to leak secrets or approve unsafe operations.

### Child process

Once launched, the child executes with the operating-system privileges, filesystem access and network access of the parent process, subject only to external OS/container controls.

## Security properties

The package attempts to enforce:

1. only configured logical command keys can be requested, using own-property lookup on a null-prototype command map;
2. execution uses argv arrays and `shell: false`;
3. requested cwd is canonicalized and must remain under an allowed canonical root;
4. bare executable resolution ignores relative `PATH` entries and caller environment overrides are denied unless explicitly allowed;
5. unclassified commands fail closed to `destructive` risk, and destructive/write operations can require explicit approval;
6. time, captured-output, argv/environment-size and per-policy direct-child concurrency limits bound common resource-exhaustion paths;
7. audit events do not include raw argv or environment values;
8. approval-handler failures are converted into a typed denial and configuration/authorization failures are fail-closed.

## Non-goals and limitations

The package does not provide:

- syscall filtering
- Linux namespaces
- containers or VMs
- filesystem mounts/chroots
- network egress filtering
- host-wide resource limits for CPU/RAM/process count
- semantic safety guarantees for every allowed executable
- protection from a malicious executable already trusted by policy
- complete prevention of secrets appearing in child stdout/stderr
- recursive termination of every descendant process created by the direct child

`stdout` and `stderr` are returned to the caller. If a child prints a secret, application code must handle that output appropriately.

## Symlink and path handling

Cwd roots and requested cwd values are resolved through `realpath()` before containment checks. This prevents a simple symlink inside an allowed root from redirecting cwd outside the root at authorization time.

This does not freeze the filesystem after the check. OS-level isolation is required for adversarial filesystem race conditions.

## Denial of service

Timeouts, captured-output limits, argv/environment byte ceilings and `maxConcurrent` reduce several application-layer resource-exhaustion cases. The concurrency limit applies only to direct children launched through one `ExecPolicy` instance. It does not cap CPU, memory, open files, descendant process count, network usage or processes launched through other policy instances. Use OS/container resource controls for those properties.

## Windows shell-script boundary

On Windows, `.bat` and `.cmd` files require a command shell. The package intentionally refuses to treat them as direct executables because enabling a shell would weaken the core `shell: false` property. Policy targets should resolve to directly executable files such as `.exe`/`.com`.

## Executable replacement races

Executable paths are canonicalized before spawn, but this package does not lock or cryptographically pin executable file contents between authorization and process creation. An attacker who can replace a trusted executable on disk already controls a powerful host boundary. Protect trusted executable directories with operating-system permissions, immutable images, package verification or other host controls.

## Approval and audit callbacks

Approval code is trusted security policy. If it throws, execution fails closed with `ApprovalDeniedError`. Audit callbacks are observational: their failures are intentionally swallowed so a logging outage cannot silently change authorization or process control. Applications that require guaranteed audit delivery should provide a durable sink outside the authorization decision itself.

## Environment snapshot

The child environment is constructed and snapshotted during authorization before an approval callback runs. Mutating `process.env` while approval is pending does not change the environment later passed to the approved child. This prevents approval from authorizing one inherited-environment state while execution receives another.
