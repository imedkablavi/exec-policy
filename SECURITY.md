# Security Policy

## Reporting a vulnerability

Please do not open a public GitHub issue for a suspected vulnerability that could expose users to command execution, policy bypass, path-boundary escape, secret disclosure or another security impact.

Use GitHub's private vulnerability reporting for the repository when available. Include:

- affected version
- minimal reproduction
- expected policy decision
- actual behavior
- platform and Node.js version
- security impact

Do not include real credentials or private production data in reports.

## Security-sensitive areas

Changes to the following require especially careful review:

- executable resolution
- cwd canonicalization and containment
- argument validation
- environment inheritance/overrides, snapshot timing and byte ceilings
- approval behavior
- child-process termination, concurrency accounting and termination-reason races
- command-map/prototype-boundary handling
- cross-platform executable resolution
- audit redaction guarantees

## Supported versions

Until the project reaches 1.0, security fixes are provided for the latest published minor line only.

## Disclosure expectations

Security reports are especially useful when they demonstrate an authorization bypass, executable-resolution bypass, cwd boundary escape, unexpected shell invocation, environment disclosure, approval fail-open behavior or audit-data exposure. Please use synthetic credentials and disposable paths in reproductions.
