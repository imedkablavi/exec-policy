# Contributing

Contributions are welcome when they keep the package small, explicit and security-focused.

## Before opening a pull request

- keep `shell: false` as a non-negotiable default;
- avoid new runtime dependencies unless there is a strong security or maintenance reason;
- preserve fail-closed authorization behavior and the destructive default for unclassified commands;
- add regression coverage for policy or process-control changes, including a Windows/macOS case when behavior is platform-specific;
- do not add logging that exposes raw environment values or raw argv to audit events;
- document any new trust boundary or security limitation.

Run locally:

```bash
npm ci
npm run typecheck
npm test
npm run test:package
npm pack --dry-run
```

For security vulnerabilities, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.
