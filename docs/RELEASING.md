# Releasing

Releases are deliberately tied to the package version and the Git tag so the published artifact can be reproduced and verified.

## Release checklist

1. Update `version` in `package.json` and the root version in `package-lock.json` to the exact release version.
2. Add the release notes to `CHANGELOG.md`.
3. Run the local release gates:

```bash
npm ci
npm run typecheck
npm test
npm run test:coverage
npm run test:package
npm run security:check
npm pack --dry-run
```

4. Merge the release changes to `main`.
5. Create a Git tag in the form `vX.Y.Z` from the release commit.
6. Create and publish the matching GitHub Release.
7. The `publish-npm.yml` workflow verifies the tag/version match, re-runs the package checks and publishes to npm using Trusted Publishing/OIDC.
8. Confirm the exact `@imedkablavi/exec-policy@X.Y.Z` version is visible on npm after publication.

## Manual workflow dispatch

`Publish npm Package` also supports `workflow_dispatch`. The input version must exactly match the `package.json` version. This path is useful when a release object is not being created, but the same validation and package verification still run.

## Publishing rules

Never reuse an already published version. npm package versions are immutable in normal use, and the workflow intentionally skips an immutable republish when the requested version already exists.

Do not commit npm tokens. The workflow uses npm Trusted Publishing with GitHub Actions OIDC rather than a long-lived registry token.

## Pre-release versions

Use npm's normal semver pre-release identifiers for release candidates, for example `0.2.0-rc.1`. The GitHub Release tag must still match the package version exactly when using the release-triggered publication path.
