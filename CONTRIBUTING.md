# Contributing

Open Security is a community-maintained fork of
[OpenAI's Codex Security](https://github.com/openai/codex-security). Issues and
pull requests are welcome in this repository.

The fork keeps inherited runtime identifiers such as `codex-security`, its
artifact schemas, and legacy environment variables stable. Avoid renaming those
contracts unless the change includes a compatibility and migration plan. This
keeps existing scan history usable and makes upstream updates easier to merge.

## Report a bug

Search [existing GitHub issues](https://github.com/masonjames/open-security/issues)
before opening a new one. Include the installed CLI or SDK version, operating
system, reproduction steps, expected behavior, and the observed result.

Remove API keys, access tokens, repository contents, security findings, and
other sensitive information from public reports. Report security vulnerabilities
privately as described in [SECURITY.md](SECURITY.md).

## Make a change

Create a focused branch, keep unrelated changes out of the commit, and run the
TypeScript checks from the repository root:

```bash
corepack enable
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run types
pnpm --dir sdk/typescript run test
pnpm --dir sdk/typescript run format
pnpm --dir sdk/typescript run build
```

Changes to published package contents should also be packed and validated:

```bash
mkdir -p dist
pnpm --dir sdk/typescript pack --pack-destination ../../dist
pnpm --dir sdk/typescript run check:package ../../dist/*.tgz
```

Tests must not use real provider credentials or make billable model requests.
Use synthetic credentials and injected network dependencies.

## Keep up with upstream

The recommended remotes are `origin` for this fork and `upstream` for OpenAI's
repository:

```bash
git remote add upstream https://github.com/openai/codex-security.git
git fetch upstream
```

Review upstream changes before merging them into a feature branch. Preserve
fork-specific provider behavior and resolve conflicts deliberately; a clean
merge does not by itself prove that provider authentication, pricing, or secret
isolation still works.

## Dependency and release maintenance

Commit dependency and lockfile changes together. Do not use forceful automated
dependency upgrades without reviewing the resulting graph and tests.

The tag workflow builds and verifies a package artifact but does not publish to
npm. Publishing requires a separate, explicitly authorized release process.
