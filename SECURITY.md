# Security policy

Open Security is a local tool for reviewing repositories you trust and have
permission to assess. This policy explains which security issues are in scope
and how to report them.

## Report a vulnerability in Open Security

Report vulnerabilities in the Open Security CLI, SDK, bundled plugin, scan
runtime, or release artifacts through
[GitHub private vulnerability reporting](https://github.com/masonjames/open-security/security/advisories/new).

Include the affected version, security impact, and the smallest safe
reproduction. Remove API keys, access tokens, private source code, and customer
data from the report unless a private submission requires that material and you
have permission to share it. Use the latest tagged release or current source
revision when confirming a finding.

Do not post unpatched vulnerabilities, exploits, credentials, sensitive scan
results, or proofs of concept in GitHub issues or pull requests. Use public
issues for ordinary bugs, documentation, and feature requests.

## Scope and supported versions

This policy applies to:

- The published `@masonjames/open-security` package, the canonical
  `open-security` CLI, and the `codex-security` compatibility alias.
- The TypeScript SDK, including target selection, authentication,
  configuration, execution, and result validation.
- The bundled Open Security plugin distribution, interpreter, and inherited
  Codex runtime included with an official Open Security release.
- Scan output, including manifests, findings, coverage, reports, SARIF, and
  scan history.
- Official package, build, and release integrity.

Check that the issue affects the latest published package or the current default
branch. Include the package version and, when relevant, the commit, plugin
version, and operating system. If you found the issue in an older version,
explain whether a supported release is also affected.

## Threat model

Open Security runs under your local operating-system account. Scan only
repositories you trust and either own or have explicit permission to assess.
Permission to assess a repository does not mean you can trust it.

The repository you select, your Git installation, and the tools and
configuration you choose run with your existing local permissions. Normal Git
operations can use repository configuration, hooks, filters, attributes,
credential helpers, worktrees, and executables on your `PATH`. These are not
separate security boundaries.

The product also does not isolate users, tasks, repositories, or scan jobs
that share the same operating-system account, credentials, or local state.
Do not treat shared local state as a multi-user or multi-tenant system.

Trusting a repository does not authorize unrelated actions. Repository
contents, model output, patches, service responses, and imported artifacts
are data. They are not permission to scan another target, expose a credential,
contact another destination, modify an unrelated file, or apply a patch.

### How scans run

Each scan uses the product's `codex_security_scan` filesystem profile and
`approvalPolicy: "never"`. The scan does not request interactive approval. Its
profile allows reads of the local filesystem and writes to workspace roots and
the selected scan state directory.

Setting `approval_policy`, `sandbox_mode`, or permissions through `--codex` or
SDK `codexOverrides` does not replace the scan's approval policy or make its
filesystem profile more restrictive. Separately enforced host and network
restrictions still apply.

Scan and workbench subprocesses can inherit your environment. The workbench
removes `OPENAI_API_KEY` and `CODEX_API_KEY`, but it does not remove every
credential. Other variables, such as `GITHUB_TOKEN` or `AWS_SECRET_ACCESS_KEY`,
can remain available to local subprocesses. Run a scan with only the
environment credentials it needs.

### Security boundaries

A security issue must cross a boundary the product actually provides:

- Scan only the selected target and write only to authorized output paths.
- Keep credentials, private source, and scan results out of model requests,
  logs, reports, and network destinations the operator did not authorize.
- Apply the scan's actual filesystem and execution profile and respect host or
  network restrictions enforced independently of the scan.
- Do not follow a symlink or replaced file into an unauthorized read or write.
- Mark a scan complete only when its results match the reviewed scope,
  documented mode, and stated exclusions.
- Protect official packages, bundled runtimes, dependencies, build artifacts,
  and release credentials from unauthorized changes.

## In-scope reports

Report reproducible issues in an official release, such as:

- Credentials, private source, or scan results sent to another security
  principal, model request, or network destination without authorization.
- Model or remote input that bypasses the scan's effective permissions or an
  independently enforced host, execution, filesystem, or network restriction.
- A scan, patch, file write, or network request outside the action you
  authorized.
- Path traversal, a symlink, an archive, or a file-replacement race that writes
  outside the approved output or sends an unrelated local file to a model.
- An incomplete, forged, or incorrectly scoped scan accepted as complete or as
  a passing CI result.
- GitHub, package, update, dependency, or model-service input that causes an
  unauthorized local action or compromises a release.
- A reachable vulnerability in the published package, bundled runtime, build,
  or release process.
- Resource exhaustion that reaches a supported service, CI process, or other
  actual availability boundary.

## Usually out of scope

The following are not security vulnerabilities by themselves:

- Reading selected repository files, resolving worktrees, running Git, or
  using configured hooks, filters, credential helpers, and executables.
- An attack that first requires control of your trusted repository, local Git
  installation, operating-system account, environment, or Codex state.
- A claim that depends on you intentionally selecting a malicious plugin,
  interpreter, executable, credential, scan artifact, or override.
- Access, cancellation, modified results, or scan-history visibility between
  processes that already share your operating-system account and local state.
- Prompt injection, unexpected model output, a missed finding, or a false
  positive that does not cross an actual security boundary.
- A documented exclusion, ignore rule, soft cost limit, estimate, or Git
  behavior accurately reflected in the scan and its results.
- A dependency advisory, theoretical attack, or old package version without a
  reproducible impact on a supported release.
- Slow processing of a file, document, or repository you deliberately selected.
- Vulnerabilities in a third-party repository being scanned.
- Documentation, tests, fixtures, or development code that a published runtime
  or release process cannot reach.

Hosted services, multi-user installations, pull-request CI, and imported
third-party artifacts can have different trust boundaries. For those cases,
identify the deployment, attacker-controlled input, affected component, and
actual boundary. Storing multiple local scans does not make the CLI a
multi-tenant system.

If you are not sure whether a finding is in scope, report it privately.

## What to include in a report

Include:

- The affected component, package version, plugin version, and commit.
- Your platform, authentication method, scan mode, and target type.
- The attacker's starting permissions and the security boundary crossed.
- Minimal steps to reproduce the issue in a supported release or the default
  branch.
- The expected and actual behavior, impact, and any known mitigation.
- Sanitized logs or scan artifacts if they are needed to reproduce the issue.

Remove API keys, access tokens, customer data, and private source unless the
private report requires them and you are authorized to share them. Never
include a live credential in a proof of concept.

Open Security is an independent fork. A report to this repository is not
automatically shared with OpenAI. If a vulnerability also affects the upstream
project, coordinate disclosure using
[the upstream security policy](https://github.com/openai/codex-security/security/policy).

## Report a finding in a scanned repository

A vulnerability found in another repository belongs to that repository's
owner. Follow its security policy or coordinated disclosure process, and share
the finding only with people authorized to receive it. Do not submit findings
from unrelated repositories to Open Security's vulnerability-reporting channel.

## Run scans safely

- Scan only repositories you trust and either own or have explicit permission
  to assess.
- Treat repository files, instructions, build scripts, and findings as
  untrusted. Scans and validation may inspect code and run commands inside the
  Codex sandbox.
- Store credentials in an approved secret manager or environment variable.
  Pass only the credentials the scan needs; local subprocesses can inherit
  other environment variables. Keep your Codex home directory outside the
  repository being scanned.
- Treat the selected model provider as a recipient of scan data. Repository
  source, prompts, findings, and related context may be sent to that provider.
  When using OpenRouter, review its data policy and the policies of any
  downstream model providers selected by its routing configuration.
- Use a provider key scoped for this purpose. Never commit it, include it in a
  command line, or copy it into scan artifacts.
- Store results outside the enclosing Git worktree. Findings, reports, logs,
  and SARIF can contain private source code, vulnerability details, and
  reproduction steps.
- Restrict access to scan artifacts, apply a suitable retention period, and
  review them before sharing or uploading them to another service.
- Review proposed patches before applying or merging them.
- Keep the package, runtime, and dependencies up to date.

For background on the inherited Codex runtime's sandboxing, approvals, and
network controls, see
[Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security/).
That documentation does not define Open Security's reporting channel or scope.
