# Security Policy

Codex Security assesses repositories using a locally invoked CLI, a TypeScript
SDK, and a bundled agent runtime. This policy explains how to report a
vulnerability in Codex Security and which trust boundaries make a report
security-relevant.

## Report a vulnerability in Codex Security

Report vulnerabilities in the Codex Security CLI, SDK, bundled plugin, scan
runtime, or published release artifacts privately through
[OpenAI's Bugcrowd program](https://bugcrowd.com/engagements/openai).

Do not disclose an unpatched vulnerability, exploit, credential, sensitive scan
result, or proof of concept in a public GitHub issue or pull request. Public
issues are appropriate for ordinary bugs, documentation, and feature requests.

OpenAI's
[coordinated vulnerability disclosure policy](https://openai.com/policies/coordinated-vulnerability-disclosure-policy/)
governs reporting, confidentiality, program eligibility, and coordinated
disclosure.

## Scope and supported versions

This policy covers:

- The published `@openai/codex-security` package and `codex-security` CLI.
- The TypeScript SDK and its target selection, authentication, configuration,
  execution, and result-validation APIs.
- The Codex Security plugin, interpreter, and Codex runtime bundled with an
  official release.
- Security-relevant scan output, including manifests, findings, coverage,
  reports, SARIF, and scan-history state.
- Official package, build, and release integrity.

Reproduce a report against the latest published package or current default
branch. Include the affected package version and, where relevant, the exact
commit, bundled plugin version, and operating system. Older versions are useful
for establishing impact, but a report should explain whether the issue still
affects a supported release.

## Threat model

Codex Security is a local developer tool. Its default security model is a
**trusted local operator analyzing a locally selected repository that the
operator trusts and either owns or is explicitly authorized to assess**. The
selected repository, local Git installation, operating-system account, and
explicitly configured tools are not mutually untrusted security principals.

The operator authorizes the selected checkout, repository scope, standard Git
operations, local credentials, and explicitly supplied configuration. Normal
Git behavior, including repository configuration, hooks, attributes, filters,
credential helpers, worktrees, and executables resolved from the operator's
configured environment, runs with the operator's existing local authority.
Codex Security does not claim to protect an operator from a repository, Git
installation, plugin, interpreter, or executable that the operator has
deliberately selected and authorized.

This is not a multi-user or multi-tenant isolation boundary. Codex Security
does not isolate mutually untrusted users, agent tasks, Git checkouts, or scan
jobs that already share the same operating-system account, credentials, local
state directory, or configured runtime.

Trusting the locally selected checkout does not authorize unrelated side
effects. Repository text, generated explanations, proposed patches, remote
service responses, and imported artifacts must still be handled as data rather
than as permission to change the selected scope, disclose credentials, contact
an unauthorized destination, modify an unrelated file, or apply a patch without
the operator's authorization. A security report must identify an actual
crossing of one of the boundaries below, not merely the existence of a local
Git operation or model-visible repository content.

### Security boundaries

- **Authorized local actions.** Scan the target and perform the Git operations
  the operator requested. Do not unexpectedly modify unrelated repositories,
  files, scan targets, or output locations.
- **Credential handling and egress.** Do not disclose API keys, Codex login
  credentials, private source, or sensitive scan state in model prompts, logs,
  error messages, reports, or network requests beyond what the operator
  authorizes. Scan and workbench subprocesses can inherit the operator's
  environment; unrelated credentials are not comprehensively filtered. Provide
  only the credentials needed for the operation. Local access already held by
  the trusted operator is not itself a disclosure or subprocess-isolation
  boundary.
- **Effective scan controls.** Scans use the product's own
  `codex_security_scan` filesystem profile and noninteractive
  `approvalPolicy: "never"`. The profile allows reads of the local filesystem
  and writes to workspace roots and the selected scan state directory. Codex
  configuration overrides do not replace this approval policy or narrow the
  scan-owned filesystem profile. Assess the actual scan permissions and
  independently enforced host or network restrictions, not a stricter override
  that the scan does not apply.
- **Target and output authorization.** Do not silently include unrelated host
  files in a scan or model request, and do not write outside the output
  locations authorized by the operator. Assess symlinks and file replacement
  against those specific guarantees, not against an assumed hostile checkout.
- **Accurate scan results.** Do not present unreviewed, incomplete, altered, or
  incorrectly scoped results as a successfully validated scan. Coverage applies
  to the documented scan mode, selected paths, and stated exclusions; the
  product does not guarantee that every possible vulnerability is found.
- **Published software and release integrity.** Protect official package
  provenance, bundled runtimes, release credentials, build artifacts, and
  dependencies from unauthorized modification or publication.

## In-scope reports

Please report a reproducible issue that crosses one of those supported
boundaries in an official release. Examples include:

- Unauthorized disclosure of credentials, private source, or scan results to
  another actual security principal, model request, or network destination.
- Model or remote input that bypasses the scan's effective permissions or an
  independently enforced host, execution, filesystem, or network restriction.
- An unexpected scan, patch, file write, or network request outside the action
  and scope authorized by the local operator.
- Path traversal, symlinks, archives, or file-replacement races that cause an
  unauthorized outside-root write or silently send an unselected local file to
  a model or remote service.
- A forged, incomplete, or incorrectly scoped result accepted as a validated
  complete scan or as a passing enforced CI policy.
- Remote GitHub, update, package, dependency, or model-service data that can
  cause an unauthorized local action or compromise release integrity.
- A reachable vulnerability in the officially published package, bundled
  runtime, protected build, or release process.
- Remotely reachable or materially exploitable resource exhaustion that
  crosses a supported availability boundary.

## Usually out of scope

The following are not normally security vulnerabilities on their own:

- Ordinary operations on the operator-selected local repository, including
  reading tracked files, resolving worktrees, invoking Git, and honoring
  operator-authorized Git configuration, hooks, filters, attributes,
  credential helpers, and local executable search paths.
- A scenario that first requires the selected repository, local Git
  installation, operating-system account, process environment, or Codex state
  to be controlled by an attacker outside the default trusted-local model.
- A trusted operator intentionally selecting a malicious plugin, interpreter,
  executable, credential, scan artifact, or configuration override.
- Access, cancellation, result modification, or scan-history visibility between
  tasks and processes already running under the same trusted operating-system
  account and shared local state.
- Prompt injection, unexpected model output, a missed finding, or a false
  positive without an actual approval, confidentiality, execution, egress,
  integrity, or output-authorization bypass.
- A documented scan exclusion, ignore rule, soft cost limit, best-effort
  estimate, or Git behavior represented accurately in the scan's scope and
  results.
- A dependency advisory, theoretical attack, or old package version without a
  reproducible impact on a supported release.
- Ordinary performance problems triggered only by a file, document, or
  repository the trusted operator deliberately selected.
- Vulnerabilities in a third-party repository being scanned.
- Documentation, tests, fixtures, or development-only code that is not
  reachable from an officially published runtime or protected release.

Different assumptions can apply to a separately deployed hosted service,
multi-user installation, untrusted pull-request CI, or explicitly imported
third-party artifacts. A report about one of those deployments must identify
the actual deployment, attacker-controlled input, supported boundary, and
affected Codex Security component. Do not infer that the local CLI offers
multi-tenant isolation merely because it stores multiple scans or uses Git.

If you are unsure whether a finding crosses a boundary, report it privately
rather than disclosing it publicly.

## What to include in a report

To help us reproduce and assess the issue, include:

- The affected component, package and plugin versions, and commit if known.
- Affected platform and relevant authentication, scan mode, and target type.
- The attacker's actual starting permissions and the boundary that is crossed.
- Minimal reproduction steps against a supported release or current default
  branch.
- Expected and observed behavior, practical security impact, and any available
  mitigation.
- Sanitized logs or scan artifacts when they are necessary to reproduce the
  issue.

Remove API keys, access tokens, customer information, and private source code
unless the private report requires the material and you are authorized to
share it. Do not include live credentials in a proof of concept.

## Report a finding in a scanned repository

A vulnerability found in another repository belongs to that repository's
owner. Follow the affected project's security policy or coordinated disclosure
process, and share the finding only with people authorized to receive it.
OpenAI's Bugcrowd program is for vulnerabilities in OpenAI products and
services, not findings in unrelated projects.

## Run scans safely

- Scan only repositories you trust and either own or have explicit permission
  to assess.
- Review repository instructions and proposed patches as data; approve a patch
  before applying or merging it.
- Run scans with only the credentials the operation needs; local subprocesses
  can inherit other environment variables.
- Keep credentials and the Codex home outside the scanned repository.
- Store scan state, findings, reports, logs, and SARIF outside the enclosing
  Git worktree.
- Restrict artifact access, set an appropriate retention period, and review
  results before sharing or uploading them.
- Keep the package, bundled runtime, and dependencies up to date.

For more about Codex sandboxing, approvals, and network controls, see
[Agent approvals and security](https://developers.openai.com/codex/agent-approvals-security/).
For vulnerability identifiers and disclosure timelines, see
[OpenAI's CVE assignment policy](https://openai.com/policies/openai-cve-assignment-policy/).
