# `@masonjames/open-security`

Open-source TypeScript SDK and CLI for running Open Security scans. The
ESM-only package includes TypeScript declarations, the canonical `open-security`
executable, the backward-compatible `codex-security` alias, and the matching
Codex runtime.

> [!IMPORTANT]
> This is an independent community fork of
> [OpenAI's Codex Security](https://github.com/openai/codex-security). It is not
> affiliated with or endorsed by OpenAI. Internal plugin and artifact identifiers
> retain their upstream names for compatibility.

> [!NOTE]
> This package follows semantic versioning. Its public API may change between
> minor versions before `1.0.0`.

## Install from source

The package is not published to npm yet. Build and install a verified local tarball:

```bash
git clone https://github.com/masonjames/open-security.git
cd open-security/sdk/typescript
corepack enable
pnpm install --frozen-lockfile
pnpm run types
pnpm run build
pnpm pack --pack-destination ./dist-package
npm install ./dist-package/masonjames-open-security-*.tgz
./node_modules/.bin/open-security --version
```

The package CLI supports macOS, Linux, and Windows and requires Node.js 22.13.0
or later in the 22.x release line, Node.js 24.x, or Node.js 26.x. Security scans
currently fail closed on Windows until the CLI can verify
private NTFS DACLs; authentication, configuration, and other non-scan commands
remain available. Scanning and exporting findings on supported scan platforms
also require Python 3.10 or later. If you use Python 3.10, install the `tomli`
package. Select another interpreter with `--python`, `pythonPath`, or `PYTHON`
when needed.

When a newer version is available, the CLI shows the update command for your
installation method. Set `OPEN_SECURITY_NO_UPDATE_NOTICE=1` to hide the notice;
the legacy `CODEX_SECURITY_NO_UPDATE_NOTICE=1` alias remains supported. Notices
are also disabled in CI and when stderr is not a terminal. Set
`OPEN_SECURITY_NPM_REGISTRY` to use a private or mirrored registry for the
check; `CODEX_SECURITY_NPM_REGISTRY` remains a compatibility alias.

## Run a scan from TypeScript

Sign in with `open-security login` or set `OPENAI_API_KEY` or
`CODEX_API_KEY`. Then create a client and scan a repository you own or have
permission to assess:

```ts
import { CodexSecurity } from "@masonjames/open-security";

const security = new CodexSecurity();

try {
  const result = await security.run("/path/to/repository", {
    outputDir: "/path/outside/repository/results",
  });

  console.log(result.reportPath);
  console.log(result.findings.findings.length);
} finally {
  await security.close();
}
```

For OpenRouter, set `OPENROUTER_API_KEY` and select the provider and exact model:

```ts
const security = new CodexSecurity({
  provider: "openrouter",
  codexOverrides: {
    model: "qwen/qwen3.7-flash",
    model_reasoning_effort: "high",
  },
});

try {
  const result = await security.run("/path/to/repository", {
    maxCostUsd: 1,
  });
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

The SDK supports repository, path, committed-diff, and working-tree targets.
Use `security.preflight()` to validate local inputs, `onWorkerStatus` and
`onReconnect` to observe long-running scans, and an `AbortSignal` to cancel a
scan.

Results can contain source excerpts, vulnerability details, and reproduction
steps. Keep result directories and saved reports outside the repository and
limit access to authorized reviewers.

### SDK configuration and scan options

Pass runtime configuration to the `CodexSecurity` constructor:

| Option           | Description                                                                 |
| ---------------- | --------------------------------------------------------------------------- |
| `pluginPath`     | Use a Codex Security plugin directory or ZIP instead of the bundled plugin. |
| `pythonPath`     | Select the Python interpreter before consulting `PYTHON`.                   |
| `codexOverrides` | Deep-merge supported settings into the isolated Codex configuration.        |

Pass scan configuration to `security.run(repository, options)` or
`security.preflight(repository, options)`:

| Option                  | Description                                                                           |
| ----------------------- | ------------------------------------------------------------------------------------- |
| `auth`                  | Select `"auto"`, `"chatgpt"`, or `"api-key"`.                                         |
| `target`                | Select a repository, repository-relative paths, committed diff, or working-tree diff. |
| `mode`                  | Select `"standard"` or `"deep"`; deep mode supports repositories and paths.           |
| `knowledgeBasePaths`    | Add architecture documents, security policies, threat models, or directories.         |
| `outputDir`             | Choose an artifact directory outside the enclosing Git worktree.                      |
| `archiveExisting`       | Archive results already in `outputDir` before starting a scan.                        |
| `maxCostUsd`            | Stop after the estimated model cost exceeds a positive USD amount.                    |
| `failureSeverity`       | Record a finding-severity policy in the saved scan recipe.                            |
| `parentScanId`          | Link a rerun to an existing parent scan.                                              |
| `expectedPluginVersion` | Require the original plugin version when replaying a scan.                            |
| `signal`                | Cancel a scan with an `AbortSignal`.                                                  |

Progress and lifecycle callbacks are `onAuthentication`, `onCost`,
`onOutputArchived`, `onOutputDirReady`, `onScanStarted`, `onReconnect`,
`onWorkerStatus`, `onWarning`, and `onObserverError`. Preflight does not start
the runtime, authenticate, resolve Python, inspect the plugin, or run those
scan-lifecycle callbacks.

## Authentication

### OpenRouter

OpenRouter uses an API key from the environment and requires an explicit model
ID. The CLI owns a fixed OpenRouter Responses API upstream and routes standard
scans through a temporary loopback bridge:

```bash
export OPENROUTER_API_KEY="<your-key>"
export OPEN_SECURITY_PROVIDER="openrouter"
export OPEN_SECURITY_MODEL="qwen/qwen3.7-flash"
export OPEN_SECURITY_REASONING_EFFORT="high"
export OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS="16384"
export OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS="10000"
export OPEN_SECURITY_OPENROUTER_MAX_RETRIES="3"
export OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS="30000"
export OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS="120000"
export OPEN_SECURITY_MAX_COST_USD="1"

open-security scan . --dry-run --json
open-security scan .
```

The same configuration can be supplied with `--provider`, `--model`,
`--reasoning-effort`, and `--max-cost`. The typed concise alias
`--effort minimal|low|medium|high|xhigh` selects the same reasoning setting;
`--reasoning-effort` and `--effort` cannot be used together. OpenRouter supports
`auto` and `api-key` authentication modes; `--auth chatgpt` is rejected. The key is not
persisted by login, written to scan recipes, or forwarded to OpenAI scans.
OpenAI keys are removed from OpenRouter model processes, and model-provider
credentials are removed from Python and workbench helper processes.

The standard-scan bridge binds an opaque route on `127.0.0.1`, removes ambient
forward-proxy variables from the model process, forwards only validated streamed
Responses requests to `https://openrouter.ai/api/v1`, and closes with the SDK
client. Codex receives a random bridge-only credential; the real OpenRouter key
stays in the host process and is substituted only on the fixed upstream request.
Its URL exists only in the isolated runtime configuration; it is absent from
scan recipes and the readable preflight snapshot. Validation, patching, and
semantic scan matching are disabled for OpenRouter until those direct Codex
paths use the same credential bridge. They remain available with OpenAI.

Set `OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS` to a decimal integer from
`0` through `60000` to enforce a bridge-local minimum between upstream Responses
request starts. For example, `10000` enforces at least ten seconds between
starts. The default `0` disables proactive pacing. The setting does not
coordinate separate Open Security processes or other API clients, and invalid
values fail closed.

Only pre-stream HTTP `429` responses are replayed through the same pacing and
capacity gates. `503` and other potentially accepted failures are not replayed
without a documented upstream idempotency guarantee. The bridge honors bounded
delta-seconds and HTTP-date `Retry-After` values; without one it uses
exponential delays from
`OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS` (default `30000`).
`OPEN_SECURITY_OPENROUTER_MAX_RETRIES` defaults to `3` and accepts `0` through
`5`; `0` disables retries. `OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS`
defaults to `120000` and caps both server-requested and calculated delays.
Delays above the cap are forwarded instead of retried. Mid-stream errors are
never replayed, and client close cancels pending retry waits.

Before starting Codex, the scanner queries OpenRouter's unauthenticated
`GET https://openrouter.ai/api/v1/models` catalog and the exact model's
`GET /api/v1/models/{author}/{slug}/endpoints` record. It requires an exact
model ID, at least one advertised provider endpoint, and the tool,
structured-response, and requested reasoning capabilities used by the command.

### OpenAI

For local use, sign in with ChatGPT:

```bash
open-security login
open-security scan .
```

On a remote or headless machine, use device authentication:

```bash
open-security login --device-auth
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. To store an API key instead,
pass it on stdin:

```bash
printenv OPENAI_API_KEY | open-security login --with-api-key
```

Environment API keys are supplied directly to the current scan and are never
saved to the Codex credential home or system keyring. Only an explicit
`login --with-api-key` stores an API key.

To pass a Codex access token explicitly, use
`login --with-access-token` and provide the token on stdin. An access token
environment variable is not automatically used as a scan API key.

On Windows, set the API key in PowerShell. Authentication and managed-keyring
operations are supported, but scan execution fails closed until private NTFS
DACL validation is available:

```powershell
$env:OPENAI_API_KEY = "<your-api-key>"
```

Check or remove the stored sign-in with `open-security login status` and
`open-security logout`. Open Security keeps its sign-in in a
private, stable Codex home at `$CODEX_SECURITY_STATE_DIR/codex-home`, or at
`$CODEX_HOME/state/plugins/codex-security/codex-home` when no state directory is
configured. Login, status, logout, and scans use the same home. Codex manages
credentials using its configured file or system-keyring backend and honors
managed-device policies. An existing file-based Codex sign-in is imported only
when the dedicated home does not already contain stored credentials. Logging
out prevents later scans from automatically reimporting that ambient sign-in
until you explicitly log in again.

An environment API key takes precedence over a stored sign-in by default.
When both a stored ChatGPT sign-in and an environment API key are available, an
interactive scan asks which credential to use. JSON output, dry runs, CI, and
other noninteractive scans never prompt and retain automatic API-key
precedence. Select the credential source explicitly with `--auth`:

```bash
open-security scan . --auth chatgpt
open-security scan . --auth api-key
```

`--auth chatgpt` uses the stored sign-in and ignores `OPENAI_API_KEY` and
`CODEX_API_KEY`. `--auth api-key` requires one of those environment variables.
Omit `--auth`, or pass `--auth auto`, to preserve automatic API-key precedence
for existing CI and unattended scans. The SDK accepts the same selection as
`security.run(repository, { auth: "chatgpt" })` and
`security.preflight(repository, { auth: "chatgpt" })`.

To make the stored ChatGPT sign-in the automatic default instead, unset any
configured API-key variables:

```bash
unset OPENAI_API_KEY CODEX_API_KEY
```

The interactive choice applies only to the current scan and is not persisted.

When an environment key is configured, ChatGPT login and
`open-security login status` identify the effective scan credential source
without printing its value, including when no stored sign-in exists.

## CLI

```bash
open-security scan /path/to/repository
open-security scan /path/to/repository --model gpt-5.6-terra
open-security scan /path/to/repository --model gpt-5.6-terra --effort high
open-security scan /path/to/repository --path src --path tests
open-security scan /path/to/repository --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
open-security scan /path/to/repository --diff origin/main --json
open-security scan /path/to/repository --output-dir /path/outside/repository/results
open-security scan /path/to/repository --output-dir /path/outside/repository/results --archive-existing
open-security scan /path/to/repository --dry-run
open-security scan /path/to/repository --fail-on-severity high
open-security scan /path/to/repository --max-cost 5
open-security scan /path/to/repository --mode deep --workers 2 --subagents 0 --stop-after-no-new 3 --max-discovery-runs 10
open-security install-hook
open-security bulk-scan
open-security bulk-scan --model gpt-5.6-terra --effort high
open-security bulk-scan repositories.csv --output-dir /path/outside/repositories/security-scans --workers 4 --knowledge-base /path/to/threat-models --knowledge-base /path/to/architecture.pdf
open-security scans list /path/to/repository
open-security scans list --scan-root /path/outside/repository/results
open-security scans show SCAN_ID
open-security scans rerun SCAN_ID
open-security scans match PREVIOUS_SCAN_ID CURRENT_SCAN_ID
open-security scans match --all
open-security scans compare PREVIOUS_SCAN_ID CURRENT_SCAN_ID
open-security findings false-positive OCCURRENCE_ID --reason "The route already checks permissions"
open-security export /path/outside/repository/results --export-format sarif --output /path/outside/repository/results.sarif
open-security export /path/outside/repository/results --export-format csv --output /path/outside/repository/findings.csv
open-security export /path/outside/repository/results --export-format json --output /path/outside/repository/findings.json
open-security validate /path/outside/repository/findings.json "Possible SQL injection in src/query.ts:42"
open-security validate "Possible SQL injection" --effort high
open-security patch /path/outside/repository/findings.json "Missing authorization check in src/routes.ts:18"
open-security patch "Missing authorization check" --effort high
```

Run `open-security --version` for the installed CLI version or
`open-security info --json` for the package, bundled plugin, Codex runtime,
default model, reasoning effort, and first-scan command. A scan with `--dry-run`
also reports its effective provider, model, and reasoning effort, including
`--codex` overrides, without starting Codex. OpenRouter dry runs query its public,
unauthenticated model catalog to validate the exact model and pricing metadata.

`install-hook` scans staged and unstaged changes before each commit. It respects
`core.hooksPath`, does not replace an existing hook, and blocks high-severity
findings or failed scans. Set `--fail-on-severity` to change the threshold.

`--path` scopes a scan to one or more paths, `--diff` scans committed changes,
and `--working-tree` scans staged and unstaged changes. Deep scans support
repository and path targets with OpenAI. OpenRouter deep scans are rejected for
now because the credential bridge and aggregate cost accounting have not yet
been validated across independent delegated workers. Standard OpenRouter scans
remain supported.
The output directory must be outside the scanned
directory and any enclosing Git worktree. When SARIF is produced, it is written
to
`<scan-dir>/exports/results.sarif`.

Repeat `--knowledge-base PATH` for multiple files or directories; `bulk-scan`
shares them with every repository. Directories are searched recursively for
Markdown, text, PDF, and Word (`.docx`) files.

### Configure deep scans

For `scan --mode deep`, `--workers` limits concurrent discovery workers,
`--subagents` controls each worker's subagents, `--stop-after-no-new` stops after
that many runs find no new issues, and `--max-discovery-runs` limits total runs.
These options are also available on SDK scans:

```ts
await security.run("/path/to/repository", {
  mode: "deep",
  workers: 2,
  subagents: 0,
  stopAfterNoNew: 3,
  maxDiscoveryRuns: 10,
});
```

Set defaults in `~/.codex/codex-security/config.toml`, or under `$CODEX_HOME`
when it is configured. Explicit CLI and SDK settings override these defaults:

```toml
[deep_scan]
workers = 2
subagents = 0
stop_after_no_new = 3
max_discovery_runs = 10
```

`scan --workers` controls discovery workers within one deep scan;
`bulk-scan --workers` controls how many repositories are scanned concurrently.

On macOS/Linux, an existing output directory must be private to the current
user (`chmod 700`).

If the output directory already contains results, add `--archive-existing`.
The CLI moves them to `<output-dir>.previous-<timestamp>-<id>` and starts the
scan in a new, empty directory at the original path. Add `--dry-run` to see
the destination without moving files. All scan execution currently fails
closed on Windows until the CLI can verify private NTFS DACLs.

Scans are report-only by default. Use `--fail-on-severity` in CI to exit 1 when
a completed scan contains a finding at or above the selected severity.
Incomplete coverage and CLI/runtime errors exit 2 so they cannot be mistaken
for a passing policy. Incomplete scans still write the available human or JSON
result to stdout and a coverage warning to stderr, including in report-only
mode.

OpenAI scans use `gpt-5.6-sol` with extra-high reasoning effort by default. Use
`--model gpt-5.6-terra` to switch OpenAI models. OpenRouter scans require an
explicit model through `--model` or `OPEN_SECURITY_MODEL` and default to `high`
reasoning unless explicitly configured. Use repeatable
`--codex KEY=VALUE` options for other Codex settings, such as
`--codex 'model_reasoning_effort="high"'`; OpenRouter's provider name, upstream
endpoint, credential variable, and Responses wire API are owned by Open Security
and cannot be overridden through raw Codex configuration. Set
`OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS` to a decimal integer from `1` through
`65536` to change the standard-scan per-request output reservation cap; the
default is `16384`. Set `OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS` to a
decimal integer from `0` through `60000` to pace upstream request starts; the
default is `0` (disabled). Bounded pre-stream retry behavior is configured with
`OPEN_SECURITY_OPENROUTER_MAX_RETRIES`,
`OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS`, and
`OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS`.

### Runtime configuration and worker limits

The standalone CLI and SDK do not load an unrelated user or repository Codex
configuration. Each scan starts with a private runtime and these Codex
defaults:

```toml
cli_auth_credentials_store = "auto"
model = "gpt-5.6-sol"
model_reasoning_effort = "xhigh"

[features]
plugins = true
goals = true

[features.multi_agent_v2]
enabled = true
max_concurrent_threads_per_session = 9

[windows]
sandbox = "unelevated"
```

Use `--model` and `--effort` for model selection. Repeat
`--codex KEY=VALUE` to deep-merge other TOML values into this isolated
configuration:

```bash
open-security scan . \
  --model gpt-5.6-terra \
  --effort high \
  --codex features.multi_agent_v2.max_concurrent_threads_per_session=4
```

The session thread limit includes the parent agent: the default of `9`
provides up to eight delegated worker slots. This limit is separate from
`bulk-scan --workers`, which controls how many repositories run concurrently.
A configured limit is a maximum, not evidence that every worker started.

Quote string values as TOML, for example
`--codex 'model_reasoning_effort="high"'`. Do not pass both `--model` and
`--codex 'model="..."'`, or both `--effort` and
`--codex 'model_reasoning_effort="..."'`: conflicting or repeated keys are
rejected.

Plugin and marketplace loading belong to Codex Security. Overrides of
`plugins`, `marketplaces`, or `features.plugins`, including profile-specific
plugin overrides, are rejected; choose `--plugin-path` instead. Native
multi-agent v2 must remain enabled. The legacy `agents.max_threads` setting
and `features.multi_agent_v2.enabled=false` are incompatible and rejected.
`validate` and `patch` accept `--effort` and only the `model` and
`model_reasoning_effort` `--codex` keys; they do not accept general scan
runtime overrides.

These overrides do not change the scan's approval policy or filesystem
permissions. See [Local security model](#local-security-model).

### Deep-scan engine configuration

When the bundled plugin runs in a normal Codex host, its repeated-discovery
engine reads `$CODEX_HOME/codex-security/config.toml`, defaulting to
`~/.codex/codex-security/config.toml`:

```toml
[deep_scan]
workers = "auto"
subagents = 3
stop_after_no_new = 6
max_discovery_runs = 60
```

`workers = "auto"` uses half the available parallelism, with a minimum of one
and a maximum of six discovery workers. Set `workers` to a positive integer to
choose an explicit count. `subagents` must be a nonnegative integer;
`stop_after_no_new` and `max_discovery_runs` must be positive integers. Unknown
`[deep_scan]` keys are rejected.

These settings are separate from Codex's
`features.multi_agent_v2.max_concurrent_threads_per_session` and
`bulk-scan --workers`. Importantly, standalone CLI and SDK scans create an
isolated `CODEX_HOME` and do not import the ambient deep-scan configuration
file. Consequently, `scan --mode deep` currently uses the deep engine's
defaults; there are no standalone CLI flags for these four settings. Use
`--codex` to adjust the Codex session thread limit, not to set `[deep_scan]`
values.

### Environment variables

The CLI and SDK recognize the following user-configurable environment:

| Variable                                                                    | Effect                                                                                        |
| --------------------------------------------------------------------------- | --------------------------------------------------------------------------------------------- |
| `OPENAI_API_KEY`, `CODEX_API_KEY`                                           | Scan authentication; `OPENAI_API_KEY` wins when both are present.                             |
| `CODEX_SECURITY_STATE_DIR`                                                  | Override the private scan-history, workbench, and default artifact directory.                 |
| `CODEX_HOME`                                                                | Set the ambient Codex home for file-backed sign-in and default state; defaults to `~/.codex`. |
| `PYTHON`                                                                    | Select a Python interpreter when `--python` or SDK `pythonPath` is not set.                   |
| `GH_HOST`                                                                   | Select a GitHub Enterprise host during interactive `bulk-scan` discovery.                     |
| `CODEX_SECURITY_NO_UPDATE_NOTICE`, `NO_UPDATE_NOTIFIER`                     | Disable interactive update notices when either variable is defined.                           |
| `CODEX_SECURITY_NPM_REGISTRY`, `npm_config_registry`, `NPM_CONFIG_REGISTRY` | Select the update-check registry, in the listed precedence order.                             |
| `CI`                                                                        | Disable interactive update notices in automated environments.                                 |
| `NO_COLOR`, `TERM`                                                          | Disable colored scan-history output when `NO_COLOR` is defined or `TERM=dumb`.                |

Interpreter discovery uses `--python` or `pythonPath` first, then `PYTHON`,
the managed Codex runtime, and finally `python3` or `python` from `PATH`.
`CODEX_SECURITY_STATE_DIR` takes precedence over `CODEX_HOME`; keep both
state and result paths outside the scanned repository.

The repository's Docker Compose workflow additionally recognizes
`CODEX_SECURITY_IMAGE`, `CODEX_SECURITY_USER`, `CODEX_SECURITY_SECCOMP`,
`CODEX_SECURITY_CSV`, `CODEX_SECURITY_RESULTS`, and `CODEX_SECURITY_STATE` for
its image, runtime user, seccomp profile, input, results, and state mounts.
Provide `GH_TOKEN` or `GITHUB_TOKEN` for private GitHub checkouts and
`CODEX_SECURITY_GIT_HOST` for a GitHub Enterprise host in the container.
These container settings are distinct from standalone CLI flags and
interactive discovery's `GH_HOST`.

Variables such as `CODEX_SECURITY_SCAN_ID`, `CODEX_SECURITY_SCAN_DIR`,
`CODEX_SECURITY_PLUGIN_ROOT`, `CODEX_SECURITY_CONFIG_PATH`, and
`CODEX_SECURITY_TARGET_PATHS_FILE` are generated by an active scan. They are
internal runtime data, not supported user configuration.

Scan progress identifies the requested paths and reports actual ranking,
file-review, validation, and attack-path phases as they become available.
Completion summarizes findings, severity, coverage, elapsed time, available
token and worker counts, estimated cost, the results directory, and the next
useful command.
Progress and summaries use stderr; structured scan results remain on stdout.

Each scan records its provider, model, tokens, and estimated cost in its JSON
result, scan history, and bulk-scan receipt. OpenAI estimates use built-in
published rates. OpenRouter estimates parse prices without floating point and
use the maximum advertised prompt, completion, cache-read, and cache-write rate
across the base catalog record, every current provider endpoint, and every
conditional pricing override. Input, cached input, cache-write input, and output
tokens are included. Models with no advertised endpoint, a nonzero per-request
fee, or any other nonzero billing category are rejected for standard scans
until they can be accounted reliably.

Use `--max-cost USD` or `OPEN_SECURITY_MAX_COST_USD` to stop an individual
standard scan, including its parent-linked delegated workers, when its running
estimate exceeds the limit. Partial results are preserved. Requests already in
progress can finish above the limit; this is a local estimate guardrail, not a
provider-side spending cap. Cost tracking accepts Codex session events up to
1 MiB; an oversized event stops the scan because its running cost can no longer
be verified safely.

For OpenRouter standard scans, the output-token cap is enforced before each
Responses request is forwarded. A missing or larger `max_output_tokens` value is
clamped, while a valid lower value is preserved. This reduces provider credit
reservations, latency, and rate-limit pressure; it complements rather than
replaces the cumulative USD guardrail. The request-start interval is a separate
proactive rate-limit control and does not change token reservations or cost
accounting.

`OPEN_SECURITY_MAX_COST_USD` fails closed for `bulk-scan`, `validate`, `patch`,
and model-backed `scans match` operations because those paths do not yet have
reliable campaign-wide or turn-level accounting. Cached and empty scan matching
and deterministic `scans compare` remain model-free. Deep scans cannot use a
cost limit; OpenRouter deep scans are entirely disabled as described above.

Run `open-security scan --help` or `open-security bulk-scan --help`
for the complete CLI references.

Sign in with `gh auth login`, then run `open-security bulk-scan` to discover
GitHub repositories pushed in the last 90 days. Archived
repositories and forks are excluded. Search the repository list, select the
repositories to scan, and confirm before scanning.
Private checkouts reuse your GitHub CLI sign-in without changing your global Git
configuration. The selected repositories are saved to
`<output-dir>/repositories.csv` for review or resumption.

To use an existing repository list or run in CI, pass a CSV with required `id`,
`repository`, and `revision` columns. Revisions must be full commit hashes;
optional `scope` and `mode` columns narrow individual scans:

```csv
id,repository,revision,scope,mode
service,https://github.com/acme/service.git,0123456789abcdef0123456789abcdef01234567,src,standard
```

`--workers` limits concurrent scans and `--max-attempts` retries failures.
Results remain under `--output-dir`; rerun the same command to resume.

### Scan history and reruns

`open-security scans list` lists scans for the current repository. Pass a
repository path to inspect another checkout, `--scan-root DIR` to list scans
whose artifacts are under a particular root. `scans show SCAN_ID` includes the
scan configuration, results, coverage, and artifact locations. Add
`--show-linked-findings` to include finding links from previous scans.

Every scan history command accepts a full scan ID or a unique prefix of at
least eight characters.

Scan history uses the existing Open Security workbench database at
`$CODEX_HOME/state/plugins/codex-security/workbench.sqlite3`. Set the preferred
`OPEN_SECURITY_STATE_DIR` variable to place the database elsewhere; the legacy
`CODEX_SECURITY_STATE_DIR` alias remains supported. Scan credentials are never
stored in the scan configuration.

The scan sandbox permits writes to the selected state directory so SQLite can
maintain its database and journal files. If the host itself cannot write to the
default directory, select a writable directory outside the scanned repository:

```bash
export OPEN_SECURITY_STATE_DIR=/path/to/writable/open-security-state
```

Use `open-security findings false-positive OCCURRENCE_ID --reason TEXT` to mark
a finding as a false positive and explain why. Later scans dismiss a matching
finding only when the same reason still applies.

`scans rerun SCAN_ID` repeats the original configuration against the current
checkout so a fixed vulnerability can be checked again.

`scans match BEFORE_SCAN_ID AFTER_SCAN_ID` links findings with the same root
cause; `scans match --all` matches all completed scans of the current repository,
including other worktrees and clones. Saved matches appear in `scans show` and
are reused unless `--force` is passed. Scans without sealed artifacts are skipped.

`scans compare BEFORE_SCAN_ID AFTER_SCAN_ID` automatically matches findings by
root cause, reuses saved matches, and reports findings as new, persisting,
reopened, resolved, or unknown. Missing findings are not treated as resolved when
the later scan is incomplete or does not cover their original scope.

The CLI uses [Incur](https://github.com/wevm/incur) for agent-friendly discovery
and structured output. Inspect the command manifest with `--llms`, inspect a
command schema with `scan --schema --format json`, register the CLI as an MCP
server with `mcp add`, sync agent skills with `skills add`, or generate shell
completions with `completions bash|zsh|fish`. Scan results support
`--format toon|json|yaml|jsonl` and `--full-output`.
Use `info --json` for SDK and bundled-plugin metadata. MCP exposes only this
read-only metadata command; scans, bulk repository scans,
authentication, exports, validation, and patching remain CLI-only because the
MCP transport cannot cancel active scans.

For CI, save machine-readable output outside the checked-out repository and
apply a severity policy. Incomplete coverage and runtime errors still exit
nonzero:

```bash
SCAN_ROOT="$(mktemp -d)"
open-security scan . \
  --diff origin/main \
  --output-dir "$SCAN_ROOT/results" \
  --json \
  --fail-on-severity high > "$SCAN_ROOT/findings.json"
```

JSON scans never use interactive terminal controls, even when stderr is a TTY.
The `validate`, `patch`, `login`, and `logout` commands reject `--json` because
they do not produce structured CLI output. Sign-in commands remain interactive.
CSV exports cannot be written to stdout while JSON output is requested.

Use `export` to create CSV, JSON, or SARIF from a completed, sealed scan without
starting Codex or loading credentials. JSON preserves the sealed findings
document. CSV uses the portable findings columns, marks findings as open, and
does not include local workbench triage state. The exporter validates the seal
before writing, accepts `--output -` for stdout, and can use
`--source-root /path/to/repository` with SARIF to add source-line fingerprints.
Run `open-security export --help` for all export options.

Use `validate` to run the bundled validation skill on candidate findings and
`patch` to run the bundled fix-finding skill on security issues. Each positional
input can be either a file, whose contents are read into the request, or literal
text. Both commands operate on the current directory, use the scan model
and reasoning defaults, ignore unrelated user configuration and plugins, and
print the final response without the underlying Codex event stream. Override
the model or reasoning effort with `--codex 'model="gpt-5.6-sol"'` or
`--codex 'model_reasoning_effort="high"'`. Inputs are limited to 64 items and
1 MiB total.

Canonical scan documents are limited to 16 MiB for the manifest, 128 MiB for
findings, and 32 MiB for coverage. Oversized scans are rejected before sealing.

Exit codes are `0` for a completed report-only scan or a passing policy, `1`
for a completed policy violation, `2` for invalid input, incomplete coverage, or
a runtime/export error, `130` for interruption, and `143` for termination.

Use `--dry-run` or `await security.preflight(...)` to validate the repository,
target, mode, output location, and Codex overrides without initializing the
runtime or loading credentials. Dry runs do not inspect the plugin or probe its
Python interpreter. The preflight result includes the selected authentication
method and, for an environment API key, its variable name. Authentication and
model access remain unverified until a real scan starts.

Scan progress identifies the selected credential source before Codex starts.
Terminals and noninteractive CI logs also show how to retry with
`--auth chatgpt` when an environment API key overrides the stored sign-in.
Progress remains on stderr so JSON output stays machine readable. Network
failures and rate limits remain retryable; definitive authentication and model
authorization failures stop immediately.

## Containerized bulk scans

Create `repositories.csv` with one full, immutable Git commit per repository:

```csv
id,repository,revision
payments,https://github.com/example/payments.git,0123456789abcdef0123456789abcdef01234567
```

Once the approved image has been published, prepare private results and
authentication directories, sign in, and run the Docker Compose configuration
from the root of the Codex Security repository:

```bash
mkdir -p results state
chmod 700 results state
export CODEX_SECURITY_USER="$(id -u):$(id -g)"
export CODEX_SECURITY_IMAGE=ghcr.io/openai/codex-security:0.1.4
docker compose pull codex-security
docker compose run --rm codex-security login --device-auth
docker compose run --rm codex-security
```

Reports and resumable scan results are written to `results/`; the reusable
device login remains in `state/`. For unattended scans, set `OPENAI_API_KEY`
or `CODEX_API_KEY` instead. Set `GH_TOKEN` or `GITHUB_TOKEN` for private
GitHub repositories.

On Ubuntu hosts that restrict unprivileged user namespaces, an administrator
can install the optional, narrowly scoped AppArmor profile once:

```bash
sudo install -m 0644 docker/codex-security.apparmor /etc/apparmor.d/codex-security-container
sudo apparmor_parser -r -W /etc/apparmor.d/codex-security-container
docker compose -f compose.yaml -f compose.apparmor.yaml run --rm codex-security
```

The override preserves the nonroot user, dropped capabilities,
no-new-privileges, and hardened seccomp policy. Other Docker hosts do not need
the profile or override.

## Local security model

Codex Security runs with your local operating-system permissions. Scan only
repositories you trust and either own or are authorized to assess. Your
repository, Git installation, configured tools, and other scans under the
same account are not separate security principals.

Every scan uses the `codex_security_scan` filesystem profile and
`approvalPolicy: "never"`. It can read the local filesystem and write to
workspace roots and the selected scan state directory. Scans do not request
interactive approval. Setting `approval_policy`, `sandbox_mode`, or permissions
through `--codex` or SDK `codexOverrides` does not replace these controls or
make them more restrictive. Independently enforced host and network
restrictions still apply.

Scan and workbench subprocesses can inherit your environment, including
unrelated API tokens and cloud credentials. Start a scan with only the
credentials it needs.

The scanner must stay within the target and output paths you authorize and
must not disclose private data beyond the operation you requested. Its results
must accurately report the scan mode, reviewed files, and exclusions. Consult
the security policy for the full threat model and private reporting process.

## Documentation and security

- [Open Security issues](https://github.com/masonjames/open-security/issues) for bugs and feature requests
- [Open Security security policy](https://github.com/masonjames/open-security/security/policy) for private vulnerability reporting
- [Upstream Codex Security](https://github.com/openai/codex-security) for project lineage and upstream documentation
