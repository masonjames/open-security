# Open Security

Open Security is a provider-flexible security scanner CLI and TypeScript SDK. It is an independent community fork of [OpenAI's Codex Security](https://github.com/openai/codex-security), with OpenRouter support added through the Responses API while retaining the original OpenAI and ChatGPT authentication paths.

> [!IMPORTANT]
> Open Security is not an OpenAI product and is not affiliated with or endorsed by OpenAI. The internal `codex-security` plugin, artifact schemas, and TypeScript `CodexSecurity` class retain their upstream names for compatibility.

**See the [Codex Security documentation](https://learn.chatgpt.com/docs/security/cli)** for more details.

## Current provider support

| Provider   | Authentication                                        | Model selection                       | Pricing source                                         |
| ---------- | ----------------------------------------------------- | ------------------------------------- | ------------------------------------------------------ |
| OpenRouter | `OPENROUTER_API_KEY`                                  | Explicit OpenRouter model ID          | Public `/models` and exact-model `/endpoints` catalogs |
| OpenAI     | ChatGPT sign-in, `OPENAI_API_KEY`, or `CODEX_API_KEY` | Existing OpenAI defaults or `--model` | Built-in published rates                               |

OpenRouter uses a fixed `https://openrouter.ai/api/v1` Responses API upstream. Standard scans route the pinned Codex runtime through a temporary loopback bridge that caps oversized output reservations before forwarding them to that upstream. Codex receives a random bridge-only credential; the real OpenRouter key remains in the host process and is substituted only on the validated upstream request. Users cannot override the provider table through raw Codex settings; this keeps the authentication boundary and endpoint predictable.

## Requirements

- Node.js 22.13.0 or later in the 22.x release line, Node.js 24.x, or Node.js 26.x
- Python 3.10 or later
- pnpm 11.9.0 through Corepack
- Permission to assess the repository being scanned
- Access to the selected model provider

## Run from source

```bash
git clone https://github.com/masonjames/open-security.git
cd open-security
corepack enable
pnpm --dir sdk/typescript install --frozen-lockfile
pnpm --dir sdk/typescript run build
node sdk/typescript/bin/codex-security.mjs --help
```

The package manifest declares `open-security` as the canonical executable and preserves `codex-security` as a backward-compatible alias. The package is not published to npm yet; use the source launcher or a locally packed tarball. The source launcher keeps its upstream filename to reduce merge conflicts.

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY` instead of signing in. Environment API keys are
passed directly to the current scan and are never stored in Codex's credential
home or system keyring.

Local sign-in honors Codex's configured credential backend, including a system
keyring required by a managed device. Codex Security keeps login and scan
credentials in the same private, persistent state directory.

Until you install a local tarball or link the package, replace `open-security` in the examples below with `node sdk/typescript/bin/codex-security.mjs`.

## OpenRouter quick start

Set the provider, exact OpenRouter model ID, and key:

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

The equivalent one-shot command is:

```bash
open-security scan . \
  --provider openrouter \
  --model qwen/qwen3.7-flash \
  --reasoning-effort high \
  --auth api-key \
  --max-cost 1
```

Use an exact ID returned by OpenRouter's unauthenticated model catalog. Open Security also checks the exact model's advertised provider endpoints, refuses a model with no routable endpoint, and verifies tool use, structured-response, and requested reasoning support before starting the model runtime. OpenRouter defaults to `high` reasoning unless you configure another effort. `--effort minimal|low|medium|high|xhigh` is the typed concise alias for the compatible `--reasoning-effort VALUE` option; do not pass both in one command.

## OpenAI quick start

The upstream authentication behavior remains available:

```bash
open-security login
open-security scan .
```

For CI, set `OPENAI_API_KEY` or `CODEX_API_KEY`. If both a stored ChatGPT sign-in and an environment API key are available, interactive scans ask which credential to use; noninteractive scans retain API-key precedence.

## Configuration environment variables

| Variable                                           | Purpose                                                                               |
| -------------------------------------------------- | ------------------------------------------------------------------------------------- |
| `OPEN_SECURITY_PROVIDER`                           | Default provider: `openai` or `openrouter`                                            |
| `OPEN_SECURITY_MODEL`                              | Default model ID; required for OpenRouter                                             |
| `OPEN_SECURITY_REASONING_EFFORT`                   | Default reasoning effort                                                              |
| `OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS`       | OpenRouter standard-scan output reservation cap (`1`–`65536`; default `16384`)        |
| `OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS` | Bridge-local minimum between upstream request starts in ms (`0`–`60000`; default `0`) |
| `OPEN_SECURITY_OPENROUTER_MAX_RETRIES`             | Pre-stream 429 retry count (`0`–`5`; default `3`)                                     |
| `OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS`     | Missing-header exponential retry base (`1000`–`300000`; default `30000`)              |
| `OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS`      | Maximum accepted or calculated retry delay (`1000`–`300000`; default `120000`)        |
| `OPEN_SECURITY_MAX_COST_USD`                       | Positive live estimated-cost limit for an individual standard scan                    |
| `OPEN_SECURITY_STATE_DIR`                          | Workbench state directory; preferred fork name                                        |
| `OPEN_SECURITY_NO_UPDATE_NOTICE`                   | Disable interactive update notices when set                                           |
| `OPEN_SECURITY_NPM_REGISTRY`                       | Registry base URL used only for update checks                                         |
| `OPENROUTER_API_KEY`                               | OpenRouter API credential                                                             |
| `OPENAI_API_KEY`                                   | OpenAI API credential                                                                 |
| `CODEX_API_KEY`                                    | Backward-compatible OpenAI API credential alias                                       |
| `CODEX_SECURITY_STATE_DIR`                         | Backward-compatible state-directory alias                                             |

Explicit CLI or SDK values take precedence over environment defaults. Saved scan recipes record the provider and safe model configuration, but never credentials.

## Pricing and cost limits

For OpenRouter, Open Security fetches `https://openrouter.ai/api/v1/models` and the selected model's exact `/api/v1/models/{author}/{slug}/endpoints` record without authentication. Prices are parsed from decimal strings without floating-point arithmetic. The scanner uses the maximum advertised rate for each token and request category across the base record, every current endpoint, and every conditional override.

The estimate accounts for input, cached input, cache-write input, and output tokens. A model with no advertised provider endpoint, a nonzero per-request fee, or any other nonzero billing category is rejected for standard scans because the runtime cannot yet account for it reliably. Catalog data is cached for one hour within a running process.

`--max-cost` and `OPEN_SECURITY_MAX_COST_USD` are live estimated-cost guardrails for individual standard scans. The scanner stops the parent scan and parent-linked delegated workers after the observed estimate crosses the limit, preserving partial results. Requests already in flight can finish above the configured amount, so the limit is not a provider-side spending cap.

For OpenRouter standard scans, `OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS` separately limits each Responses request's output reservation. Missing or larger `max_output_tokens` values are clamped to `16384` by default; valid lower values are preserved. This reduces provider-side credit reservations, latency, and rate-limit pressure without replacing the cumulative USD guardrail.

Set `OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS` to a decimal integer from `0` through `60000` to pace upstream Responses request starts within one standard-scan bridge. For example, `10000` enforces at least ten seconds between starts. The default `0` disables proactive pacing. This setting is local to one bridge and does not coordinate separate Open Security processes or other API clients; invalid values fail closed.

The bridge retries only pre-stream HTTP `429` responses, where the buffered request can be replayed without exposing partial output. `503` and other potentially accepted failures are not replayed without a documented upstream idempotency guarantee. It honors bounded delta-seconds and HTTP-date `Retry-After` headers; when the header is absent, delays grow exponentially from `OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS`. `OPEN_SECURITY_OPENROUTER_MAX_RETRIES` defaults to `3`, and `OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS` defaults to `120000`. A delay above that cap is not retried, mid-stream failures are never replayed, closing the client cancels pending waits, and every retry re-enters the same pacing and capacity gates. Set the retry count to `0` to disable this behavior.

The cost environment variable fails closed for `bulk-scan`, `validate`, `patch`, and model-backed `scans match`; these paths do not yet have reliable campaign-wide or turn-level accounting. Cached or empty matching and deterministic `scans compare` remain available without model spend. Deep scans cannot use a cost limit.

## Credential isolation

Open Security keeps provider credentials separated:

- OpenRouter scans remove OpenAI credentials from the model environment.
- OpenAI scans remove OpenRouter credentials from the model environment.
- Python, workbench, export, and other helper processes receive no model-provider credentials.
- OpenRouter keys are read from the environment at launch and are not persisted by the CLI's login machinery, saved in scan recipes, or placed in the Codex child process.
- Standard OpenRouter scans bind an opaque, ephemeral bridge route on `127.0.0.1`; ambient forward-proxy variables are removed from the model process, and the bridge closes with the SDK client.
- Codex authenticates to that route with a random bridge-only credential. The host substitutes the current OpenRouter key only on the fixed upstream request, so key rotation does not require rebuilding the client.
- The bridge URL is written only to the isolated runtime configuration, never to scan recipes or the readable preflight snapshot.
- OpenRouter deep scans are rejected for now because the credential bridge and aggregate cost accounting have not yet been validated across independent delegated workers. Standard OpenRouter scans are supported.

Use a secret manager or ephemeral environment injection instead of committing keys to files.

## TypeScript SDK

The upstream class name is retained for API compatibility:

```ts
import { CodexSecurity } from "@masonjames/open-security";

const security = new CodexSecurity({
  provider: "openrouter",
  codexOverrides: {
    model: "qwen/qwen3.7-flash",
    model_reasoning_effort: "high",
  },
});

try {
  const result = await security.run(".", { maxCostUsd: 1 });
  console.log(result.reportPath);
} finally {
  await security.close();
}
```

See [sdk/typescript/README.md](sdk/typescript/README.md) for scan modes, history, exports, CI behavior, and the full SDK surface.

For complete command help, runtime defaults, native multi-agent worker limits,
environment variables, deep-scan configuration, and SDK options, also see the
[official CLI reference](https://learn.chatgpt.com/docs/security/cli/reference).

## Development

```bash
pnpm --dir sdk/typescript run types
pnpm --dir sdk/typescript run test
pnpm --dir sdk/typescript run format
pnpm --dir sdk/typescript run build
pnpm --dir sdk/typescript pack --pack-destination ../../dist
pnpm --dir sdk/typescript run check:package ../../dist/*.tgz
```

The repository keeps OpenAI's repository as the `upstream` remote so upstream changes can be reviewed and merged deliberately. Provider-specific changes should stay at the CLI/SDK boundary where possible; internal plugin names and artifact contracts remain stable.

## Security and license

Read [SECURITY.md](SECURITY.md) before reporting a vulnerability or sharing scan artifacts. Scan only code you own or have explicit permission to assess.

Open Security is distributed under the [Apache License 2.0](LICENSE). The original Codex Security work remains copyright OpenAI; fork-specific changes are maintained by Mason James and contributors.
