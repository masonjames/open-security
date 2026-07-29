import { createServer, type IncomingMessage } from "node:http";
import { mkdtemp, realpath, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { Codex } from "@openai/codex-sdk";
import { expect, test } from "bun:test";
import { createOpenRouterResponsesBridge } from "../src/openrouter-responses-bridge.js";

const MODEL_ID = "qwen/qwen3.7-flash";
const SYNTHETIC_UPSTREAM_API_KEY = "synthetic-openrouter-upstream-key";
const SYNTHETIC_UPSTREAM_AUTHORIZATION = `Bearer ${SYNTHETIC_UPSTREAM_API_KEY}`;

async function readBody(request: IncomingMessage): Promise<string> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks).toString("utf8");
}

function timeoutAfter(milliseconds: number): Promise<never> {
  return new Promise((_, reject) => {
    const timeout = setTimeout(
      () => reject(new Error("Pinned Codex did not reach the bridge in time")),
      milliseconds,
    );
    timeout.unref();
  });
}

test("the pinned Codex client reaches the exact bridged Responses route with a clamped request", async () => {
  let resolveCaptured:
    | ((value: {
        body: Record<string, unknown>;
        headers: IncomingMessage["headers"];
        url: string | undefined;
      }) => void)
    | undefined;
  const captured = new Promise<{
    body: Record<string, unknown>;
    headers: IncomingMessage["headers"];
    url: string | undefined;
  }>((resolve) => {
    resolveCaptured = resolve;
  });
  const upstream = createServer((request, response) => {
    void (async () => {
      resolveCaptured?.({
        body: JSON.parse(await readBody(request)) as Record<string, unknown>,
        headers: request.headers,
        url: request.url,
      });
      response.writeHead(401, { "content-type": "application/json" });
      response.end(
        JSON.stringify({
          error: {
            code: "synthetic_rejection",
            message: "Synthetic local rejection.",
            type: "invalid_request_error",
          },
        }),
      );
    })().catch(() => response.destroy());
  });
  await new Promise<void>((resolve, reject) => {
    upstream.once("error", reject);
    upstream.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = upstream.address();
  expect(address).not.toBeNull();
  expect(typeof address).not.toBe("string");
  const upstreamBaseUrl = new URL(
    `http://127.0.0.1:${typeof address === "string" || address === null ? 0 : address.port}/api/v1/`,
  );
  const bridge = await createOpenRouterResponsesBridge(
    {
      expectedModel: MODEL_ID,
      getUpstreamApiKey: () => SYNTHETIC_UPSTREAM_API_KEY,
      maxOutputTokens: 16_384,
    },
    { upstreamBaseUrl },
  );
  const codexHome = await realpath(
    await mkdtemp(join(tmpdir(), "open-security-bridge-codex-")),
  );
  const controller = new AbortController();
  const abortTimeout = setTimeout(() => controller.abort(), 15_000);
  abortTimeout.unref();

  try {
    const codex = new Codex({
      env: {
        CODEX_HOME: codexHome,
        HOME: codexHome,
        LANG: process.env["LANG"] ?? "C.UTF-8",
        NO_PROXY: "127.0.0.1,localhost",
        OPENROUTER_API_KEY: bridge.credential,
        PATH: process.env["PATH"] ?? "/usr/bin:/bin",
        no_proxy: "127.0.0.1,localhost",
      },
      config: {
        model: MODEL_ID,
        model_provider: "openrouter",
        "model_providers.openrouter.name": "OpenRouter",
        "model_providers.openrouter.base_url": bridge.baseUrl,
        "model_providers.openrouter.env_key": "OPENROUTER_API_KEY",
        "model_providers.openrouter.wire_api": "responses",
        "features.enable_request_compression": false,
        "features.responses_websockets": false,
        "features.responses_websockets_v2": false,
        "features.remote_compaction_v2": false,
      },
    });
    const thread = codex.startThread({
      approvalPolicy: "never",
      sandboxMode: "read-only",
      skipGitRepoCheck: true,
      workingDirectory: codexHome,
    });

    try {
      const { events } = await thread.runStreamed("Reply with one word.", {
        signal: controller.signal,
      });
      for await (const _event of events) {
        // A local 401 is expected; consuming the stream drives the real request.
      }
    } catch {
      // The fake upstream intentionally rejects the request after capture.
    }

    const request = await Promise.race([captured, timeoutAfter(10_000)]);
    expect(request.url).toBe("/api/v1/responses");
    expect(bridge.credential).not.toBe(SYNTHETIC_UPSTREAM_API_KEY);
    expect(request.headers.authorization).toBe(
      SYNTHETIC_UPSTREAM_AUTHORIZATION,
    );
    expect(request.headers["content-encoding"]).toBeUndefined();
    expect(request.headers.accept).toBe("text/event-stream");
    expect(request.body["model"]).toBe(MODEL_ID);
    expect(request.body["stream"]).toBe(true);
    expect(request.body["max_output_tokens"]).toBe(16_384);
  } finally {
    clearTimeout(abortTimeout);
    controller.abort();
    await bridge.close();
    await new Promise<void>((resolve) => upstream.close(() => resolve()));
    await rm(codexHome, { recursive: true, force: true });
  }
});
