import { afterEach, describe, expect, test } from "bun:test";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type ServerResponse,
} from "node:http";
import { createConnection, type AddressInfo, type Socket } from "node:net";
import { performance } from "node:perf_hooks";
import {
  createOpenRouterResponsesBridge,
  type OpenRouterResponsesBridge,
} from "../src/openrouter-responses-bridge.js";

const MODEL_ID = "qwen/qwen3.7-flash";
const UPSTREAM_API_KEY = "sk-or-v1-upstream-test-only";
const UPSTREAM_AUTHORIZATION = `Bearer ${UPSTREAM_API_KEY}`;

function bridgeAuthorization(bridge: OpenRouterResponsesBridge): string {
  return `Bearer ${bridge.credential}`;
}

interface TestServer {
  readonly baseUrl: string;
  close(): Promise<void>;
}

interface RawResponse {
  readonly body: Buffer;
  readonly headers: IncomingMessage["headers"];
  readonly status: number;
}

const bridges: OpenRouterResponsesBridge[] = [];
const upstreams: TestServer[] = [];

async function startServer(
  handler: (request: IncomingMessage, response: ServerResponse) => void,
): Promise<TestServer> {
  const server = createServer(handler);
  const sockets = new Set<Socket>();
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });
  await new Promise<void>((resolve, reject) => {
    server.once("error", reject);
    server.listen({ host: "127.0.0.1", port: 0 }, resolve);
  });
  const address = server.address() as AddressInfo;

  let closePromise: Promise<void> | undefined;
  const result: TestServer = {
    baseUrl: `http://127.0.0.1:${address.port}`,
    close(): Promise<void> {
      closePromise ??= new Promise<void>((resolve, reject) => {
        server.close((error) => {
          if (error === undefined) resolve();
          else reject(error);
        });
        for (const socket of sockets) socket.destroy();
        server.closeAllConnections();
      });
      return closePromise;
    },
  };
  upstreams.push(result);
  return result;
}

async function createBridge(
  upstream: TestServer,
  maxOutputTokens = 16_384,
  fetchImplementation: typeof globalThis.fetch = globalThis.fetch,
  minRequestIntervalMs = 0,
  getUpstreamApiKey: () => string = () => UPSTREAM_API_KEY,
): Promise<OpenRouterResponsesBridge> {
  const bridge = await createOpenRouterResponsesBridge(
    {
      expectedModel: MODEL_ID,
      getUpstreamApiKey,
      maxOutputTokens,
      minRequestIntervalMs,
    },
    {
      fetch: fetchImplementation,
      upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`),
    },
  );
  bridges.push(bridge);
  return bridge;
}

function validBody(overrides: Record<string, unknown> = {}): string {
  return JSON.stringify({ model: MODEL_ID, stream: true, ...overrides });
}

function bridgeRequest(
  bridge: OpenRouterResponsesBridge,
  body = validBody(),
  init: RequestInit = {},
): Promise<Response> {
  const headers = new Headers(init.headers);
  if (!headers.has("authorization"))
    headers.set("authorization", bridgeAuthorization(bridge));
  if (!headers.has("content-type"))
    headers.set("content-type", "application/json");
  return fetch(`${bridge.baseUrl}/responses`, {
    ...init,
    body,
    headers,
    method: "POST",
  });
}

async function readBody(request: IncomingMessage): Promise<Buffer> {
  const chunks: Buffer[] = [];
  for await (const chunk of request) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function rawRequest(
  url: string,
  headers: readonly string[],
  body?: Buffer,
): Promise<RawResponse> {
  const target = new URL(url);
  return new Promise<RawResponse>((resolve, reject) => {
    const request = httpRequest(
      {
        headers,
        host: target.hostname,
        method: "POST",
        path: `${target.pathname}${target.search}`,
        port: target.port,
      },
      (response) => {
        const chunks: Buffer[] = [];
        response.on("data", (chunk: Buffer) => chunks.push(chunk));
        response.once("end", () => {
          resolve({
            body: Buffer.concat(chunks),
            headers: response.headers,
            status: response.statusCode ?? 0,
          });
        });
      },
    );
    request.once("error", reject);
    if (body !== undefined) request.write(body);
    request.end();
  });
}

function timeoutAfter(milliseconds: number): Promise<never> {
  return new Promise((_, reject) => {
    setTimeout(() => reject(new Error("Timed out")), milliseconds);
  });
}

async function waitFor(condition: () => boolean): Promise<void> {
  const deadline = Date.now() + 1_000;
  while (!condition()) {
    if (Date.now() >= deadline) throw new Error("Timed out");
    await Bun.sleep(5);
  }
}

function rawHeadersOnlyRequest(
  url: string,
  authorization: string,
  contentLength?: number,
): Promise<number> {
  const target = new URL(url);
  return new Promise<number>((resolve, reject) => {
    const socket = createConnection(
      { host: target.hostname, port: Number(target.port) },
      () => {
        socket.write(
          [
            `POST ${target.pathname} HTTP/1.1`,
            `Host: ${target.host}`,
            `Authorization: ${authorization}`,
            "Content-Type: application/json",
            contentLength === undefined
              ? "Transfer-Encoding: chunked"
              : `Content-Length: ${contentLength}`,
            "Connection: close",
            "",
            "",
          ].join("\r\n"),
        );
      },
    );
    let response = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk: string) => {
      response += chunk;
      const match = /^HTTP\/1\.1 (\d{3}) /.exec(response);
      if (match?.[1] !== undefined) {
        resolve(Number(match[1]));
        socket.destroy();
      }
    });
    socket.once("error", reject);
    socket.once("close", () => {
      if (response.length === 0) reject(new Error("No HTTP response"));
    });
  });
}

afterEach(async () => {
  await Promise.allSettled(bridges.splice(0).map((bridge) => bridge.close()));
  await Promise.allSettled(upstreams.splice(0).map((server) => server.close()));
});

describe("OpenRouter Responses bridge", () => {
  test("binds an opaque loopback route, rewrites the request, and streams SSE", async () => {
    let captured:
      | {
          body: Record<string, unknown>;
          headers: IncomingMessage["headers"];
          method: string | undefined;
          url: string | undefined;
        }
      | undefined;
    let releaseSecondChunk: (() => void) | undefined;
    const secondChunkReady = new Promise<void>((resolve) => {
      releaseSecondChunk = resolve;
    });
    const upstream = await startServer((request, response) => {
      void (async () => {
        captured = {
          body: JSON.parse(
            (await readBody(request)).toString("utf8"),
          ) as Record<string, unknown>,
          headers: request.headers,
          method: request.method,
          url: request.url,
        };
        response.writeHead(200, { "content-type": "text/event-stream" });
        response.write("data: first\n\n");
        await secondChunkReady;
        response.end("data: second\n\n");
      })();
    });
    const bridge = await createBridge(upstream, 12_345);

    expect(bridge.baseUrl).toMatch(
      /^http:\/\/127\.0\.0\.1:\d+\/[A-Za-z0-9_-]{43}\/api\/v1$/,
    );
    const responsePromise = bridgeRequest(
      bridge,
      validBody({ input: "hello" }),
      {
        headers: {
          accept: "text/event-stream",
          "x-must-not-forward": "private-metadata",
        },
      },
    );
    const response = await responsePromise;
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "text/event-stream; charset=utf-8",
    );
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");

    const reader = response.body?.getReader();
    expect(reader).toBeDefined();
    const first = await reader?.read();
    expect(new TextDecoder().decode(first?.value)).toBe("data: first\n\n");

    let secondSettled = false;
    const secondPromise = reader?.read().then((value) => {
      secondSettled = true;
      return value;
    });
    await Bun.sleep(20);
    expect(secondSettled).toBe(false);
    releaseSecondChunk?.();
    const second = await secondPromise;
    expect(new TextDecoder().decode(second?.value)).toBe("data: second\n\n");
    expect((await reader?.read())?.done).toBe(true);

    expect(captured?.method).toBe("POST");
    expect(captured?.url).toBe("/api/v1/responses");
    expect(captured?.body).toEqual({
      input: "hello",
      max_output_tokens: 12_345,
      model: MODEL_ID,
      stream: true,
    });
    expect(captured?.headers.authorization).toBe(UPSTREAM_AUTHORIZATION);
    expect(captured?.headers["content-type"]).toBe("application/json");
    expect(captured?.headers.accept).toBe("text/event-stream");
    expect(captured?.headers["accept-encoding"]).toBe("identity");
    expect(captured?.headers["x-must-not-forward"]).toBeUndefined();
  });

  test("clamps high valid max_output_tokens and preserves a lower value", async () => {
    const received: Record<string, unknown>[] = [];
    const upstream = await startServer((request, response) => {
      void (async () => {
        received.push(
          JSON.parse((await readBody(request)).toString("utf8")) as Record<
            string,
            unknown
          >,
        );
        response.writeHead(200, { "content-type": "text/event-stream" });
        response.end("data: done\n\n");
      })();
    });
    const bridge = await createBridge(upstream, 8_192);

    expect(
      await (
        await bridgeRequest(bridge, validBody({ max_output_tokens: 65_536 }))
      ).text(),
    ).toBe("data: done\n\n");
    expect(
      await (
        await bridgeRequest(bridge, validBody({ max_output_tokens: 1_024 }))
      ).text(),
    ).toBe("data: done\n\n");
    expect(received.map((body) => body["max_output_tokens"])).toEqual([
      8_192, 1_024,
    ]);
  });

  test("paces concurrent valid upstream starts by the configured interval", async () => {
    const minRequestIntervalMs = 80;
    const startedAt: number[] = [];
    const recordingFetch: typeof globalThis.fetch = Object.assign(
      (...args: Parameters<typeof globalThis.fetch>) => {
        startedAt.push(performance.now());
        return globalThis.fetch(...args);
      },
      { preconnect: globalThis.fetch.preconnect },
    );
    const upstream = await startServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end("data: done\n\n");
    });
    const bridge = await createBridge(
      upstream,
      16_384,
      recordingFetch,
      minRequestIntervalMs,
    );

    const responses = await Promise.all(
      Array.from({ length: 4 }, () => bridgeRequest(bridge)),
    );
    expect(
      await Promise.all(responses.map((response) => response.text())),
    ).toEqual(Array.from({ length: 4 }, () => "data: done\n\n"));
    expect(startedAt).toHaveLength(4);
    for (let index = 1; index < startedAt.length; index += 1) {
      expect(
        (startedAt[index] ?? 0) - (startedAt[index - 1] ?? 0),
      ).toBeGreaterThanOrEqual(minRequestIntervalMs - 1);
    }
  });

  test("bounds the paced queue without starting upstream work or rereading the key", async () => {
    const minRequestIntervalMs = 10_000;
    let fetchStarts = 0;
    let keyReads = 0;
    const stalledFetch: typeof globalThis.fetch = Object.assign(
      (...args: Parameters<typeof globalThis.fetch>): Promise<Response> => {
        fetchStarts += 1;
        return new Promise<Response>((_resolve, reject) => {
          const signal = args[1]?.signal;
          const rejectAbort = (): void => {
            const error = new Error("Request aborted");
            error.name = "AbortError";
            reject(error);
          };
          if (signal?.aborted === true) rejectAbort();
          else signal?.addEventListener("abort", rejectAbort, { once: true });
        });
      },
      { preconnect: globalThis.fetch.preconnect },
    );
    const upstream = await startServer((_request, response) => response.end());
    const bridge = await createBridge(
      upstream,
      16_384,
      stalledFetch,
      minRequestIntervalMs,
      () => {
        keyReads += 1;
        return UPSTREAM_API_KEY;
      },
    );
    expect(keyReads).toBe(1);

    const body = Buffer.from(validBody());
    const requests = Array.from({ length: 18 }, () =>
      rawRequest(
        `${bridge.baseUrl}/responses`,
        [
          "Authorization",
          bridgeAuthorization(bridge),
          "Content-Type",
          "application/json",
          "Content-Length",
          String(body.byteLength),
        ],
        body,
      ),
    );
    const overflow = await Promise.race(requests);
    expect(overflow.status).toBe(429);
    expect(JSON.parse(overflow.body.toString("utf8"))).toEqual({
      error: {
        code: "rate_limit_exceeded",
        message: "Bridge request capacity reached. Retry later.",
        type: "rate_limit_error",
      },
    });
    expect(Number(overflow.headers["retry-after"])).toBeGreaterThanOrEqual(1);
    expect(Number(overflow.headers["retry-after"])).toBeLessThanOrEqual(10);
    expect(fetchStarts).toBe(1);
    expect(keyReads).toBe(2);

    await bridge.close();
    await Promise.allSettled(requests);
  });

  test("reserves declared and chunked body bytes before buffering", async () => {
    let keyReads = 0;
    let upstreamRequests = 0;
    const upstream = await startServer((_request, response) => {
      upstreamRequests += 1;
      response.end();
    });

    for (const contentLength of [24 * 1024 * 1024, undefined] as const) {
      const bridge = await createBridge(
        upstream,
        16_384,
        globalThis.fetch,
        10_000,
        () => {
          keyReads += 1;
          return UPSTREAM_API_KEY;
        },
      );
      const heldRequests = Array.from({ length: 2 }, () =>
        rawHeadersOnlyRequest(
          `${bridge.baseUrl}/responses`,
          bridgeAuthorization(bridge),
          contentLength,
        ).catch(() => 0),
      );
      await Bun.sleep(50);

      const rejectedStatus = await rawHeadersOnlyRequest(
        `${bridge.baseUrl}/responses`,
        bridgeAuthorization(bridge),
        contentLength,
      );
      expect(rejectedStatus).toBe(429);

      await bridge.close();
      await Promise.allSettled(heldRequests);
    }
    expect(keyReads).toBe(2);
    expect(upstreamRequests).toBe(0);
  });

  test("local request and credential failures do not consume pacing slots", async () => {
    const minRequestIntervalMs = 500;
    const startedAt: number[] = [];
    const recordingFetch: typeof globalThis.fetch = Object.assign(
      (...args: Parameters<typeof globalThis.fetch>) => {
        startedAt.push(performance.now());
        return globalThis.fetch(...args);
      },
      { preconnect: globalThis.fetch.preconnect },
    );
    const upstream = await startServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end("data: done\n\n");
    });
    let apiKey = UPSTREAM_API_KEY;
    let keyReads = 0;
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => {
          keyReads += 1;
          return apiKey;
        },
        maxOutputTokens: 16_384,
        minRequestIntervalMs,
      },
      {
        fetch: recordingFetch,
        upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`),
      },
    );
    bridges.push(bridge);
    expect(keyReads).toBe(1);

    const invalidBody = await bridgeRequest(
      bridge,
      validBody({ model: "other/model" }),
    );
    expect(invalidBody.status).toBe(400);
    expect(keyReads).toBe(1);
    expect(startedAt).toHaveLength(0);

    apiKey = " invalid ";
    const invalidCredential = await bridgeRequest(bridge);
    expect(invalidCredential.status).toBe(401);
    expect(keyReads).toBe(2);
    expect(startedAt).toHaveLength(0);

    apiKey = UPSTREAM_API_KEY;
    const requestedAt = performance.now();
    expect(await (await bridgeRequest(bridge)).text()).toBe("data: done\n\n");
    expect(
      (startedAt[0] ?? Number.POSITIVE_INFINITY) - requestedAt,
    ).toBeLessThan(minRequestIntervalMs / 2);
  });

  test("uses a generic 404 for every route or method mismatch without upstream access", async () => {
    let upstreamRequests = 0;
    const upstream = await startServer((_request, response) => {
      upstreamRequests += 1;
      response.end();
    });
    const bridge = await createBridge(upstream);

    for (const [url, method] of [
      [`${bridge.baseUrl}/responses?debug=1`, "POST"],
      [`${bridge.baseUrl}/other`, "POST"],
      [`${bridge.baseUrl}/responses`, "GET"],
    ] as const) {
      const response = await fetch(url, { method });
      expect(response.status).toBe(404);
      expect(await response.json()).toEqual({
        error: {
          code: "not_found",
          message: "Not found.",
          type: "invalid_request_error",
        },
      });
    }
    expect(upstreamRequests).toBe(0);
  });

  test("requires one syntactically valid Bearer authorization header", async () => {
    let upstreamRequests = 0;
    const upstream = await startServer((_request, response) => {
      upstreamRequests += 1;
      response.end();
    });
    const bridge = await createBridge(upstream);
    const target = `${bridge.baseUrl}/responses`;
    const body = Buffer.from(validBody());
    expect(bridge.credential).not.toBe(UPSTREAM_API_KEY);

    const missing = await rawRequest(
      target,
      [
        "Content-Type",
        "application/json",
        "Content-Length",
        String(body.byteLength),
      ],
      body,
    );
    expect(missing.status).toBe(401);

    const duplicate = await rawRequest(
      target,
      [
        "Authorization",
        bridgeAuthorization(bridge),
        "Authorization",
        "Bearer second-token",
        "Content-Type",
        "application/json",
        "Content-Length",
        String(body.byteLength),
      ],
      body,
    );
    expect(duplicate.status).toBe(401);

    const malformed = await rawRequest(
      target,
      [
        "Authorization",
        "Bearer first, Bearer second",
        "Content-Type",
        "application/json",
        "Content-Length",
        String(body.byteLength),
      ],
      body,
    );
    expect(malformed.status).toBe(401);

    const providerCredential = await rawRequest(
      target,
      [
        "Authorization",
        UPSTREAM_AUTHORIZATION,
        "Content-Type",
        "application/json",
        "Content-Length",
        String(body.byteLength),
      ],
      body,
    );
    expect(providerCredential.status).toBe(401);
    expect(upstreamRequests).toBe(0);
  });

  test("reads the upstream key at request time without exposing it downstream", async () => {
    const authorizations: Array<string | undefined> = [];
    const upstream = await startServer((request, response) => {
      authorizations.push(request.headers.authorization);
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end("data: done\n\n");
    });
    let upstreamApiKey = "sk-or-v1-first-test-only";
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => upstreamApiKey,
        maxOutputTokens: 16_384,
      },
      {
        upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`),
      },
    );
    bridges.push(bridge);

    expect(await (await bridgeRequest(bridge)).text()).toBe("data: done\n\n");
    upstreamApiKey = "sk-or-v1-second-test-only";
    expect(await (await bridgeRequest(bridge)).text()).toBe("data: done\n\n");
    expect(authorizations).toEqual([
      "Bearer sk-or-v1-first-test-only",
      "Bearer sk-or-v1-second-test-only",
    ]);
    expect(bridge.credential).not.toBe(upstreamApiKey);
  });

  test("rejects invalid media, compression, UTF-8, JSON shape, model, stream, and token limits", async () => {
    let upstreamRequests = 0;
    const upstream = await startServer((_request, response) => {
      upstreamRequests += 1;
      response.end();
    });
    const bridge = await createBridge(upstream);

    const invalidRequests: Array<Promise<Response>> = [
      bridgeRequest(bridge, validBody(), {
        headers: { "content-type": "text/plain" },
      }),
      bridgeRequest(bridge, validBody(), {
        headers: { "content-encoding": "gzip" },
      }),
      bridgeRequest(bridge, "[]"),
      bridgeRequest(bridge, "not-json"),
      bridgeRequest(bridge, validBody({ model: "other/model" })),
      bridgeRequest(bridge, validBody({ stream: false })),
      bridgeRequest(bridge, validBody({ max_output_tokens: 0 })),
      bridgeRequest(bridge, validBody({ max_output_tokens: 65_537 })),
      bridgeRequest(bridge, validBody({ max_output_tokens: 1.5 })),
      bridgeRequest(bridge, validBody({ max_output_tokens: "1024" })),
    ];
    const responses = await Promise.all(invalidRequests);
    expect(responses.map((response) => response.status)).toEqual([
      415, 415, 400, 400, 400, 400, 400, 400, 400, 400,
    ]);

    const invalidUtf8 = Buffer.from([0xff]);
    const raw = await rawRequest(
      `${bridge.baseUrl}/responses`,
      [
        "Authorization",
        bridgeAuthorization(bridge),
        "Content-Type",
        "application/json",
        "Content-Length",
        String(invalidUtf8.byteLength),
      ],
      invalidUtf8,
    );
    expect(raw.status).toBe(400);
    expect(upstreamRequests).toBe(0);
  });

  test("rejects excessive JSON depth before upstream access", async () => {
    let upstreamRequests = 0;
    const upstream = await startServer((_request, response) => {
      upstreamRequests += 1;
      response.end();
    });
    const bridge = await createBridge(upstream);
    let nested: Record<string, unknown> = {};
    for (let depth = 0; depth < 65; depth += 1) {
      nested = { nested };
    }

    const response = await bridgeRequest(bridge, validBody({ input: nested }));
    expect(response.status).toBe(400);
    expect(response.headers.get("x-content-type-options")).toBe("nosniff");
    expect(upstreamRequests).toBe(0);
  });

  test("rejects a declared body above the fixed 32 MiB cap", async () => {
    const upstream = await startServer((_request, response) => response.end());
    const bridge = await createBridge(upstream);

    const status = await rawHeadersOnlyRequest(
      `${bridge.baseUrl}/responses`,
      bridgeAuthorization(bridge),
      32 * 1024 * 1024 + 1,
    );
    expect(status).toBe(413);
  });

  test("preserves an upstream error status and bounded numeric Retry-After without leaking its body", async () => {
    let requests = 0;
    const upstream = await startServer((_request, response) => {
      requests += 1;
      response.writeHead(429, {
        "content-type": "application/json",
        "retry-after": requests === 1 ? "17" : "999999",
      });
      response.end('{"secret":"must-not-cross-bridge"}');
    });
    const bridge = await createBridge(upstream);

    const first = await bridgeRequest(bridge);
    expect(first.status).toBe(429);
    expect(first.headers.get("retry-after")).toBe("17");
    expect(await first.json()).toEqual({
      error: {
        code: "upstream_error",
        message: "Upstream request failed.",
        type: "upstream_error",
      },
    });

    const second = await bridgeRequest(bridge);
    expect(second.status).toBe(429);
    expect(second.headers.get("retry-after")).toBeNull();
    expect(await second.text()).not.toContain("must-not-cross-bridge");
  });

  test("retries bounded pre-stream 429 responses before exposing SSE", async () => {
    let requests = 0;
    let keyReads = 0;
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      if (requests === 1) {
        response.writeHead(429, {
          "content-type": "application/json",
          "retry-after": new Date(0).toUTCString(),
        });
        response.end('{"secret":"first-rate-limit"}');
        return;
      }
      if (requests === 2) {
        response.writeHead(429, { "content-type": "application/json" });
        response.end('{"secret":"second-rate-limit"}');
        return;
      }
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end("data: done\n\n");
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => {
          keyReads += 1;
          return UPSTREAM_API_KEY;
        },
        maxOutputTokens: 16_384,
        maxRetries: 2,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 100,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("data: done\n\n");
    expect(requests).toBe(3);
    expect(keyReads).toBe(4);
  });

  test("accepts leading-zero delta-seconds before retrying a 429", async () => {
    let requests = 0;
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      if (requests === 1) {
        response.writeHead(429, {
          "content-type": "application/json",
          "retry-after": "01",
        });
        response.end('{"secret":"first-rate-limit"}');
        return;
      }
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.end("data: done\n\n");
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => UPSTREAM_API_KEY,
        maxOutputTokens: 16_384,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 1_000,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("data: done\n\n");
    expect(requests).toBe(2);
  });

  test("rejects non-HTTP dates that Date.parse would otherwise accept", async () => {
    let requests = 0;
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      response.writeHead(429, {
        "content-type": "application/json",
        "retry-after": "01/02/2026",
      });
      response.end('{"secret":"must-not-cross-bridge"}');
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => UPSTREAM_API_KEY,
        maxOutputTokens: 16_384,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 1_000,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(429);
    expect(response.headers.get("retry-after")).toBeNull();
    expect(await response.text()).not.toContain("must-not-cross-bridge");
    expect(requests).toBe(1);
  });

  test("does not replay 503 responses without an idempotency guarantee", async () => {
    let requests = 0;
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      response.writeHead(503, {
        "content-type": "application/json",
        "retry-after": "0",
      });
      response.end('{"secret":"possibly-accepted-work"}');
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => UPSTREAM_API_KEY,
        maxOutputTokens: 16_384,
        maxRetries: 5,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 100,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(503);
    expect(await response.text()).not.toContain("possibly-accepted-work");
    expect(requests).toBe(1);
  });

  test("does not retry HTTP-date Retry-After beyond the configured delay cap", async () => {
    let requests = 0;
    const retryAt = new Date(Date.now() + 60_000).toUTCString();
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      response.writeHead(429, {
        "content-type": "application/json",
        "retry-after": retryAt,
      });
      response.end('{"secret":"must-not-cross-bridge"}');
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => UPSTREAM_API_KEY,
        maxOutputTokens: 16_384,
        maxRetries: 2,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 100,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(429);
    const retryAfter = Number(response.headers.get("retry-after"));
    expect(retryAfter).toBeGreaterThanOrEqual(55);
    expect(retryAfter).toBeLessThanOrEqual(60);
    expect(await response.text()).not.toContain("must-not-cross-bridge");
    expect(requests).toBe(1);
  });

  test("close cancels a pending retry without rereading the key", async () => {
    let requests = 0;
    let keyReads = 0;
    const upstream = await startServer((request, response) => {
      request.resume();
      requests += 1;
      response.writeHead(429, {
        "content-type": "application/json",
        "retry-after": "60",
      });
      response.end();
    });
    const bridge = await createOpenRouterResponsesBridge(
      {
        expectedModel: MODEL_ID,
        getUpstreamApiKey: () => {
          keyReads += 1;
          return UPSTREAM_API_KEY;
        },
        maxOutputTokens: 16_384,
        maxRetries: 1,
        retryBaseDelayMs: 1,
        maxRetryDelayMs: 60_000,
      },
      { upstreamBaseUrl: new URL(`${upstream.baseUrl}/api/v1/`) },
    );
    bridges.push(bridge);
    const request = bridgeRequest(bridge).then(
      () => undefined,
      () => undefined,
    );
    await waitFor(() => requests === 1);
    await Promise.race([bridge.close(), timeoutAfter(1_500)]);
    await Promise.race([request, timeoutAfter(1_000)]);
    await Bun.sleep(25);
    expect(requests).toBe(1);
    expect(keyReads).toBe(2);
  });

  test("rejects a successful non-SSE upstream response with a safe 502", async () => {
    const upstream = await startServer((_request, response) => {
      response.writeHead(200, { "content-type": "application/json" });
      response.end('{"secret":"unexpected-success"}');
    });
    const bridge = await createBridge(upstream);

    const response = await bridgeRequest(bridge);
    expect(response.status).toBe(502);
    expect(await response.json()).toEqual({
      error: {
        code: "upstream_error",
        message: "Upstream request failed.",
        type: "upstream_error",
      },
    });
  });

  // Bun does not propagate this client-abort path through its node:http shim.
  // The same invariant runs under supported Node 22 in the package smoke gate.
  test.skip("aborts the upstream stream when the downstream disconnects", async () => {
    let upstreamSignal: AbortSignal | undefined;
    const recordingFetch: typeof globalThis.fetch = Object.assign(
      (...args: Parameters<typeof globalThis.fetch>) => {
        upstreamSignal = args[1]?.signal ?? undefined;
        return globalThis.fetch(...args);
      },
      { preconnect: globalThis.fetch.preconnect },
    );
    const upstream = await startServer((_request, response) => {
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: first\n\n");
      const heartbeat = setInterval(
        () => response.write("data: heartbeat\n\n"),
        10,
      );
      response.once("close", () => clearInterval(heartbeat));
    });
    const bridge = await createBridge(upstream, 16_384, recordingFetch);
    const downstream = new AbortController();
    const response = await bridgeRequest(bridge, validBody(), {
      signal: downstream.signal,
    });
    const reader = response.body?.getReader();
    expect(new TextDecoder().decode((await reader?.read())?.value)).toContain(
      "data: first",
    );
    downstream.abort();

    await waitFor(() => upstreamSignal?.aborted === true);
  });

  test("close atomically rejects an overdue paced queue, aborts active fetches, and stops accepts", async () => {
    const minRequestIntervalMs = 250;
    let fetchStarts = 0;
    let keyReads = 0;
    let upstreamStarted: (() => void) | undefined;
    let upstreamSignal: AbortSignal | undefined;
    const started = new Promise<void>((resolve) => {
      upstreamStarted = resolve;
    });
    const recordingFetch: typeof globalThis.fetch = Object.assign(
      (...args: Parameters<typeof globalThis.fetch>) => {
        fetchStarts += 1;
        upstreamSignal = args[1]?.signal ?? undefined;
        return globalThis.fetch(...args);
      },
      { preconnect: globalThis.fetch.preconnect },
    );
    const upstream = await startServer((_request, response) => {
      upstreamStarted?.();
      response.writeHead(200, { "content-type": "text/event-stream" });
      response.write("data: pending\n\n");
    });
    const bridge = await createBridge(
      upstream,
      16_384,
      recordingFetch,
      minRequestIntervalMs,
      () => {
        keyReads += 1;
        return UPSTREAM_API_KEY;
      },
    );
    const response = await bridgeRequest(bridge);
    await started;
    expect(response.status).toBe(200);
    expect(keyReads).toBe(2);
    const queuedRequests = Array.from({ length: 2 }, () =>
      bridgeRequest(bridge).then(
        () => undefined,
        () => undefined,
      ),
    );
    await Bun.sleep(50);
    expect(fetchStarts).toBe(1);

    // Leave the timer overdue while this event-loop turn remains active, then
    // begin close before its callback can run.
    const overdueAt = performance.now() + minRequestIntervalMs + 25;
    while (performance.now() < overdueAt) {
      // Intentionally block this test turn.
    }
    const firstClose = bridge.close();
    const secondClose = bridge.close();
    expect(firstClose).toBe(secondClose);
    await Promise.race([firstClose, timeoutAfter(1_500)]);
    await waitFor(() => upstreamSignal?.aborted === true);
    await Promise.race([Promise.all(queuedRequests), timeoutAfter(1_000)]);
    await Bun.sleep(minRequestIntervalMs + 75);
    expect(fetchStarts).toBe(1);
    expect(keyReads).toBe(2);
    await expect(fetch(`${bridge.baseUrl}/responses`)).rejects.toBeDefined();
    await Promise.race([
      response.text().then(
        () => undefined,
        () => undefined,
      ),
      timeoutAfter(1_000),
    ]);
  });

  test("validates factory limits before opening a listener", async () => {
    for (const maxOutputTokens of [0, 65_537, 1.5, Number.NaN]) {
      await expect(
        createOpenRouterResponsesBridge({
          expectedModel: MODEL_ID,
          getUpstreamApiKey: () => UPSTREAM_API_KEY,
          maxOutputTokens,
        }),
      ).rejects.toBeInstanceOf(TypeError);
    }
    for (const minRequestIntervalMs of [
      -1,
      60_001,
      1.5,
      Number.NaN,
      Number.POSITIVE_INFINITY,
    ]) {
      await expect(
        createOpenRouterResponsesBridge({
          expectedModel: MODEL_ID,
          getUpstreamApiKey: () => UPSTREAM_API_KEY,
          maxOutputTokens: 1_024,
          minRequestIntervalMs,
        }),
      ).rejects.toBeInstanceOf(TypeError);
    }
    for (const maxRetries of [-1, 6, 1.5, Number.NaN]) {
      await expect(
        createOpenRouterResponsesBridge({
          expectedModel: MODEL_ID,
          getUpstreamApiKey: () => UPSTREAM_API_KEY,
          maxOutputTokens: 1_024,
          maxRetries,
        }),
      ).rejects.toBeInstanceOf(TypeError);
    }
    for (const retryDelayMs of [-1, 300_001, 1.5, Number.NaN]) {
      await expect(
        createOpenRouterResponsesBridge({
          expectedModel: MODEL_ID,
          getUpstreamApiKey: () => UPSTREAM_API_KEY,
          maxOutputTokens: 1_024,
          retryBaseDelayMs: retryDelayMs,
        }),
      ).rejects.toBeInstanceOf(TypeError);
    }
    for (const options of [
      { retryBaseDelayMs: 120_001 },
      { maxRetryDelayMs: 29_999 },
      { retryBaseDelayMs: 2, maxRetryDelayMs: 1 },
    ]) {
      await expect(
        createOpenRouterResponsesBridge({
          expectedModel: MODEL_ID,
          getUpstreamApiKey: () => UPSTREAM_API_KEY,
          maxOutputTokens: 1_024,
          ...options,
        }),
      ).rejects.toBeInstanceOf(TypeError);
    }
    await expect(
      createOpenRouterResponsesBridge({
        expectedModel: " ",
        getUpstreamApiKey: () => UPSTREAM_API_KEY,
        maxOutputTokens: 1_024,
      }),
    ).rejects.toBeInstanceOf(TypeError);

    const maxIntervalBridge = await createOpenRouterResponsesBridge({
      expectedModel: MODEL_ID,
      getUpstreamApiKey: () => UPSTREAM_API_KEY,
      maxOutputTokens: 1_024,
      minRequestIntervalMs: 60_000,
    });
    bridges.push(maxIntervalBridge);
  });
});
