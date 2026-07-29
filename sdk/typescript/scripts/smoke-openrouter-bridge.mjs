import assert from "node:assert/strict";
import { createServer } from "node:http";
import { createConnection } from "node:net";
import { resolve } from "node:path";
import { pathToFileURL } from "node:url";

const [bridgeModulePath] = process.argv.slice(2);
if (bridgeModulePath === undefined || process.argv.length !== 3) {
  throw new Error(
    "Usage: node scripts/smoke-openrouter-bridge.mjs <bridge-module>",
  );
}

const { createOpenRouterResponsesBridge } = await import(
  pathToFileURL(resolve(bridgeModulePath)).href
);
const minRequestIntervalMs = 500;
const upstreamSockets = new Set();
let heartbeat;
let upstreamSignal;
let fetchStarts = 0;
let keyReads = 0;
const upstreamApiKey = "sk-or-v1-node-smoke-upstream";
const upstream = createServer((request, response) => {
  assert.equal(request.headers.authorization, `Bearer ${upstreamApiKey}`);
  response.writeHead(200, { "content-type": "text/event-stream" });
  response.write("data: first\n\n");
  heartbeat = setInterval(() => response.write("data: heartbeat\n\n"), 10);
  response.once("close", () => clearInterval(heartbeat));
});
upstream.on("connection", (socket) => {
  upstreamSockets.add(socket);
  socket.once("close", () => upstreamSockets.delete(socket));
});
await new Promise((resolveListen, reject) => {
  upstream.once("error", reject);
  upstream.listen({ host: "127.0.0.1", port: 0 }, resolveListen);
});
const upstreamAddress = upstream.address();
assert.notEqual(upstreamAddress, null);
assert.equal(typeof upstreamAddress, "object");

const recordingFetch = (...args) => {
  fetchStarts += 1;
  upstreamSignal = args[1]?.signal;
  return globalThis.fetch(...args);
};
if (typeof globalThis.fetch.preconnect === "function") {
  recordingFetch.preconnect = globalThis.fetch.preconnect;
}

let bridge;
let activeSocket;
let queuedSocket;
try {
  bridge = await createOpenRouterResponsesBridge(
    {
      expectedModel: "qwen/qwen3.7-flash",
      getUpstreamApiKey: () => {
        keyReads += 1;
        return upstreamApiKey;
      },
      maxOutputTokens: 16_384,
      minRequestIntervalMs,
    },
    {
      fetch: recordingFetch,
      upstreamBaseUrl: new URL(
        `http://127.0.0.1:${upstreamAddress.port}/api/v1/`,
      ),
    },
  );

  const target = new URL(`${bridge.baseUrl}/responses`);
  const body = JSON.stringify({
    model: "qwen/qwen3.7-flash",
    stream: true,
  });
  const requestText = [
    `POST ${target.pathname} HTTP/1.1`,
    `Host: ${target.host}`,
    `Authorization: Bearer ${bridge.credential}`,
    "Content-Type: application/json",
    `Content-Length: ${Buffer.byteLength(body)}`,
    "Connection: keep-alive",
    "",
    body,
  ].join("\r\n");

  activeSocket = createConnection({
    host: target.hostname,
    port: Number(target.port),
  });
  await new Promise((resolveFirstEvent, reject) => {
    let firstEventReceived = false;
    let response = "";
    activeSocket.setEncoding("utf8");
    activeSocket.once("connect", () => activeSocket.write(requestText));
    activeSocket.on("data", (chunk) => {
      response += chunk;
      if (!firstEventReceived && response.includes("data: first")) {
        firstEventReceived = true;
        resolveFirstEvent();
      }
    });
    activeSocket.once("error", (error) => {
      if (!firstEventReceived) reject(error);
    });
  });
  assert.equal(fetchStarts, 1);
  assert.equal(keyReads, 2);

  queuedSocket = createConnection({
    host: target.hostname,
    port: Number(target.port),
  });
  await new Promise((resolveDisconnect, reject) => {
    let settled = false;
    let disconnectTimer;
    queuedSocket.once("connect", () => {
      queuedSocket.write(requestText);
      disconnectTimer = setTimeout(() => {
        settled = true;
        queuedSocket.resetAndDestroy();
        resolveDisconnect();
      }, 100);
    });
    queuedSocket.once("error", (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(disconnectTimer);
      reject(error);
    });
  });

  await new Promise((resolveWait) =>
    setTimeout(resolveWait, minRequestIntervalMs + 100),
  );
  assert.equal(
    fetchStarts,
    1,
    "A disconnected paced request unexpectedly started an upstream request.",
  );
  assert.equal(
    keyReads,
    2,
    "A disconnected paced request unexpectedly reread the upstream key.",
  );
  assert.equal(upstreamSignal?.aborted, false);

  activeSocket.resetAndDestroy();
  const deadline = Date.now() + 2_000;
  while (upstreamSignal?.aborted !== true && Date.now() < deadline) {
    await new Promise((resolveWait) => setTimeout(resolveWait, 10));
  }
  assert.equal(
    upstreamSignal?.aborted,
    true,
    "Downstream disconnect did not abort the upstream Responses request.",
  );
} finally {
  clearInterval(heartbeat);
  activeSocket?.destroy();
  queuedSocket?.destroy();
  await bridge?.close();
  for (const socket of upstreamSockets) socket.destroy();
  upstream.closeAllConnections();
  await new Promise((resolveClose) => upstream.close(resolveClose));
}

console.log(
  "Validated Node paced-queue and active downstream-disconnect cancellation for the OpenRouter bridge.",
);
