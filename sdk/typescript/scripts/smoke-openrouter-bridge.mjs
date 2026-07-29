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
const upstreamSockets = new Set();
let heartbeat;
let upstreamSignal;
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
  upstreamSignal = args[1]?.signal;
  return globalThis.fetch(...args);
};
if (typeof globalThis.fetch.preconnect === "function") {
  recordingFetch.preconnect = globalThis.fetch.preconnect;
}

let bridge;
try {
  bridge = await createOpenRouterResponsesBridge(
    {
      expectedModel: "qwen/qwen3.7-flash",
      getUpstreamApiKey: () => upstreamApiKey,
      maxOutputTokens: 16_384,
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
  await new Promise((resolveDisconnect, reject) => {
    const socket = createConnection(
      { host: target.hostname, port: Number(target.port) },
      () => {
        socket.write(
          [
            `POST ${target.pathname} HTTP/1.1`,
            `Host: ${target.host}`,
            `Authorization: Bearer ${bridge.credential}`,
            "Content-Type: application/json",
            `Content-Length: ${Buffer.byteLength(body)}`,
            "Connection: keep-alive",
            "",
            body,
          ].join("\r\n"),
        );
      },
    );
    let response = "";
    let disconnected = false;
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      response += chunk;
      if (!disconnected && response.includes("data: first")) {
        disconnected = true;
        socket.resetAndDestroy();
        resolveDisconnect();
      }
    });
    socket.once("error", (error) => {
      if (!disconnected) reject(error);
    });
  });

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
  await bridge?.close();
  for (const socket of upstreamSockets) socket.destroy();
  upstream.closeAllConnections();
  await new Promise((resolveClose) => upstream.close(resolveClose));
}

console.log(
  "Validated Node downstream-disconnect cancellation for the OpenRouter bridge.",
);
