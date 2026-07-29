import { randomBytes, timingSafeEqual } from "node:crypto";
import {
  createServer,
  request as httpRequest,
  type IncomingMessage,
  type Server,
  type ServerResponse,
} from "node:http";
import { request as httpsRequest } from "node:https";
import type { Socket } from "node:net";
import { performance } from "node:perf_hooks";
import { Readable } from "node:stream";
import { pipeline } from "node:stream/promises";

const OPENROUTER_API_BASE_URL = new URL("https://openrouter.ai/api/v1/");
const MAX_BODY_BYTES = 32 * 1024 * 1024;
const MAX_HEADER_BYTES = 16 * 1024;
const MAX_HEADER_COUNT = 32;
const HEADER_TIMEOUT_MS = 10_000;
const REQUEST_TIMEOUT_MS = 30_000;
const UPSTREAM_HEADER_TIMEOUT_MS = 30_000;
const CLOSE_TIMEOUT_MS = 1_000;
const MAX_RETRY_AFTER_SECONDS = 3_600;
const MAX_OUTPUT_TOKENS = 65_536;
const MAX_JSON_DEPTH = 64;
const MAX_JSON_NODES = 250_000;
const MAX_PACED_QUEUE_REQUESTS = 16;
const MAX_PACED_QUEUE_BYTES = 64 * 1024 * 1024;
const MAX_IN_FLIGHT_REQUESTS = 16;
const MAX_IN_FLIGHT_BODY_BYTES = 64 * 1024 * 1024;
const MAX_UPSTREAM_RETRIES = 5;
const MAX_UPSTREAM_RETRY_DELAY_MS = 300_000;

const SAFE_RESPONSES = {
  badGateway: {
    error: {
      code: "upstream_error",
      message: "Upstream request failed.",
      type: "upstream_error",
    },
  },
  invalidRequest: {
    error: {
      code: "invalid_request",
      message: "Invalid request.",
      type: "invalid_request_error",
    },
  },
  notFound: {
    error: {
      code: "not_found",
      message: "Not found.",
      type: "invalid_request_error",
    },
  },
  rateLimited: {
    error: {
      code: "rate_limit_exceeded",
      message: "Bridge request capacity reached. Retry later.",
      type: "rate_limit_error",
    },
  },
  unauthorized: {
    error: {
      code: "invalid_api_key",
      message: "Unauthorized.",
      type: "authentication_error",
    },
  },
} as const;

export interface OpenRouterResponsesBridge {
  readonly baseUrl: string;
  readonly credential: string;
  close(): Promise<void>;
}

export interface OpenRouterResponsesBridgeOptions {
  readonly expectedModel: string;
  readonly getUpstreamApiKey: () => string;
  readonly maxOutputTokens: number;
  readonly minRequestIntervalMs?: number;
  readonly maxRetries?: number;
  readonly retryBaseDelayMs?: number;
  readonly maxRetryDelayMs?: number;
}

/** @internal Test-only dependency injection. Production callers should omit it. */
export interface OpenRouterResponsesBridgeDependencies {
  readonly fetch?: typeof globalThis.fetch;
  readonly upstreamBaseUrl?: URL;
}

class RequestValidationError extends Error {
  constructor(
    readonly status: number,
    readonly response: (typeof SAFE_RESPONSES)[keyof typeof SAFE_RESPONSES],
  ) {
    super("Request validation failed");
    this.name = "RequestValidationError";
  }
}

class BridgeCapacityError extends Error {
  constructor(readonly retryAfterSeconds: number) {
    super("Bridge request capacity reached");
    this.name = "BridgeCapacityError";
  }
}

interface RequestAdmission {
  release(): void;
}

interface RequestAdmissionController {
  tryAcquire(reservedBytes: number): RequestAdmission | undefined;
}

function createRequestAdmissionController(): RequestAdmissionController {
  let activeRequests = 0;
  let reservedBodyBytes = 0;
  return {
    tryAcquire(reservedBytes: number): RequestAdmission | undefined {
      if (
        !Number.isSafeInteger(reservedBytes) ||
        reservedBytes < 0 ||
        reservedBytes > MAX_BODY_BYTES ||
        activeRequests >= MAX_IN_FLIGHT_REQUESTS ||
        reservedBytes > MAX_IN_FLIGHT_BODY_BYTES - reservedBodyBytes
      ) {
        return undefined;
      }
      activeRequests += 1;
      reservedBodyBytes += reservedBytes;
      let released = false;
      return {
        release(): void {
          if (released) return;
          released = true;
          activeRequests -= 1;
          reservedBodyBytes -= reservedBytes;
        },
      };
    },
  };
}

function rawHeaderValues(
  request: IncomingMessage,
  name: string,
): string[] | undefined {
  const values: string[] = [];
  for (let index = 0; index < request.rawHeaders.length; index += 2) {
    if (request.rawHeaders[index]?.toLowerCase() === name) {
      const value = request.rawHeaders[index + 1];
      if (value !== undefined) values.push(value);
    }
  }

  // Node 22 exposes arrays in headersDistinct. Bun's node:http compatibility
  // layer may omit it or expose a non-array value, so rawHeaders remains the
  // compatibility source while Node's distinct view is checked fail-closed.
  const distinctValues: unknown = request.headersDistinct?.[name];
  if (
    Array.isArray(distinctValues) &&
    (values.length !== distinctValues.length ||
      values.some((value, index) => value !== distinctValues[index]))
  ) {
    return undefined;
  }
  return values;
}

function singleHeaderValue(
  request: IncomingMessage,
  name: string,
): string | undefined {
  const values = rawHeaderValues(request, name);
  return values?.length === 1 ? values[0] : undefined;
}

function hasExpectedAuthorization(
  request: IncomingMessage,
  expectedAuthorization: string,
): boolean {
  const value = singleHeaderValue(request, "authorization");
  if (value === undefined) return false;
  const actual = Buffer.from(value, "utf8");
  const expected = Buffer.from(expectedAuthorization, "utf8");
  return (
    actual.byteLength === expected.byteLength &&
    timingSafeEqual(actual, expected)
  );
}

function authorizationForApiKey(apiKey: string): string {
  if (
    apiKey.length === 0 ||
    apiKey.length > 4_096 ||
    apiKey.trim() !== apiKey ||
    !/^[A-Za-z0-9\-._~+/]+=*$/u.test(apiKey)
  ) {
    throw new TypeError("OpenRouter API key is not a valid bearer credential");
  }
  return `Bearer ${apiKey}`;
}

function directFetch(
  input: string | URL | Request,
  init: RequestInit = {},
): Promise<Response> {
  if (input instanceof Request) {
    return Promise.reject(
      new TypeError("The direct bridge transport requires a URL"),
    );
  }
  const url = input instanceof URL ? new URL(input) : new URL(input);
  if (url.protocol !== "https:" && url.protocol !== "http:") {
    return Promise.reject(
      new TypeError("The direct bridge transport requires HTTP or HTTPS"),
    );
  }
  if (init.redirect !== undefined && init.redirect !== "error") {
    return Promise.reject(
      new TypeError("The direct bridge transport does not follow redirects"),
    );
  }
  const body = init.body;
  if (
    body !== undefined &&
    body !== null &&
    typeof body !== "string" &&
    !(body instanceof ArrayBuffer) &&
    !ArrayBuffer.isView(body)
  ) {
    return Promise.reject(
      new TypeError("The direct bridge transport requires a bounded body"),
    );
  }
  const headers = Object.fromEntries(new Headers(init.headers).entries());
  const request = url.protocol === "https:" ? httpsRequest : httpRequest;
  return new Promise<Response>((resolve, reject) => {
    const outgoing = request(
      url,
      {
        agent: false,
        headers,
        maxHeaderSize: MAX_HEADER_BYTES,
        method: init.method ?? "GET",
        signal: init.signal ?? undefined,
      },
      (incoming) => {
        const responseHeaders = new Headers();
        for (let index = 0; index < incoming.rawHeaders.length; index += 2) {
          const name = incoming.rawHeaders[index];
          const value = incoming.rawHeaders[index + 1];
          if (name !== undefined && value !== undefined) {
            responseHeaders.append(name, value);
          }
        }
        const status = incoming.statusCode ?? 502;
        const responseBody =
          status === 204 || status === 205 || status === 304
            ? null
            : (Readable.toWeb(incoming) as ReadableStream<Uint8Array>);
        try {
          resolve(
            new Response(responseBody, {
              headers: responseHeaders,
              status,
              statusText: incoming.statusMessage,
            }),
          );
        } catch (error) {
          incoming.destroy();
          reject(error);
        }
      },
    );
    outgoing.once("error", reject);
    if (typeof body === "string" || ArrayBuffer.isView(body)) {
      outgoing.end(body);
    } else if (body instanceof ArrayBuffer) {
      outgoing.end(new Uint8Array(body));
    } else {
      outgoing.end();
    }
  });
}

function isApplicationJson(value: string | undefined): boolean {
  return (
    value !== undefined &&
    /^application\/json(?:\s*;\s*charset=utf-8)?$/i.test(value)
  );
}

function acceptsIdentityEncoding(request: IncomingMessage): boolean {
  const values = rawHeaderValues(request, "content-encoding");
  return (
    values !== undefined &&
    (values.length === 0 ||
      (values.length === 1 && values[0]?.trim().toLowerCase() === "identity"))
  );
}

function parseContentLength(request: IncomingMessage): number | undefined {
  const values = rawHeaderValues(request, "content-length");
  if (values === undefined) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }
  if (values.length === 0) return undefined;
  if (values.length !== 1 || !/^(?:0|[1-9][0-9]*)$/.test(values[0] ?? "")) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }

  const value = Number(values[0]);
  if (!Number.isSafeInteger(value)) {
    throw new RequestValidationError(413, SAFE_RESPONSES.invalidRequest);
  }
  return value;
}

async function readRequestBody(
  request: IncomingMessage,
  contentLength: number | undefined,
): Promise<Buffer> {
  const chunks: Buffer[] = [];
  let totalBytes = 0;
  for await (const chunk of request) {
    const buffer = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    totalBytes += buffer.byteLength;
    if (totalBytes > MAX_BODY_BYTES) {
      throw new RequestValidationError(413, SAFE_RESPONSES.invalidRequest);
    }
    chunks.push(buffer);
  }
  if (contentLength !== undefined && totalBytes !== contentLength) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }
  return Buffer.concat(chunks, totalBytes);
}

function assertBoundedJson(value: unknown): void {
  const stack: Array<{ depth: number; value: unknown }> = [{ depth: 1, value }];
  let visited = 0;

  while (stack.length > 0) {
    const current = stack.pop();
    if (current === undefined) break;
    visited += 1;
    if (visited > MAX_JSON_NODES) {
      throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
    }
    if (current.value === null || typeof current.value !== "object") {
      continue;
    }
    if (current.depth > MAX_JSON_DEPTH) {
      throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
    }

    const append = (child: unknown): void => {
      if (visited + stack.length >= MAX_JSON_NODES) {
        throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
      }
      stack.push({ depth: current.depth + 1, value: child });
    };
    if (Array.isArray(current.value)) {
      for (const child of current.value) append(child);
      continue;
    }
    for (const key in current.value) {
      if (Object.prototype.hasOwnProperty.call(current.value, key)) {
        append((current.value as Record<string, unknown>)[key]);
      }
    }
  }
}

function parseRequestBody(
  body: Buffer,
  expectedModel: string,
  maxOutputTokens: number,
): string {
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(body);
  } catch {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }

  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }
  assertBoundedJson(parsed);

  const requestBody = parsed as Record<string, unknown>;
  if (
    requestBody["stream"] !== true ||
    requestBody["model"] !== expectedModel
  ) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }

  const requestedMaxOutputTokens = requestBody["max_output_tokens"];
  if (
    requestedMaxOutputTokens !== undefined &&
    (!Number.isSafeInteger(requestedMaxOutputTokens) ||
      (requestedMaxOutputTokens as number) < 1 ||
      (requestedMaxOutputTokens as number) > MAX_OUTPUT_TOKENS)
  ) {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }

  requestBody["max_output_tokens"] =
    requestedMaxOutputTokens === undefined
      ? maxOutputTokens
      : Math.min(requestedMaxOutputTokens as number, maxOutputTokens);

  try {
    return JSON.stringify(requestBody);
  } catch {
    throw new RequestValidationError(400, SAFE_RESPONSES.invalidRequest);
  }
}

interface BoundedRetryAfter {
  readonly delayMs: number;
  readonly headerValue: string;
}

function boundedRetryAfter(
  response: Response,
): BoundedRetryAfter | null | undefined {
  const value = response.headers.get("retry-after");
  if (value === null) return undefined;

  let delayMs: number;
  if (/^[0-9]+$/.test(value)) {
    const delaySeconds = Number(value);
    if (
      !Number.isSafeInteger(delaySeconds) ||
      delaySeconds > MAX_RETRY_AFTER_SECONDS
    ) {
      return null;
    }
    delayMs = delaySeconds * 1_000;
  } else {
    // Only the preferred IMF-fixdate form is accepted. Date.parse() also
    // accepts non-HTTP legacy date strings, so using it without a grammar
    // gate could turn malformed Retry-After values into immediate replays.
    if (
      !/^(?:Mon|Tue|Wed|Thu|Fri|Sat|Sun), [0-9]{2} (?:Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]{4} [0-9]{2}:[0-9]{2}:[0-9]{2} GMT$/.test(
        value,
      )
    ) {
      return null;
    }
    const retryAt = Date.parse(value);
    if (!Number.isFinite(retryAt)) return null;
    delayMs = Math.max(0, retryAt - Date.now());
  }
  if (delayMs > MAX_RETRY_AFTER_SECONDS * 1_000) return null;
  return {
    delayMs,
    headerValue: String(Math.ceil(delayMs / 1_000)),
  };
}

function retryAfterHeader(response: Response): string | undefined {
  return boundedRetryAfter(response)?.headerValue;
}

function upstreamRetryDelayMs(
  response: Response,
  retriesPerformed: number,
  retryBaseDelayMs: number,
  maxRetryDelayMs: number,
): number | undefined {
  if (response.status !== 429) return undefined;
  const retryAfter = boundedRetryAfter(response);
  if (retryAfter === null) return undefined;
  if (retryAfter !== undefined) {
    return retryAfter.delayMs <= maxRetryDelayMs
      ? retryAfter.delayMs
      : undefined;
  }
  return Math.min(retryBaseDelayMs * 2 ** retriesPerformed, maxRetryDelayMs);
}

function waitForRetry(delayMs: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(requestAbortedError());
  if (delayMs === 0) return Promise.resolve();
  return new Promise<void>((resolve, reject) => {
    const onAbort = (): void => {
      clearTimeout(timer);
      reject(requestAbortedError());
    };
    const timer = setTimeout(() => {
      signal.removeEventListener("abort", onAbort);
      resolve();
    }, delayMs);
    timer.unref();
    signal.addEventListener("abort", onAbort, { once: true });
    if (signal.aborted) onAbort();
  });
}

function sendJson(
  response: ServerResponse,
  status: number,
  body: (typeof SAFE_RESPONSES)[keyof typeof SAFE_RESPONSES],
  headers: Record<string, string> = {},
): void {
  if (response.headersSent || response.destroyed || response.writableEnded)
    return;
  const serialized = JSON.stringify(body);
  response.writeHead(status, {
    "cache-control": "no-store",
    connection: "close",
    "content-length": Buffer.byteLength(serialized),
    "content-type": "application/json; charset=utf-8",
    "x-content-type-options": "nosniff",
    ...headers,
  });
  response.end(serialized);
}

function discardResponseBody(response: Response): void {
  void response.body?.cancel().catch(() => undefined);
}

interface PendingUpstreamRequest {
  readonly onAbort: () => void;
  readonly reject: (reason: Error) => void;
  readonly resolve: (response: Response | PromiseLike<Response>) => void;
  readonly retainedBytes: number;
  readonly signal: AbortSignal;
  readonly start: () => Promise<Response>;
}

type StartUpstreamRequest = (
  signal: AbortSignal,
  retainedBytes: number,
  start: () => Promise<Response>,
) => Promise<Response>;

interface UpstreamRequestScheduler {
  readonly start: StartUpstreamRequest;
  close(): void;
}

function requestAbortedError(): Error {
  const error = new Error("Request aborted");
  error.name = "AbortError";
  return error;
}

function createUpstreamRequestScheduler(
  minRequestIntervalMs: number,
): UpstreamRequestScheduler {
  const queue: PendingUpstreamRequest[] = [];
  let closed = false;
  let nextStartAt = 0;
  let queuedBytes = 0;
  let timer: ReturnType<typeof setTimeout> | undefined;

  const removeQueued = (index: number): PendingUpstreamRequest | undefined => {
    const [pending] = queue.splice(index, 1);
    if (pending !== undefined) queuedBytes -= pending.retainedBytes;
    return pending;
  };
  const capacityRetryAfterSeconds = (): number =>
    Math.max(
      1,
      Math.min(
        MAX_RETRY_AFTER_SECONDS,
        Math.ceil(Math.max(0, nextStartAt - performance.now()) / 1_000),
      ),
    );

  const pump = (): void => {
    if (timer !== undefined) {
      clearTimeout(timer);
      timer = undefined;
    }
    if (closed) return;

    while (queue.length > 0) {
      const pending = queue[0];
      if (pending === undefined) return;
      if (pending.signal.aborted) {
        removeQueued(0);
        pending.signal.removeEventListener("abort", pending.onAbort);
        pending.reject(requestAbortedError());
        continue;
      }

      const delay = nextStartAt - performance.now();
      if (delay > 0) {
        timer = setTimeout(pump, Math.ceil(delay));
        timer.unref();
        return;
      }

      removeQueued(0);
      pending.signal.removeEventListener("abort", pending.onAbort);
      if (pending.signal.aborted) {
        pending.reject(requestAbortedError());
        continue;
      }

      try {
        const started = pending.start();
        // Record the slot after invoking the transport. This makes the interval
        // conservative relative to the actual upstream request start time.
        nextStartAt = performance.now() + minRequestIntervalMs;
        pending.resolve(started);
      } catch (error) {
        // A local failure (for example, an invalid API key) did not start an
        // upstream request and therefore must not consume a pacing slot.
        pending.reject(
          error instanceof Error ? error : new Error("Upstream request failed"),
        );
      }
    }
  };

  const startRequest: StartUpstreamRequest = (signal, retainedBytes, start) =>
    new Promise<Response>((resolve, reject) => {
      if (closed || signal.aborted) {
        reject(requestAbortedError());
        return;
      }
      if (
        !Number.isSafeInteger(retainedBytes) ||
        retainedBytes < 0 ||
        retainedBytes > MAX_PACED_QUEUE_BYTES
      ) {
        reject(new Error("Invalid paced request size"));
        return;
      }
      if (
        queue.length >= MAX_PACED_QUEUE_REQUESTS ||
        retainedBytes > MAX_PACED_QUEUE_BYTES - queuedBytes
      ) {
        reject(new BridgeCapacityError(capacityRetryAfterSeconds()));
        return;
      }

      let pending: PendingUpstreamRequest;
      const onAbort = (): void => {
        const index = queue.indexOf(pending);
        if (index === -1) return;
        removeQueued(index);
        signal.removeEventListener("abort", onAbort);
        reject(requestAbortedError());
        // Re-evaluate the timer so an emptied queue leaves no scheduled work.
        pump();
      };
      pending = { onAbort, reject, resolve, retainedBytes, signal, start };
      signal.addEventListener("abort", onAbort, { once: true });
      queue.push(pending);
      queuedBytes += retainedBytes;
      pump();
    });

  return {
    start: startRequest,
    close(): void {
      if (closed) return;
      closed = true;
      if (timer !== undefined) {
        clearTimeout(timer);
        timer = undefined;
      }
      while (queue.length > 0) {
        const pending = removeQueued(0);
        if (pending === undefined) break;
        pending.signal.removeEventListener("abort", pending.onAbort);
        pending.reject(requestAbortedError());
      }
      queuedBytes = 0;
    },
  };
}

interface RequestHandlerContext {
  readonly activeControllers: Set<AbortController>;
  readonly expectedAuthorization: string;
  readonly expectedModel: string;
  readonly expectedPath: string;
  readonly fetch: typeof globalThis.fetch;
  readonly getUpstreamApiKey: () => string;
  readonly maxOutputTokens: number;
  readonly maxRetries: number;
  readonly retryBaseDelayMs: number;
  readonly maxRetryDelayMs: number;
  readonly requestAdmission: RequestAdmissionController;
  readonly startUpstreamRequest: StartUpstreamRequest;
  readonly upstreamUrl: URL;
}

async function handleRequest(
  request: IncomingMessage,
  response: ServerResponse,
  context: RequestHandlerContext,
): Promise<void> {
  if (request.method !== "POST" || request.url !== context.expectedPath) {
    sendJson(response, 404, SAFE_RESPONSES.notFound);
    return;
  }

  if (!hasExpectedAuthorization(request, context.expectedAuthorization)) {
    sendJson(response, 401, SAFE_RESPONSES.unauthorized);
    return;
  }

  const contentType = singleHeaderValue(request, "content-type");
  if (!isApplicationJson(contentType) || !acceptsIdentityEncoding(request)) {
    sendJson(response, 415, SAFE_RESPONSES.invalidRequest);
    return;
  }

  let contentLength: number | undefined;
  try {
    contentLength = parseContentLength(request);
    if (contentLength !== undefined && contentLength > MAX_BODY_BYTES) {
      throw new RequestValidationError(413, SAFE_RESPONSES.invalidRequest);
    }
  } catch (error) {
    if (error instanceof RequestValidationError) {
      sendJson(response, error.status, error.response);
      return;
    }
    sendJson(response, 400, SAFE_RESPONSES.invalidRequest);
    return;
  }
  const admission = context.requestAdmission.tryAcquire(
    contentLength ?? MAX_BODY_BYTES,
  );
  if (admission === undefined) {
    request.resume();
    sendJson(response, 429, SAFE_RESPONSES.rateLimited, {
      "retry-after": "1",
    });
    return;
  }

  try {
    let requestBody: string;
    try {
      requestBody = parseRequestBody(
        await readRequestBody(request, contentLength),
        context.expectedModel,
        context.maxOutputTokens,
      );
    } catch (error) {
      if (error instanceof RequestValidationError) {
        sendJson(response, error.status, error.response);
        return;
      }
      sendJson(response, 400, SAFE_RESPONSES.invalidRequest);
      return;
    }

    const controller = new AbortController();
    context.activeControllers.add(controller);
    let upstreamStream: Readable | undefined;
    const abort = (): void => {
      controller.abort();
      upstreamStream?.destroy();
    };
    const downstreamClosed = (): void => {
      if (!response.writableEnded) abort();
    };
    const cleanup = (): void => {
      context.activeControllers.delete(controller);
      request.off("aborted", abort);
      request.socket.off("close", abort);
      request.socket.off("end", abort);
      request.socket.off("error", abort);
      response.off("close", downstreamClosed);
      response.off("error", abort);
    };
    request.once("aborted", abort);
    request.socket.once("close", abort);
    request.socket.once("end", abort);
    request.socket.once("error", abort);
    response.once("close", downstreamClosed);
    response.once("error", abort);

    let invalidUpstreamCredential = false;
    let upstreamResponse: Response;
    let retriesPerformed = 0;
    while (true) {
      let headerTimeout: ReturnType<typeof setTimeout> | undefined;
      try {
        upstreamResponse = await context.startUpstreamRequest(
          controller.signal,
          Buffer.byteLength(requestBody),
          () => {
            let upstreamAuthorization: string;
            try {
              upstreamAuthorization = authorizationForApiKey(
                context.getUpstreamApiKey(),
              );
            } catch (error) {
              invalidUpstreamCredential = true;
              throw error;
            }
            if (controller.signal.aborted) throw requestAbortedError();
            const upstreamHeaders = new Headers({
              accept: "text/event-stream",
              authorization: upstreamAuthorization,
              "content-type": "application/json",
              "accept-encoding": "identity",
            });
            headerTimeout = setTimeout(abort, UPSTREAM_HEADER_TIMEOUT_MS);
            headerTimeout.unref();
            return context.fetch(context.upstreamUrl, {
              body: requestBody,
              headers: upstreamHeaders,
              method: "POST",
              redirect: "error",
              signal: controller.signal,
            });
          },
        );
      } catch (error) {
        if (headerTimeout !== undefined) clearTimeout(headerTimeout);
        cleanup();
        if (invalidUpstreamCredential) {
          abort();
          sendJson(response, 401, SAFE_RESPONSES.unauthorized);
        } else if (error instanceof BridgeCapacityError) {
          sendJson(response, 429, SAFE_RESPONSES.rateLimited, {
            "retry-after": String(error.retryAfterSeconds),
          });
        } else if (!controller.signal.aborted || !response.destroyed) {
          sendJson(response, 502, SAFE_RESPONSES.badGateway);
        }
        return;
      }
      if (headerTimeout !== undefined) clearTimeout(headerTimeout);

      const retryDelayMs =
        retriesPerformed < context.maxRetries
          ? upstreamRetryDelayMs(
              upstreamResponse,
              retriesPerformed,
              context.retryBaseDelayMs,
              context.maxRetryDelayMs,
            )
          : undefined;
      if (retryDelayMs === undefined) break;
      discardResponseBody(upstreamResponse);
      retriesPerformed += 1;
      try {
        await waitForRetry(retryDelayMs, controller.signal);
      } catch {
        cleanup();
        if (!controller.signal.aborted || !response.destroyed) {
          sendJson(response, 502, SAFE_RESPONSES.badGateway);
        }
        return;
      }
    }

    if (!upstreamResponse.ok) {
      const retryAfter = retryAfterHeader(upstreamResponse);
      discardResponseBody(upstreamResponse);
      cleanup();
      sendJson(
        response,
        upstreamResponse.status,
        SAFE_RESPONSES.badGateway,
        retryAfter === undefined ? {} : { "retry-after": retryAfter },
      );
      return;
    }

    const upstreamContentType = upstreamResponse.headers.get("content-type");
    const upstreamContentEncoding =
      upstreamResponse.headers.get("content-encoding");
    if (
      upstreamResponse.body === null ||
      upstreamContentType === null ||
      !/^text\/event-stream(?:\s*;|$)/i.test(upstreamContentType) ||
      (upstreamContentEncoding !== null &&
        upstreamContentEncoding.trim().toLowerCase() !== "identity")
    ) {
      discardResponseBody(upstreamResponse);
      cleanup();
      sendJson(response, 502, SAFE_RESPONSES.badGateway);
      return;
    }

    if (controller.signal.aborted || response.destroyed) {
      discardResponseBody(upstreamResponse);
      cleanup();
      return;
    }

    response.writeHead(upstreamResponse.status, {
      "cache-control": "no-store",
      connection: "keep-alive",
      "content-type": "text/event-stream; charset=utf-8",
      "x-content-type-options": "nosniff",
    });

    upstreamStream = Readable.fromWeb(upstreamResponse.body);
    try {
      await pipeline(upstreamStream, response, {
        signal: controller.signal,
      });
    } catch {
      abort();
      if (!response.destroyed) response.destroy();
    } finally {
      cleanup();
    }
  } finally {
    admission.release();
  }
}

function createBridgeServer(context: RequestHandlerContext): Server {
  const server = createServer(
    {
      headersTimeout: HEADER_TIMEOUT_MS,
      keepAliveTimeout: 1_000,
      maxHeaderSize: MAX_HEADER_BYTES,
      requestTimeout: REQUEST_TIMEOUT_MS,
    },
    (request, response) => {
      void handleRequest(request, response, context).catch(() => {
        sendJson(response, 500, SAFE_RESPONSES.badGateway);
      });
    },
  );
  server.maxHeadersCount = MAX_HEADER_COUNT;
  server.maxRequestsPerSocket = 100;
  server.on("clientError", (_error, socket) => {
    if (!socket.writable) {
      socket.destroy();
      return;
    }
    const body = JSON.stringify(SAFE_RESPONSES.invalidRequest);
    socket.end(
      `HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Type: application/json; charset=utf-8\r\nContent-Length: ${Buffer.byteLength(body)}\r\n\r\n${body}`,
    );
  });
  return server;
}

function validateFactoryOptions(
  options: OpenRouterResponsesBridgeOptions,
): void {
  if (typeof options.getUpstreamApiKey !== "function") {
    throw new TypeError("getUpstreamApiKey must be a function");
  }
  authorizationForApiKey(options.getUpstreamApiKey());
  if (
    options.expectedModel.length === 0 ||
    options.expectedModel.length > 512 ||
    options.expectedModel.trim() !== options.expectedModel
  ) {
    throw new TypeError("expectedModel must be a non-empty model identifier");
  }
  if (
    !Number.isSafeInteger(options.maxOutputTokens) ||
    options.maxOutputTokens < 1 ||
    options.maxOutputTokens > MAX_OUTPUT_TOKENS
  ) {
    throw new TypeError("maxOutputTokens must be an integer from 1 to 65536");
  }
  if (
    options.minRequestIntervalMs !== undefined &&
    (!Number.isSafeInteger(options.minRequestIntervalMs) ||
      options.minRequestIntervalMs < 0 ||
      options.minRequestIntervalMs > 60_000)
  ) {
    throw new TypeError(
      "minRequestIntervalMs must be an integer from 0 to 60000",
    );
  }
  if (
    options.maxRetries !== undefined &&
    (!Number.isSafeInteger(options.maxRetries) ||
      options.maxRetries < 0 ||
      options.maxRetries > MAX_UPSTREAM_RETRIES)
  ) {
    throw new TypeError("maxRetries must be an integer from 0 to 5");
  }
  for (const [name, value] of [
    ["retryBaseDelayMs", options.retryBaseDelayMs],
    ["maxRetryDelayMs", options.maxRetryDelayMs],
  ] as const) {
    if (
      value !== undefined &&
      (!Number.isSafeInteger(value) ||
        value < 0 ||
        value > MAX_UPSTREAM_RETRY_DELAY_MS)
    ) {
      throw new TypeError(`${name} must be an integer from 0 to 300000`);
    }
  }
  const effectiveRetryBaseDelayMs = options.retryBaseDelayMs ?? 30_000;
  const effectiveMaxRetryDelayMs = options.maxRetryDelayMs ?? 120_000;
  if (effectiveRetryBaseDelayMs > effectiveMaxRetryDelayMs) {
    throw new TypeError("retryBaseDelayMs must not exceed maxRetryDelayMs");
  }
}

function resolveUpstreamUrl(baseUrl: URL): URL {
  if (baseUrl.username !== "" || baseUrl.password !== "") {
    throw new TypeError("upstreamBaseUrl must not contain credentials");
  }
  if (baseUrl.protocol !== "https:" && baseUrl.protocol !== "http:") {
    throw new TypeError("upstreamBaseUrl must use HTTP or HTTPS");
  }

  const normalized = new URL(baseUrl);
  normalized.hash = "";
  normalized.search = "";
  if (!normalized.pathname.endsWith("/")) normalized.pathname += "/";
  return new URL("responses", normalized);
}

export async function createOpenRouterResponsesBridge(
  options: OpenRouterResponsesBridgeOptions,
  dependencies: OpenRouterResponsesBridgeDependencies = {},
): Promise<OpenRouterResponsesBridge> {
  validateFactoryOptions(options);

  const routeToken = randomBytes(32).toString("base64url");
  const credential = randomBytes(32).toString("base64url");
  const expectedAuthorization = `Bearer ${credential}`;
  const expectedPath = `/${routeToken}/api/v1/responses`;
  const activeControllers = new Set<AbortController>();
  const sockets = new Set<Socket>();
  const requestAdmission = createRequestAdmissionController();
  const requestScheduler = createUpstreamRequestScheduler(
    options.minRequestIntervalMs ?? 0,
  );
  const context: RequestHandlerContext = {
    activeControllers,
    expectedAuthorization,
    expectedModel: options.expectedModel,
    expectedPath,
    fetch: dependencies.fetch ?? (directFetch as typeof globalThis.fetch),
    getUpstreamApiKey: options.getUpstreamApiKey,
    maxOutputTokens: options.maxOutputTokens,
    maxRetries: options.maxRetries ?? 0,
    retryBaseDelayMs: options.retryBaseDelayMs ?? 30_000,
    maxRetryDelayMs: options.maxRetryDelayMs ?? 120_000,
    requestAdmission,
    startUpstreamRequest: requestScheduler.start,
    upstreamUrl: resolveUpstreamUrl(
      dependencies.upstreamBaseUrl ?? OPENROUTER_API_BASE_URL,
    ),
  };
  const server = createBridgeServer(context);
  server.on("connection", (socket) => {
    sockets.add(socket);
    socket.once("close", () => sockets.delete(socket));
  });

  await new Promise<void>((resolve, reject) => {
    const onError = (error: Error): void => reject(error);
    server.once("error", onError);
    server.listen({ exclusive: true, host: "127.0.0.1", port: 0 }, () => {
      server.off("error", onError);
      server.on("error", () => undefined);
      resolve();
    });
  });

  const address = server.address();
  if (
    address === null ||
    typeof address === "string" ||
    address.address !== "127.0.0.1" ||
    address.family !== "IPv4" ||
    !Number.isSafeInteger(address.port) ||
    address.port < 1 ||
    address.port > 65_535
  ) {
    requestScheduler.close();
    server.close();
    throw new Error("OpenRouter bridge did not bind to an IPv4 loopback port");
  }

  let closePromise: Promise<void> | undefined;
  return {
    baseUrl: `http://127.0.0.1:${address.port}/${routeToken}/api/v1`,
    credential,
    close(): Promise<void> {
      if (closePromise !== undefined) return closePromise;
      closePromise = new Promise<void>((resolve) => {
        let settled = false;
        const finish = (): void => {
          if (settled) return;
          settled = true;
          clearTimeout(fallback);
          resolve();
        };
        const fallback = setTimeout(finish, CLOSE_TIMEOUT_MS);
        fallback.unref();

        requestScheduler.close();
        for (const controller of activeControllers) controller.abort();
        for (const socket of sockets) socket.destroy();
        server.close(finish);
        server.closeAllConnections();
      });
      return closePromise;
    },
  };
}
