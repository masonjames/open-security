import { open, readdir } from "node:fs/promises";
import { join } from "node:path";
import { CodexSecurityError } from "./errors.js";
import { OPEN_SECURITY_MAX_COST_USD_ENV } from "./provider.js";
import type { ProcessEnvironment } from "./runtime.js";

export function scanCostLimitFromEnvironment(
  environment: ProcessEnvironment,
): number | undefined {
  const configured = Object.entries(environment).find(
    ([name, value]) =>
      name.toUpperCase() === OPEN_SECURITY_MAX_COST_USD_ENV && value?.trim(),
  )?.[1];
  if (configured === undefined) return undefined;
  const value = Number(configured);
  if (!Number.isFinite(value) || value <= 0) {
    throw new CodexSecurityError(
      `${OPEN_SECURITY_MAX_COST_USD_ENV} must be a positive USD amount.`,
    );
  }
  return value;
}

export function rejectUnsupportedScanCostLimit(
  environment: ProcessEnvironment,
  operation: string,
): void {
  if (scanCostLimitFromEnvironment(environment) === undefined) return;
  throw new CodexSecurityError(
    `${OPEN_SECURITY_MAX_COST_USD_ENV} cannot currently be enforced for ${operation}; unset it or run an individually budgeted standard scan.`,
  );
}

export interface ScanCost {
  model: string;
  inputTokens: number;
  cachedInputTokens: number;
  cacheWriteInputTokens: number;
  outputTokens: number;
  estimatedUsd: number;
}

export interface ModelPricingNanodollars {
  input: number;
  cachedInput: number;
  cacheWriteInput: number;
  output: number;
}

interface ScanTokenUsage {
  input_tokens: number;
  cached_input_tokens: number;
  cache_write_input_tokens: number;
  output_tokens: number;
  reasoning_output_tokens: number;
  total_tokens: number;
}

interface SessionUsage {
  offset: number;
  pendingLine: Buffer[];
  pendingLineBytes: number;
  unreadable: boolean;
  threadId: string | null;
  parentThreadId: string | null;
  usage: ScanTokenUsage | null;
}

interface ScanCostTrackerOptions {
  codexHome: string;
  model: string;
  pricing?: Readonly<ModelPricingNanodollars>;
  maxCostUsd?: number;
  onCost?: (cost: Readonly<ScanCost>) => void;
  onCostLimitExceeded?: (cost: Readonly<ScanCost>) => void;
  onError?: (error: unknown) => void;
}

interface ScanCostSnapshot {
  usage: unknown;
  cost: ScanCost | null;
}

const MODEL_PRICING_NANODOLLARS: Readonly<
  Record<string, Readonly<ModelPricingNanodollars>>
> = {
  "gpt-5.6": {
    input: 5_000,
    cachedInput: 500,
    cacheWriteInput: 6_250,
    output: 30_000,
  },
  "gpt-5.6-sol": {
    input: 5_000,
    cachedInput: 500,
    cacheWriteInput: 6_250,
    output: 30_000,
  },
  "gpt-5.6-terra": {
    input: 2_500,
    cachedInput: 250,
    cacheWriteInput: 3_125,
    output: 15_000,
  },
  "gpt-5.6-luna": {
    input: 1_000,
    cachedInput: 100,
    cacheWriteInput: 1_250,
    output: 6_000,
  },
};

const COST_POLL_INTERVAL_MS = 100;
const SESSION_READ_SIZE = 64 * 1_024;
const MAX_SESSION_EVENT_BYTES = 1 * 1_024 * 1_024;

export class ScanCostTracker {
  readonly #options: ScanCostTrackerOptions;
  readonly #sessions = new Map<string, SessionUsage>();
  #threadId: string | null = null;
  #timer: NodeJS.Timeout | null = null;
  #pending: Promise<void> = Promise.resolve();
  #sessionUsage: ScanTokenUsage | null = null;
  #completedTurnUsage: ScanTokenUsage | null = null;
  #snapshot: ScanCostSnapshot = { usage: null, cost: null };
  #lastCost: number | null = null;
  #limitExceeded = false;

  public constructor(options: ScanCostTrackerOptions) {
    this.#options = options;
  }

  public start(threadId: string): void {
    if (this.#threadId !== null) return;
    this.#threadId = threadId;
    if (this.#options.maxCostUsd === undefined) return;
    let polling = false;
    let rerun = false;
    const poll = () => {
      if (polling) {
        rerun = true;
        return;
      }
      polling = true;
      void this.refresh()
        .catch((error: unknown) => {
          this.#options.onError?.(error);
        })
        .finally(() => {
          polling = false;
          if (rerun && this.#timer !== null) {
            rerun = false;
            poll();
          }
        });
    };
    this.#timer = setInterval(poll, COST_POLL_INTERVAL_MS);
    this.#timer.unref();
    poll();
  }

  public async refresh(): Promise<ScanCostSnapshot> {
    const update = this.#pending.then(async () => {
      await this.#readSessions();
      this.#updateSnapshot();
    });
    this.#pending = update.catch(() => {});
    await update;
    return this.#snapshot;
  }

  public async observeCompletedTurnUsage(
    cumulativeUsage: unknown,
  ): Promise<ScanCostSnapshot> {
    const normalized = tokenUsage(cumulativeUsage);
    if (normalized === null) {
      const error = new CodexSecurityError(
        "Cannot account for completed-turn usage because it is invalid or exceeds safe-integer arithmetic.",
      );
      this.#options.onError?.(error);
      throw error;
    }
    this.#completedTurnUsage = normalized;
    return await this.refresh();
  }

  public async stop(fallbackUsage?: unknown): Promise<ScanCostSnapshot> {
    if (this.#timer !== null) {
      clearInterval(this.#timer);
      this.#timer = null;
    }
    const hadCompletedTurnUsage = this.#completedTurnUsage !== null;
    const fallback = tokenUsage(fallbackUsage);
    if (fallback !== null) this.#completedTurnUsage = fallback;
    await this.refresh();

    // Retain the historical one-turn result shape when no session log was
    // available. Recovery checkpoints use the normalized cumulative shape.
    if (
      !hadCompletedTurnUsage &&
      fallback !== null &&
      this.#sessionUsage === null
    ) {
      const cost = estimateScanCost(
        this.#options.model,
        fallbackUsage,
        this.#options.pricing,
      );
      this.#snapshot = { usage: fallbackUsage ?? null, cost };
      this.#reportCost(cost, fallbackUsage);
      return this.#snapshot;
    }

    if (
      this.#snapshot.usage === null &&
      fallbackUsage !== undefined &&
      fallback === null
    ) {
      const cost = estimateScanCost(
        this.#options.model,
        fallbackUsage,
        this.#options.pricing,
      );
      this.#snapshot = { usage: fallbackUsage, cost };
      this.#reportCost(cost, fallbackUsage);
    }
    return this.#snapshot;
  }

  async #readSessions(): Promise<void> {
    if (this.#threadId === null) return;
    const unreadable: Array<{ session: SessionUsage; error: unknown }> = [];
    for await (const path of sessionFiles(
      join(this.#options.codexHome, "sessions"),
    )) {
      let session = this.#sessions.get(path);
      if (session === undefined) {
        session = {
          offset: 0,
          pendingLine: [],
          pendingLineBytes: 0,
          unreadable: false,
          threadId: null,
          parentThreadId: null,
          usage: null,
        };
        this.#sessions.set(path, session);
      }
      try {
        await readSessionUsage(path, session);
      } catch (error) {
        if (session.threadId === null) throw error;
        unreadable.push({ session, error });
      }
    }

    const included = new Set([this.#threadId]);
    let changed = true;
    while (changed) {
      changed = false;
      for (const session of this.#sessions.values()) {
        if (
          session.threadId !== null &&
          session.parentThreadId !== null &&
          included.has(session.parentThreadId) &&
          !included.has(session.threadId)
        ) {
          included.add(session.threadId);
          changed = true;
        }
      }
    }
    for (const { session, error } of unreadable) {
      if (included.has(session.threadId!)) throw error;
    }

    let usage: ScanTokenUsage | null = null;
    for (const session of this.#sessions.values()) {
      if (
        session.threadId !== null &&
        included.has(session.threadId) &&
        session.usage !== null
      ) {
        const combined = addTokenUsage(usage, session.usage);
        if (combined === null) {
          throw new CodexSecurityError(
            "Cannot account for session usage because it exceeds safe-integer arithmetic.",
          );
        }
        usage = combined;
      }
    }
    this.#sessionUsage = usage;
  }

  #updateSnapshot(): void {
    let usage = this.#sessionUsage;
    if (this.#completedTurnUsage !== null) {
      if (usage === null) {
        usage = this.#completedTurnUsage;
      } else {
        const trackedRoot = [...this.#sessions.values()].find(
          (session) => session.threadId === this.#threadId,
        )?.usage;
        usage =
          trackedRoot === undefined || trackedRoot === null
            ? addTokenUsage(usage, this.#completedTurnUsage)
            : reconcileAggregateRootUsage(
                usage,
                trackedRoot,
                this.#completedTurnUsage,
              );
        if (usage === null) {
          throw new CodexSecurityError(
            "Cannot reconcile completed-turn and session usage because the aggregate exceeds safe-integer arithmetic.",
          );
        }
      }
    }
    if (usage === null) return;
    const cost = estimateScanCost(
      this.#options.model,
      usage,
      this.#options.pricing,
    );
    this.#snapshot = { usage, cost };
    this.#reportCost(cost, usage);
  }

  #reportCost(cost: ScanCost | null, usage: unknown): void {
    if (cost === null) return;
    if (this.#options.maxCostUsd !== undefined) {
      const exceeded = scanCostExceedsLimit(
        this.#options.model,
        usage,
        this.#options.maxCostUsd,
        this.#options.pricing,
      );
      if (exceeded === null) {
        this.#options.onError?.(
          new CodexSecurityError(
            "Cannot evaluate the cost limit: model pricing, token usage, or the configured limit is invalid.",
          ),
        );
      } else if (exceeded && !this.#limitExceeded) {
        this.#limitExceeded = true;
        this.#options.onCostLimitExceeded?.(cost);
      }
    }
    if (cost.estimatedUsd === this.#lastCost) return;
    this.#lastCost = cost.estimatedUsd;
    this.#options.onCost?.(cost);
  }
}

async function* sessionFiles(directory: string): AsyncGenerator<string> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  for (const entry of entries) {
    const path = join(directory, entry.name);
    if (entry.isDirectory()) {
      yield* sessionFiles(path);
    } else if (entry.isFile() && entry.name.endsWith(".jsonl")) {
      yield path;
    }
  }
}

async function readSessionUsage(
  path: string,
  session: SessionUsage,
): Promise<void> {
  if (session.unreadable) return;
  let file;
  try {
    file = await open(path, "r");
  } catch (error) {
    if (isMissingFile(error)) return;
    throw error;
  }
  try {
    const buffer = Buffer.alloc(SESSION_READ_SIZE);
    while (true) {
      const { bytesRead } = await file.read(
        buffer,
        0,
        buffer.length,
        session.offset,
      );
      if (bytesRead === 0) return;
      session.offset += bytesRead;
      try {
        readSessionChunk(buffer.subarray(0, bytesRead), session);
      } catch (error) {
        session.unreadable = true;
        session.pendingLine = [];
        session.pendingLineBytes = 0;
        throw error;
      }
    }
  } finally {
    await file.close();
  }
}

function readSessionChunk(contents: Buffer, session: SessionUsage): void {
  let lineStart = 0;
  while (lineStart < contents.length) {
    const newline = contents.indexOf(0x0a, lineStart);
    const lineEnd = newline === -1 ? contents.length : newline;
    const fragment = contents.subarray(lineStart, lineEnd);
    const lineBytes = session.pendingLineBytes + fragment.length;
    if (lineBytes > MAX_SESSION_EVENT_BYTES) {
      throw new Error("Codex session event exceeds the 1 MiB safety limit.");
    }

    if (newline === -1) {
      if (fragment.length > 0) {
        session.pendingLine.push(Buffer.from(fragment));
        session.pendingLineBytes = lineBytes;
      }
      return;
    }

    if (session.pendingLineBytes === 0) {
      readSessionEvent(fragment.toString("utf8"), session);
    } else {
      if (fragment.length > 0) session.pendingLine.push(Buffer.from(fragment));
      readSessionEvent(
        Buffer.concat(session.pendingLine, lineBytes).toString("utf8"),
        session,
      );
      session.pendingLine = [];
      session.pendingLineBytes = 0;
    }
    lineStart = newline + 1;
  }
}

function readSessionEvent(line: string, session: SessionUsage): void {
  if (line.length === 0) return;
  let event: unknown;
  try {
    event = JSON.parse(line) as unknown;
  } catch {
    return;
  }
  if (!isRecord(event) || !isRecord(event["payload"])) return;
  const payload = event["payload"];
  if (event["type"] === "session_meta") {
    if (typeof payload["id"] === "string") {
      session.threadId = payload["id"];
    }
    const source = payload["source"];
    const subagent = isRecord(source) ? source["subagent"] : undefined;
    const spawn = isRecord(subagent) ? subagent["thread_spawn"] : undefined;
    const parent =
      payload["parent_thread_id"] ??
      (isRecord(spawn) ? spawn["parent_thread_id"] : undefined);
    if (typeof parent === "string") session.parentThreadId = parent;
    return;
  }
  if (
    event["type"] !== "event_msg" ||
    payload["type"] !== "token_count" ||
    !isRecord(payload["info"])
  ) {
    return;
  }
  const usage = tokenUsage(payload["info"]["total_token_usage"]);
  if (usage !== null) session.usage = usage;
}

function tokenUsage(value: unknown): ScanTokenUsage | null {
  if (!isRecord(value)) return null;
  const input = value["input_tokens"];
  const cached = value["cached_input_tokens"] ?? 0;
  const cacheWrite =
    value["cache_write_input_tokens"] ?? value["cache_write_tokens"] ?? 0;
  const output = value["output_tokens"];
  const reasoning = value["reasoning_output_tokens"] ?? 0;
  if (
    !isTokenCount(input) ||
    !isTokenCount(cached) ||
    !isTokenCount(cacheWrite) ||
    !isTokenCount(output) ||
    !isTokenCount(reasoning) ||
    cached + cacheWrite > input ||
    reasoning > output ||
    !Number.isSafeInteger(input + output)
  ) {
    return null;
  }
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

export function aggregateScanTokenUsage(
  usages: readonly unknown[],
): unknown | null {
  let aggregate: ScanTokenUsage | null = {
    input_tokens: 0,
    cached_input_tokens: 0,
    cache_write_input_tokens: 0,
    output_tokens: 0,
    reasoning_output_tokens: 0,
    total_tokens: 0,
  };
  for (const usage of usages) {
    const normalized = tokenUsage(usage);
    if (normalized === null) return null;
    aggregate = addTokenUsage(aggregate, normalized);
    if (aggregate === null) return null;
  }
  return aggregate;
}

function addTokenUsage(
  previous: ScanTokenUsage | null,
  next: ScanTokenUsage,
): ScanTokenUsage | null {
  if (previous === null) return next;
  return tokenUsage({
    input_tokens: previous.input_tokens + next.input_tokens,
    cached_input_tokens:
      previous.cached_input_tokens + next.cached_input_tokens,
    cache_write_input_tokens:
      previous.cache_write_input_tokens + next.cache_write_input_tokens,
    output_tokens: previous.output_tokens + next.output_tokens,
    reasoning_output_tokens:
      previous.reasoning_output_tokens + next.reasoning_output_tokens,
  });
}

function reconcileAggregateRootUsage(
  aggregate: ScanTokenUsage,
  trackedRoot: ScanTokenUsage,
  finalRoot: ScanTokenUsage,
): ScanTokenUsage | null {
  const withoutTrackedRoot = subtractTokenUsage(aggregate, trackedRoot);
  const reconciledRoot = maximumTokenUsage(trackedRoot, finalRoot);
  if (reconciledRoot === null) return null;
  return withoutTrackedRoot === null
    ? maximumTokenUsage(aggregate, finalRoot)
    : addTokenUsage(withoutTrackedRoot, reconciledRoot);
}

function subtractTokenUsage(
  total: ScanTokenUsage,
  part: ScanTokenUsage,
): ScanTokenUsage | null {
  const input = total.input_tokens - part.input_tokens;
  const cached = total.cached_input_tokens - part.cached_input_tokens;
  const cacheWrite =
    total.cache_write_input_tokens - part.cache_write_input_tokens;
  const output = total.output_tokens - part.output_tokens;
  const reasoning =
    total.reasoning_output_tokens - part.reasoning_output_tokens;
  if (
    [input, cached, cacheWrite, output, reasoning].some((value) => value < 0)
  ) {
    return null;
  }
  return {
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
    total_tokens: input + output,
  };
}

function maximumTokenUsage(
  left: ScanTokenUsage,
  right: ScanTokenUsage,
): ScanTokenUsage | null {
  const cached = Math.max(left.cached_input_tokens, right.cached_input_tokens);
  const cacheWrite = Math.max(
    left.cache_write_input_tokens,
    right.cache_write_input_tokens,
  );
  const input = Math.max(
    left.input_tokens,
    right.input_tokens,
    cached + cacheWrite,
  );
  const reasoning = Math.max(
    left.reasoning_output_tokens,
    right.reasoning_output_tokens,
  );
  const output = Math.max(left.output_tokens, right.output_tokens, reasoning);
  return tokenUsage({
    input_tokens: input,
    cached_input_tokens: cached,
    cache_write_input_tokens: cacheWrite,
    output_tokens: output,
    reasoning_output_tokens: reasoning,
  });
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isMissingFile(error: unknown): boolean {
  return isRecord(error) && error["code"] === "ENOENT";
}

export function estimateScanCost(
  model: string | undefined,
  usage: unknown,
  providedPricing?: Readonly<ModelPricingNanodollars>,
): ScanCost | null {
  const estimate = exactScanCost(model, usage, providedPricing);
  if (estimate === null || model === undefined) return null;
  const {
    normalized: {
      input_tokens: inputTokens,
      cached_input_tokens: cachedInputTokens,
      cache_write_input_tokens: cacheWriteInputTokens,
      output_tokens: outputTokens,
    },
    nanodollars,
  } = estimate;

  return {
    model,
    inputTokens,
    cachedInputTokens,
    cacheWriteInputTokens,
    outputTokens,
    estimatedUsd: Number(nanodollars) / 1_000_000_000,
  };
}

function exactScanCost(
  model: string | undefined,
  usage: unknown,
  providedPricing?: Readonly<ModelPricingNanodollars>,
): { normalized: ScanTokenUsage; nanodollars: bigint } | null {
  if (model === undefined) return null;
  const pricing = providedPricing ?? MODEL_PRICING_NANODOLLARS[model];
  const normalized = tokenUsage(usage);
  if (
    pricing === undefined ||
    !isModelPricing(pricing) ||
    normalized === null
  ) {
    return null;
  }
  const uncachedInputTokens =
    normalized.input_tokens -
    normalized.cached_input_tokens -
    normalized.cache_write_input_tokens;
  const nanodollars =
    BigInt(uncachedInputTokens) * BigInt(pricing.input) +
    BigInt(normalized.cached_input_tokens) * BigInt(pricing.cachedInput) +
    BigInt(normalized.cache_write_input_tokens) *
      BigInt(pricing.cacheWriteInput) +
    BigInt(normalized.output_tokens) * BigInt(pricing.output);
  return { normalized, nanodollars };
}

function scanCostExceedsLimit(
  model: string,
  usage: unknown,
  maxCostUsd: number,
  providedPricing?: Readonly<ModelPricingNanodollars>,
): boolean | null {
  const estimate = exactScanCost(model, usage, providedPricing);
  const limitNanodollars = usdNanodollarFloor(maxCostUsd);
  if (estimate === null || limitNanodollars === null) return null;
  return estimate.nanodollars > limitNanodollars;
}

function usdNanodollarFloor(value: number): bigint | null {
  if (!Number.isFinite(value) || value <= 0) return null;
  const match =
    /^(?<integer>\d+)(?:\.(?<fraction>\d+))?(?:e(?<exponent>[+-]?\d+))?$/iu.exec(
      value.toString(),
    );
  if (match?.groups === undefined) return null;
  const fraction = match.groups["fraction"] ?? "";
  const exponent = Number(match.groups["exponent"] ?? "0");
  if (!Number.isSafeInteger(exponent)) return null;
  const digits = BigInt(`${match.groups["integer"]}${fraction}`);
  const scale = exponent - fraction.length + 9;
  return scale >= 0
    ? digits * 10n ** BigInt(scale)
    : digits / 10n ** BigInt(-scale);
}

function isModelPricing(pricing: Readonly<ModelPricingNanodollars>): boolean {
  return [
    pricing.input,
    pricing.cachedInput,
    pricing.cacheWriteInput,
    pricing.output,
  ].every((value) => Number.isSafeInteger(value) && value >= 0);
}

export function formatUsd(value: number): string {
  return new Intl.NumberFormat("en-US", {
    style: "currency",
    currency: "USD",
    minimumFractionDigits: 2,
    maximumFractionDigits: 9,
  }).format(value);
}

function isTokenCount(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
