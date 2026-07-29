import {
  appendFile,
  mkdir,
  mkdtemp,
  realpath,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterEach, describe, expect, test } from "bun:test";
import {
  aggregateScanTokenUsage,
  estimateScanCost,
  rejectUnsupportedScanCostLimit,
  scanCostLimitFromEnvironment,
  ScanCostTracker,
} from "../src/cost.js";

const temporaryDirectories: string[] = [];

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((directory) => rm(directory, { recursive: true, force: true })),
  );
});

async function codexHome(): Promise<string> {
  const directory = await realpath(
    await mkdtemp(join(tmpdir(), "codex-security-cost-")),
  );
  temporaryDirectories.push(directory);
  return directory;
}

describe("cost limit environment", () => {
  test("parses a positive case-insensitive USD limit", () => {
    expect(
      scanCostLimitFromEnvironment({ open_security_max_cost_usd: " 1.25 " }),
    ).toBe(1.25);
    expect(scanCostLimitFromEnvironment({})).toBeUndefined();
  });

  test("rejects invalid and unsupported limits before model work", () => {
    for (const value of ["0", "-1", "NaN", "Infinity"]) {
      expect(() =>
        scanCostLimitFromEnvironment({ OPEN_SECURITY_MAX_COST_USD: value }),
      ).toThrow("must be a positive USD amount");
    }
    expect(() =>
      rejectUnsupportedScanCostLimit(
        { OPEN_SECURITY_MAX_COST_USD: "1" },
        "semantic matching",
      ),
    ).toThrow("cannot currently be enforced for semantic matching");
  });
});

async function writeSession(
  home: string,
  threadId: string,
  usage: Record<string, number>,
  parentThreadId?: string,
): Promise<string> {
  const directory = join(home, "sessions", "2026", "07", "26");
  await mkdir(directory, { recursive: true });
  const path = join(directory, `rollout-${threadId}.jsonl`);
  await writeFile(
    path,
    [
      JSON.stringify({
        type: "session_meta",
        payload: {
          id: threadId,
          ...(parentThreadId === undefined
            ? {}
            : {
                source: {
                  subagent: {
                    thread_spawn: { parent_thread_id: parentThreadId },
                  },
                },
              }),
        },
      }),
      JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: { total_token_usage: usage },
        },
      }),
      "",
    ].join("\n"),
  );
  return path;
}

describe("scan cost", () => {
  test("aggregates per-turn usage exactly", () => {
    expect(
      aggregateScanTokenUsage([
        {
          input_tokens: 1_000,
          cached_input_tokens: 100,
          cache_write_input_tokens: 200,
          output_tokens: 30,
          reasoning_output_tokens: 10,
        },
        {
          input_tokens: 250,
          cached_input_tokens: 50,
          output_tokens: 20,
          reasoning_output_tokens: 5,
        },
      ]),
    ).toEqual({
      input_tokens: 1_250,
      cached_input_tokens: 150,
      cache_write_input_tokens: 200,
      output_tokens: 50,
      reasoning_output_tokens: 15,
      total_tokens: 1_300,
    });
    expect(aggregateScanTokenUsage([])).toEqual({
      input_tokens: 0,
      cached_input_tokens: 0,
      cache_write_input_tokens: 0,
      output_tokens: 0,
      reasoning_output_tokens: 0,
      total_tokens: 0,
    });
  });

  test("rejects invalid or overflowing per-turn usage aggregates", () => {
    expect(
      aggregateScanTokenUsage([
        { input_tokens: 1, output_tokens: 1 },
        { input_tokens: -1, output_tokens: 1 },
      ]),
    ).toBeNull();
    expect(
      aggregateScanTokenUsage([
        { input_tokens: Number.MAX_SAFE_INTEGER, output_tokens: 0 },
        { input_tokens: 1, output_tokens: 0 },
      ]),
    ).toBeNull();
  });

  test("uses published GPT-5.6 model rates", () => {
    const usage = { input_tokens: 1_000_000, output_tokens: 1_000_000 };

    expect(estimateScanCost("gpt-5.6", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-sol", usage)?.estimatedUsd).toBe(35);
    expect(estimateScanCost("gpt-5.6-terra", usage)?.estimatedUsd).toBe(17.5);
    expect(estimateScanCost("gpt-5.6-luna", usage)?.estimatedUsd).toBe(7);
  });

  test("charges cached input at its discounted rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_250,
        cached_input_tokens: 200,
        output_tokens: 30,
      }),
    ).toEqual({
      model: "gpt-5.6-sol",
      inputTokens: 1_250,
      cachedInputTokens: 200,
      cacheWriteInputTokens: 0,
      outputTokens: 30,
      estimatedUsd: 0.00625,
    });
  });

  test("charges GPT-5.6 cache writes at their published rate", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        cached_input_tokens: 100,
        cache_write_input_tokens: 200,
        output_tokens: 10,
      })?.estimatedUsd,
    ).toBe(0.0051);
  });

  test("does not double-charge reasoning tokens included in output", () => {
    expect(
      estimateScanCost("gpt-5.6-sol", {
        input_tokens: 1_000,
        output_tokens: 10,
        reasoning_output_tokens: 9,
      })?.estimatedUsd,
    ).toBe(0.0053);
  });

  test("uses injected conservative OpenRouter rates without floating point", () => {
    expect(
      estimateScanCost(
        "qwen/qwen3.7-flash",
        {
          input_tokens: 1_000_000,
          cached_input_tokens: 100_000,
          cache_write_input_tokens: 50_000,
          output_tokens: 250_000,
        },
        {
          input: 200,
          cachedInput: 40,
          cacheWriteInput: 250,
          output: 800,
        },
      ),
    ).toEqual({
      model: "qwen/qwen3.7-flash",
      inputTokens: 1_000_000,
      cachedInputTokens: 100_000,
      cacheWriteInputTokens: 50_000,
      outputTokens: 250_000,
      estimatedUsd: 0.3865,
    });
  });

  test("uses exact bigint arithmetic for high catalog rates", () => {
    const rate = Number.MAX_SAFE_INTEGER;
    const cost = estimateScanCost(
      "high-rate/model",
      { input_tokens: 2, output_tokens: 0 },
      { input: rate, cachedInput: 0, cacheWriteInput: 0, output: 0 },
    );

    expect(cost).not.toBeNull();
    expect(cost?.estimatedUsd).toBe(Number(2n * BigInt(rate)) / 1_000_000_000);
  });

  test("does not invent prices for unknown models or incomplete usage", () => {
    for (const [model, usage] of [
      ["unknown-model", { input_tokens: 1, output_tokens: 1 }],
      ["gpt-5.6-sol", null],
      ["gpt-5.6-sol", {}],
      ["gpt-5.6-sol", { input_tokens: -1, output_tokens: 1 }],
      ["gpt-5.6-sol", { input_tokens: 1.5, output_tokens: 1 }],
      [
        "gpt-5.6-sol",
        { input_tokens: 1, cached_input_tokens: 2, output_tokens: 1 },
      ],
      [
        "gpt-5.6-sol",
        {
          input_tokens: Number.MAX_SAFE_INTEGER,
          output_tokens: Number.MAX_SAFE_INTEGER,
        },
      ],
    ] as const) {
      expect(estimateScanCost(model, usage)).toBeNull();
    }
  });
});

describe("live scan cost tracking", () => {
  test("retains cumulative completed-turn usage without session logs", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
    });
    tracker.start("scan-thread");
    const firstTurn = { input_tokens: 1_000, output_tokens: 20 };
    const cumulative = aggregateScanTokenUsage([
      firstTurn,
      { input_tokens: 500, output_tokens: 10 },
    ]);

    expect(await tracker.observeCompletedTurnUsage(firstTurn)).toEqual({
      usage: {
        input_tokens: 1_000,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 20,
        reasoning_output_tokens: 0,
        total_tokens: 1_020,
      },
      cost: {
        model: "gpt-5.6-luna",
        inputTokens: 1_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 20,
        estimatedUsd: 0.00112,
      },
    });
    expect(cumulative).not.toBeNull();
    expect(await tracker.stop(cumulative)).toEqual({
      usage: {
        input_tokens: 1_500,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 30,
        reasoning_output_tokens: 0,
        total_tokens: 1_530,
      },
      cost: {
        model: "gpt-5.6-luna",
        inputTokens: 1_500,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 30,
        estimatedUsd: 0.00168,
      },
    });
  });

  test("reconciles cumulative root turns with delegated workers once", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    await writeSession(
      home,
      "worker-thread",
      { input_tokens: 50, output_tokens: 5 },
      "scan-thread",
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    await tracker.observeCompletedTurnUsage({
      input_tokens: 100,
      output_tokens: 10,
    });
    const cumulative = aggregateScanTokenUsage([
      { input_tokens: 100, output_tokens: 10 },
      { input_tokens: 200, output_tokens: 20 },
    ]);

    expect(await tracker.stop(cumulative)).toEqual({
      usage: {
        input_tokens: 350,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 35,
        reasoning_output_tokens: 0,
        total_tokens: 385,
      },
      cost: {
        model: "gpt-5.6-terra",
        inputTokens: 350,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 35,
        estimatedUsd: 0.0014,
      },
    });
  });

  test("enforces the exact ceiling before a recovery turn starts", async () => {
    const exceeded: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
      maxCostUsd: 0.001,
      onCostLimitExceeded: (cost) => exceeded.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");

    const snapshot = await tracker.observeCompletedTurnUsage({
      input_tokens: 1_000,
      output_tokens: 20,
    });

    expect(snapshot.cost?.estimatedUsd).toBe(0.00112);
    expect(exceeded).toEqual([0.00112]);
    await tracker.stop();
    expect(exceeded).toEqual([0.00112]);
  });

  test("counts the scan and delegated workers without including other scans", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_000,
      cached_input_tokens: 100,
      cache_write_input_tokens: 200,
      output_tokens: 10,
      reasoning_output_tokens: 2,
    });
    await writeSession(
      home,
      "worker-thread",
      {
        input_tokens: 250,
        cached_input_tokens: 50,
        output_tokens: 5,
        reasoning_output_tokens: 1,
      },
      "scan-thread",
    );
    await writeSession(home, "unrelated-thread", {
      input_tokens: 1_000_000,
      output_tokens: 1_000_000,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
    });
    tracker.start("scan-thread");

    expect(await tracker.stop()).toEqual({
      usage: {
        input_tokens: 1_250,
        cached_input_tokens: 150,
        cache_write_input_tokens: 200,
        output_tokens: 15,
        reasoning_output_tokens: 3,
        total_tokens: 1_265,
      },
      cost: {
        model: "gpt-5.6-sol",
        inputTokens: 1_250,
        cachedInputTokens: 150,
        cacheWriteInputTokens: 200,
        outputTokens: 15,
        estimatedUsd: 0.006275,
      },
    });
  });

  test("uses each session's final cumulative usage without double counting", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");
    expect((await tracker.refresh()).cost?.estimatedUsd).toBe(0.0004);

    const latest = JSON.stringify({
      type: "event_msg",
      payload: {
        type: "token_count",
        info: {
          total_token_usage: { input_tokens: 250, output_tokens: 20 },
        },
      },
    });
    await appendFile(path, `${latest}\n${latest}\n`);

    expect((await tracker.stop()).cost).toEqual({
      model: "gpt-5.6-terra",
      inputTokens: 250,
      cachedInputTokens: 0,
      cacheWriteInputTokens: 0,
      outputTokens: 20,
      estimatedUsd: 0.000925,
    });
  });

  test("reconciles a newer completed-turn usage with delegated workers", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 100,
      output_tokens: 10,
    });
    await writeSession(
      home,
      "worker-thread",
      { input_tokens: 50, output_tokens: 5 },
      "scan-thread",
    );
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-terra",
    });
    tracker.start("scan-thread");

    expect(
      await tracker.stop({ input_tokens: 250, output_tokens: 20 }),
    ).toEqual({
      usage: {
        input_tokens: 300,
        cached_input_tokens: 0,
        cache_write_input_tokens: 0,
        output_tokens: 25,
        reasoning_output_tokens: 0,
        total_tokens: 325,
      },
      cost: {
        model: "gpt-5.6-terra",
        inputTokens: 300,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 25,
        estimatedUsd: 0.001125,
      },
    });
  });

  test("reports a changed running cost only once", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 1_250,
      cached_input_tokens: 200,
      output_tokens: 30,
    });
    const updates: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "gpt-5.6-sol",
      maxCostUsd: 0.005,
      onCost: (cost) => updates.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");

    await tracker.stop();

    expect(updates).toEqual([0.00625]);
  });

  test("fails a cost ceiling closed when the exact total exceeds safe-integer arithmetic", async () => {
    const home = await codexHome();
    await writeSession(home, "scan-thread", {
      input_tokens: 2,
      output_tokens: 0,
    });
    const exceeded: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "high-rate/model",
      pricing: {
        input: Number.MAX_SAFE_INTEGER,
        cachedInput: 0,
        cacheWriteInput: 0,
        output: 0,
      },
      maxCostUsd: 1,
      onCostLimitExceeded: (cost) => exceeded.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");

    const snapshot = await tracker.stop();

    expect(snapshot.cost).not.toBeNull();
    expect(exceeded).toEqual([snapshot.cost!.estimatedUsd]);
    expect(snapshot.cost!.estimatedUsd).toBeGreaterThan(1);
  });

  test("checks the exact ceiling before deduplicating rounded display costs", async () => {
    const home = await codexHome();
    const path = await writeSession(home, "scan-thread", {
      input_tokens: 1,
      output_tokens: 5,
    });
    const displayed: number[] = [];
    const exceeded: number[] = [];
    const tracker = new ScanCostTracker({
      codexHome: home,
      model: "rounding-boundary/model",
      pricing: {
        input: Number.MAX_SAFE_INTEGER,
        cachedInput: 0,
        cacheWriteInput: 0,
        output: 1,
      },
      maxCostUsd: 9_007_199.254_740_996,
      onCost: (cost) => displayed.push(cost.estimatedUsd),
      onCostLimitExceeded: (cost) => exceeded.push(cost.estimatedUsd),
    });
    tracker.start("scan-thread");
    await tracker.refresh();
    expect(exceeded).toEqual([]);

    await appendFile(
      path,
      `${JSON.stringify({
        type: "event_msg",
        payload: {
          type: "token_count",
          info: {
            total_token_usage: { input_tokens: 1, output_tokens: 6 },
          },
        },
      })}\n`,
    );
    await tracker.stop();

    expect(displayed).toHaveLength(1);
    expect(exceeded).toEqual([displayed[0]!]);
  });

  test("falls back to the completed turn when session logs are unavailable", async () => {
    const tracker = new ScanCostTracker({
      codexHome: await codexHome(),
      model: "gpt-5.6-luna",
    });
    const usage = { input_tokens: 1_000, output_tokens: 20 };
    tracker.start("scan-thread");

    expect(await tracker.stop(usage)).toEqual({
      usage,
      cost: {
        model: "gpt-5.6-luna",
        inputTokens: 1_000,
        cachedInputTokens: 0,
        cacheWriteInputTokens: 0,
        outputTokens: 20,
        estimatedUsd: 0.00112,
      },
    });
  });
});
