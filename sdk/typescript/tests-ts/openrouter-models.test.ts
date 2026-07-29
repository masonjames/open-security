import { afterEach, describe, expect, test } from "bun:test";
import {
  assertOpenRouterScanCapabilities,
  clearOpenRouterModelCatalogCache,
  fetchOpenRouterModel,
  OPENROUTER_MODELS_URL,
  OpenRouterModelCatalogError,
  OpenRouterModelCompatibilityError,
  usdPerUnitToNanodollars,
  type OpenRouterCatalogFetch,
} from "../src/openrouter-models.js";

const MODEL_ID = "qwen/qwen3.7-flash";
const ENDPOINTS_URL = `${OPENROUTER_MODELS_URL}/qwen/qwen3.7-flash/endpoints`;

function qwenPricing(): Record<string, unknown> {
  return {
    prompt: "0.00000003",
    completion: "0.00000013",
    input_cache_read: "0.000000006",
    input_cache_write: "0.000000038",
    overrides: [
      {
        min_prompt_tokens: 32_000,
        prompt: "0.0000001",
        completion: "0.0000004",
        input_cache_read: "0.00000002",
        input_cache_write: "0.000000125",
      },
      {
        min_prompt_tokens: 256_000,
        prompt: "0.0000002",
        completion: "0.0000008",
        input_cache_read: "0.00000004",
        input_cache_write: "0.00000025",
      },
    ],
  };
}

function qwenModel(
  overrides: Record<string, unknown> = {},
): Record<string, unknown> {
  return {
    id: MODEL_ID,
    canonical_slug: "qwen/qwen3.7-flash-20260727",
    name: "Qwen: Qwen3.7 Flash",
    context_length: 1_000_000,
    supported_parameters: [
      "include_reasoning",
      "reasoning",
      "response_format",
      "tool_choice",
      "tools",
    ],
    pricing: qwenPricing(),
    ...overrides,
  };
}

function providerEndpoint(
  modelId = MODEL_ID,
  pricing: Record<string, unknown> = { ...qwenPricing(), discount: 0 },
): Record<string, unknown> {
  return {
    name: `Provider | ${modelId}`,
    model_id: modelId,
    pricing,
    provider_name: "Provider",
  };
}

function providerEndpointsBody(
  modelId = MODEL_ID,
  endpoints: Record<string, unknown>[] = [providerEndpoint(modelId)],
): Record<string, unknown> {
  return { data: { id: modelId, endpoints } };
}

function catalogResponse(...models: Record<string, unknown>[]): Response {
  return Response.json({ data: models });
}

function fixtureFetch(
  models: Record<string, unknown>[] = [qwenModel()],
  endpointBody: unknown = providerEndpointsBody(),
  requests: Array<{ input: string; init: RequestInit | undefined }> = [],
): OpenRouterCatalogFetch {
  return async (input, init) => {
    requests.push({ input, init });
    return input === OPENROUTER_MODELS_URL
      ? catalogResponse(...models)
      : Response.json(endpointBody);
  };
}

afterEach(() => {
  clearOpenRouterModelCatalogCache();
});

describe("OpenRouter price conversion", () => {
  test("converts decimal USD strings to nanodollars without floating point", () => {
    expect(usdPerUnitToNanodollars("0")).toBe(0);
    expect(usdPerUnitToNanodollars("0.00000003")).toBe(30);
    expect(usdPerUnitToNanodollars("0.000000001")).toBe(1);
    expect(usdPerUnitToNanodollars("1.234567891")).toBe(1_234_567_891);
  });

  test("rounds sub-nanodollar prices up conservatively", () => {
    expect(usdPerUnitToNanodollars("0.0000000001")).toBe(1);
    expect(usdPerUnitToNanodollars("1.2345678912")).toBe(1_234_567_892);
  });

  test("rejects negative, exponential, numeric-looking, and unsafe prices", () => {
    for (const value of ["-1", "1e-9", ".1", "01", "10000000"]) {
      expect(() => usdPerUnitToNanodollars(value)).toThrow(
        OpenRouterModelCatalogError,
      );
    }
  });
});

describe("OpenRouter public model catalog", () => {
  test("fetches both fixed unauthenticated endpoints and selects an exact model id", async () => {
    const requests: Array<{
      input: string;
      init: RequestInit | undefined;
    }> = [];
    const fetchMock = fixtureFetch(
      [qwenModel(), qwenModel({ id: `${MODEL_ID}:free` })],
      providerEndpointsBody(),
      requests,
    );

    const model = await fetchOpenRouterModel(MODEL_ID, {
      fetch: fetchMock,
      now: () => 123_456,
    });

    expect(requests.map(({ input }) => input)).toEqual([
      OPENROUTER_MODELS_URL,
      ENDPOINTS_URL,
    ]);
    for (const { init } of requests) {
      expect(init?.method).toBe("GET");
      expect(init?.headers).toBeUndefined();
    }
    expect(model).toEqual({
      id: MODEL_ID,
      canonicalSlug: "qwen/qwen3.7-flash-20260727",
      name: "Qwen: Qwen3.7 Flash",
      contextLength: 1_000_000,
      supportedParameters: [
        "include_reasoning",
        "reasoning",
        "response_format",
        "tool_choice",
        "tools",
      ],
      tokenPricingNanodollars: {
        input: 200,
        cachedInput: 40,
        cacheWriteInput: 250,
        output: 800,
      },
      requestPricingNanodollars: 0,
      unsupportedPricingNanodollars: 0,
      pricingOverridesConsidered: 4,
      providerEndpointsConsidered: 1,
      fetchedAt: 123_456,
    });
    expect(() =>
      assertOpenRouterScanCapabilities(model, { reasoning: true }),
    ).not.toThrow();
  });

  test("URL-encodes real variant suffixes as one exact slug segment", async () => {
    const variantId = "vendor/model:free";
    const requests: Array<{
      input: string;
      init: RequestInit | undefined;
    }> = [];
    const fetchMock = fixtureFetch(
      [qwenModel({ id: variantId })],
      providerEndpointsBody(variantId, [providerEndpoint(variantId)]),
      requests,
    );

    await fetchOpenRouterModel(variantId, { fetch: fetchMock });

    expect(requests[1]?.input).toBe(
      `${OPENROUTER_MODELS_URL}/vendor/model%3Afree/endpoints`,
    );
  });

  test("rejects model ids that cannot be encoded as exactly two safe path segments", async () => {
    let requests = 0;
    const fetchMock: OpenRouterCatalogFetch = async () => {
      requests += 1;
      return catalogResponse(qwenModel());
    };

    for (const modelId of [
      "author",
      "author/",
      "/slug",
      "author/slug/extra",
      "../slug",
      "author/..",
    ]) {
      await expect(
        fetchOpenRouterModel(modelId, { fetch: fetchMock }),
      ).rejects.toMatchObject({ code: "invalid-model-id" });
    }
    expect(requests).toBe(0);
  });

  test("fails instead of accepting a partial or canonical-slug match", async () => {
    const fetchMock = fixtureFetch([qwenModel({ id: `${MODEL_ID}-20260727` })]);

    await expect(
      fetchOpenRouterModel(MODEL_ID, { fetch: fetchMock }),
    ).rejects.toMatchObject({ code: "model-not-found" });
  });

  test("validates the selected base model schema and pricing strings", async () => {
    const fetchMock = fixtureFetch([
      qwenModel({ pricing: { prompt: 0.1, completion: "0.2" } }),
    ]);

    await expect(
      fetchOpenRouterModel(MODEL_ID, { fetch: fetchMock }),
    ).rejects.toMatchObject({ code: "invalid-response" });
  });

  test("bounds catalog bodies and cancels rejected HTTP responses", async () => {
    let oversizedCanceled = false;
    const oversizedBody = new ReadableStream<Uint8Array>({
      cancel() {
        oversizedCanceled = true;
      },
    });
    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: async () =>
          new Response(oversizedBody, {
            headers: { "content-length": String(32 * 1024 * 1024 + 1) },
          }),
      }),
    ).rejects.toMatchObject({ code: "invalid-response" });
    expect(oversizedCanceled).toBe(true);

    clearOpenRouterModelCatalogCache();
    let rejectedCanceled = false;
    const rejectedBody = new ReadableStream<Uint8Array>({
      cancel() {
        rejectedCanceled = true;
      },
    });
    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: async () => new Response(rejectedBody, { status: 503 }),
      }),
    ).rejects.toMatchObject({ code: "http-error" });
    expect(rejectedCanceled).toBe(true);
  });

  test("maximizes every tracked price across every provider endpoint and override", async () => {
    const expensivePricing = {
      prompt: "0.0000004",
      completion: "0.0000009",
      request: "0.000002",
      input_cache_read: "0.00000005",
      input_cache_write: "0.0000003",
      overrides: [
        {
          min_prompt_tokens: 100_000,
          prompt: "0.0000005",
          completion: "0.0000012",
          request: "0.000003",
          input_cache_read: "0.00000006",
          input_cache_write: "0.00000035",
        },
      ],
    };
    const secondPricing = {
      prompt: "0.00000045",
      completion: "0.000001",
      request: "0.0000025",
      input_cache_read: "0.000000055",
      input_cache_write: "0.00000034",
    };
    const fetchMock = fixtureFetch(
      [qwenModel()],
      providerEndpointsBody(MODEL_ID, [
        providerEndpoint(MODEL_ID, expensivePricing),
        providerEndpoint(MODEL_ID, secondPricing),
      ]),
    );

    const model = await fetchOpenRouterModel(MODEL_ID, { fetch: fetchMock });

    expect(model.tokenPricingNanodollars).toEqual({
      input: 500,
      cachedInput: 60,
      cacheWriteInput: 350,
      output: 1_200,
    });
    expect(model.requestPricingNanodollars).toBe(3_000);
    expect(model.unsupportedPricingNanodollars).toBe(0);
    expect(model.pricingOverridesConsidered).toBe(3);
    expect(model.providerEndpointsConsidered).toBe(2);
  });

  test("captures the most expensive additional-unit price across catalog data", async () => {
    const basePricing = {
      ...qwenPricing(),
      image: "0.000004",
      web_search: "0",
    };
    const endpointPricing = {
      ...qwenPricing(),
      audio: "0.000007",
      overrides: [
        {
          min_prompt_tokens: 32_000,
          internal_reasoning: "0.000009",
        },
      ],
    };
    const model = await fetchOpenRouterModel(MODEL_ID, {
      fetch: fixtureFetch(
        [qwenModel({ pricing: basePricing })],
        providerEndpointsBody(MODEL_ID, [
          providerEndpoint(MODEL_ID, endpointPricing),
        ]),
      ),
    });

    expect(model.unsupportedPricingNanodollars).toBe(9_000);
  });

  test("strictly validates the endpoint response and each endpoint model id", async () => {
    const invalidBodies = [
      providerEndpointsBody("other/model"),
      providerEndpointsBody(MODEL_ID, [providerEndpoint("other/model")]),
      { data: { id: MODEL_ID, endpoints: [{}] } },
    ];

    for (const endpointBody of invalidBodies) {
      clearOpenRouterModelCatalogCache();
      await expect(
        fetchOpenRouterModel(MODEL_ID, {
          fetch: fixtureFetch([qwenModel()], endpointBody),
        }),
      ).rejects.toMatchObject({ code: "invalid-response" });
    }
  });

  test("fails closed when no routable provider endpoints are advertised", async () => {
    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: fixtureFetch([qwenModel()], providerEndpointsBody(MODEL_ID, [])),
      }),
    ).rejects.toMatchObject({ code: "invalid-response" });
  });

  test("validates provider request pricing as a decimal string", async () => {
    const endpointBody = providerEndpointsBody(MODEL_ID, [
      providerEndpoint(MODEL_ID, {
        prompt: "0.00000003",
        completion: "0.00000013",
        request: 0,
      }),
    ]);

    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: fixtureFetch([qwenModel()], endpointBody),
      }),
    ).rejects.toMatchObject({ code: "invalid-response" });
  });

  test("accepts only a zero provider discount until discount accounting is supported", async () => {
    for (const discount of [0, "0"] as const) {
      clearOpenRouterModelCatalogCache();
      await expect(
        fetchOpenRouterModel(MODEL_ID, {
          fetch: fixtureFetch(
            [qwenModel()],
            providerEndpointsBody(MODEL_ID, [
              providerEndpoint(MODEL_ID, { ...qwenPricing(), discount }),
            ]),
          ),
        }),
      ).resolves.toMatchObject({
        unsupportedPricingNanodollars: 0,
        providerEndpointsConsidered: 1,
      });
    }

    for (const discount of [0.01, "0.01", null]) {
      clearOpenRouterModelCatalogCache();
      await expect(
        fetchOpenRouterModel(MODEL_ID, {
          fetch: fixtureFetch(
            [qwenModel()],
            providerEndpointsBody(MODEL_ID, [
              providerEndpoint(MODEL_ID, { ...qwenPricing(), discount }),
            ]),
          ),
        }),
      ).rejects.toMatchObject({ code: "invalid-response" });
    }
  });

  test("requires tools and response format, plus reasoning when requested", () => {
    const model = {
      id: MODEL_ID,
      supportedParameters: ["tools"],
    };

    expect(() =>
      assertOpenRouterScanCapabilities(model, { reasoning: true }),
    ).toThrow(OpenRouterModelCompatibilityError);
    try {
      assertOpenRouterScanCapabilities(model, { reasoning: true });
    } catch (error) {
      expect(error).toMatchObject({
        modelId: MODEL_ID,
        missingParameters: ["response_format", "reasoning"],
      });
    }
  });

  test("uses both module caches until their shared TTL expires", async () => {
    let requests = 0;
    let time = 1_000;
    const baseFetch = fixtureFetch();
    const fetchMock: OpenRouterCatalogFetch = async (input, init) => {
      requests += 1;
      return baseFetch(input, init);
    };
    const options = {
      fetch: fetchMock,
      now: () => time,
      cacheTtlMs: 1_000,
    };

    expect((await fetchOpenRouterModel(MODEL_ID, options)).fetchedAt).toBe(
      1_000,
    );
    time = 1_999;
    expect((await fetchOpenRouterModel(MODEL_ID, options)).fetchedAt).toBe(
      1_000,
    );
    time = 2_000;
    expect((await fetchOpenRouterModel(MODEL_ID, options)).fetchedAt).toBe(
      2_000,
    );
    expect(requests).toBe(4);
  });

  test("rejects an already-aborted signal before cached catalog or endpoint results", async () => {
    const otherModelId = "other/model";
    let requests = 0;
    let time = 1_000;
    const fetchMock: OpenRouterCatalogFetch = async (input) => {
      requests += 1;
      if (input === OPENROUTER_MODELS_URL) {
        return catalogResponse(
          qwenModel(),
          qwenModel({
            id: otherModelId,
            canonical_slug: "other/model-20260727",
          }),
        );
      }
      const requestedModel = input === ENDPOINTS_URL ? MODEL_ID : otherModelId;
      return Response.json(providerEndpointsBody(requestedModel));
    };
    const options = {
      fetch: fetchMock,
      now: () => time,
      cacheTtlMs: 1_000,
    };

    await fetchOpenRouterModel(otherModelId, options);
    time = 1_500;
    await fetchOpenRouterModel(MODEL_ID, options);
    expect(requests).toBe(3);

    const cachedAbort = new AbortController();
    cachedAbort.abort();
    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        ...options,
        signal: cachedAbort.signal,
      }),
    ).rejects.toMatchObject({ code: "request-aborted" });
    expect(requests).toBe(3);

    time = 2_000;
    const endpointAbort = new AbortController();
    const abortingFetch: OpenRouterCatalogFetch = async (input, init) => {
      const response = await fetchMock(input, init);
      if (input === OPENROUTER_MODELS_URL) endpointAbort.abort();
      return response;
    };
    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        ...options,
        fetch: abortingFetch,
        signal: endpointAbort.signal,
      }),
    ).rejects.toMatchObject({ code: "request-aborted" });
    expect(requests).toBe(4);
  });

  test("aborts a model catalog request after the configured timeout", async () => {
    const fetchMock: OpenRouterCatalogFetch = (_input, init) =>
      new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true },
        );
      });

    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: fetchMock,
        timeoutMs: 5,
        cacheTtlMs: 0,
      }),
    ).rejects.toMatchObject({ code: "request-timeout" });
  });

  test("applies the same timeout semantics to the provider endpoint request", async () => {
    let requests = 0;
    const fetchMock: OpenRouterCatalogFetch = (input, init) => {
      requests += 1;
      if (input === OPENROUTER_MODELS_URL) {
        return Promise.resolve(catalogResponse(qwenModel()));
      }
      return new Promise<Response>((_resolve, reject) => {
        init?.signal?.addEventListener(
          "abort",
          () => reject(new DOMException("aborted", "AbortError")),
          { once: true },
        );
      });
    };

    await expect(
      fetchOpenRouterModel(MODEL_ID, {
        fetch: fetchMock,
        timeoutMs: 5,
        cacheTtlMs: 0,
      }),
    ).rejects.toMatchObject({ code: "request-timeout" });
    expect(requests).toBe(2);
  });
});
