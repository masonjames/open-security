import { describe, expect, test } from "bun:test";
import {
  CODEX_API_KEY_ENV,
  DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS,
  DEFAULT_OPENROUTER_MIN_REQUEST_INTERVAL_MS,
  DEFAULT_OPENROUTER_MAX_RETRIES,
  DEFAULT_OPENROUTER_RETRY_BASE_DELAY_MS,
  DEFAULT_OPENROUTER_MAX_RETRY_DELAY_MS,
  DEFAULT_OPENROUTER_REASONING_EFFORT,
  DEFAULT_SCAN_PROVIDER,
  helperProcessEnvironment,
  modelProviderExecutionEnvironment,
  openRouterBridgeExecutionEnvironment,
  OPEN_SECURITY_MODEL_ENV,
  OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV,
  OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS_ENV,
  OPEN_SECURITY_OPENROUTER_MAX_RETRIES_ENV,
  OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS_ENV,
  OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS_ENV,
  OPEN_SECURITY_PROVIDER_ENV,
  OPEN_SECURITY_REASONING_EFFORT_ENV,
  OPENAI_API_KEY_ENV,
  OPENROUTER_API_KEY_ENV,
  OPENROUTER_BASE_URL,
  providerAuthentication,
  providerCodexOverrides,
  providerEnvironmentCredential,
  ProviderConfigurationError,
  resolveOpenRouterMaxOutputTokens,
  resolveOpenRouterMinRequestIntervalMs,
  resolveOpenRouterRetryPolicy,
  resolveProviderSelection,
  validateProviderAuthMode,
} from "../src/provider.js";

describe("model provider configuration", () => {
  test("defaults to OpenAI without environment defaults", () => {
    expect(resolveProviderSelection({ environment: {} })).toEqual({
      provider: DEFAULT_SCAN_PROVIDER,
    });
  });

  test("defaults OpenRouter reasoning to a deliberate high setting", () => {
    expect(
      resolveProviderSelection({ provider: "openrouter", environment: {} }),
    ).toEqual({
      provider: "openrouter",
      reasoningEffort: DEFAULT_OPENROUTER_REASONING_EFFORT,
    });
  });

  test("reads safe defaults from the environment", () => {
    expect(
      resolveProviderSelection({
        environment: {
          [OPEN_SECURITY_PROVIDER_ENV]: " OpenRouter ",
          [OPEN_SECURITY_MODEL_ENV]: " qwen/qwen3.7-flash ",
          [OPEN_SECURITY_REASONING_EFFORT_ENV]: " high ",
        },
      }),
    ).toEqual({
      provider: "openrouter",
      model: "qwen/qwen3.7-flash",
      reasoningEffort: "high",
    });
  });

  test("explicit SDK or CLI values override environment defaults", () => {
    expect(
      resolveProviderSelection({
        provider: "openai",
        model: "gpt-5.6-sol",
        reasoningEffort: "xhigh",
        environment: {
          [OPEN_SECURITY_PROVIDER_ENV]: "openrouter",
          [OPEN_SECURITY_MODEL_ENV]: "qwen/qwen3.7-flash",
          [OPEN_SECURITY_REASONING_EFFORT_ENV]: "low",
        },
      }),
    ).toEqual({
      provider: "openai",
      model: "gpt-5.6-sol",
      reasoningEffort: "xhigh",
    });
  });

  test("rejects invalid providers and blank explicit defaults", () => {
    expect(() =>
      resolveProviderSelection({ provider: "anthropic", environment: {} }),
    ).toThrow(ProviderConfigurationError);
    expect(() =>
      resolveProviderSelection({ model: "   ", environment: {} }),
    ).toThrow("model must be non-empty");
    expect(() =>
      resolveProviderSelection({ reasoningEffort: "\t", environment: {} }),
    ).toThrow("reasoning effort must be non-empty");
  });

  test("resolves a bounded OpenRouter max-output reservation", () => {
    expect(resolveOpenRouterMaxOutputTokens({})).toBe(
      DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS,
    );
    for (const blank of ["", "  ", "\t"]) {
      expect(
        resolveOpenRouterMaxOutputTokens({
          [OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV]: blank,
        }),
      ).toBe(DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS);
    }
    for (const [raw, expected] of [
      ["1", 1],
      [" 2048 ", 2048],
      ["016384", 16_384],
      ["65536", 65_536],
    ] as const) {
      expect(
        resolveOpenRouterMaxOutputTokens({
          [OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV]: raw,
        }),
      ).toBe(expected);
    }
  });

  test("rejects non-decimal and out-of-range output reservations", () => {
    for (const raw of [
      "0",
      "65537",
      "-1",
      "+1",
      "1.5",
      "1e3",
      "0x10",
      "1_000",
      "Infinity",
      "999999999999999999999999999999999999",
    ]) {
      expect(() =>
        resolveOpenRouterMaxOutputTokens({
          [OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV]: raw,
        }),
      ).toThrow(ProviderConfigurationError);
    }
  });

  test("resolves a bounded OpenRouter request-start interval", () => {
    expect(resolveOpenRouterMinRequestIntervalMs({})).toBe(
      DEFAULT_OPENROUTER_MIN_REQUEST_INTERVAL_MS,
    );
    for (const blank of ["", "  ", "\t"]) {
      expect(
        resolveOpenRouterMinRequestIntervalMs({
          [OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS_ENV]: blank,
        }),
      ).toBe(DEFAULT_OPENROUTER_MIN_REQUEST_INTERVAL_MS);
    }
    for (const [raw, expected] of [
      ["0", 0],
      [" 10000 ", 10_000],
      ["060000", 60_000],
    ] as const) {
      expect(
        resolveOpenRouterMinRequestIntervalMs({
          [OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS_ENV]: raw,
        }),
      ).toBe(expected);
    }
  });

  test("rejects non-decimal and out-of-range request-start intervals", () => {
    for (const raw of [
      "60001",
      "-1",
      "+0",
      "1.5",
      "1e3",
      "0x10",
      "1_000",
      "Infinity",
      "999999999999999999999999999999999999",
    ]) {
      expect(() =>
        resolveOpenRouterMinRequestIntervalMs({
          [OPEN_SECURITY_OPENROUTER_MIN_REQUEST_INTERVAL_MS_ENV]: raw,
        }),
      ).toThrow(ProviderConfigurationError);
    }
  });

  test("resolves a bounded OpenRouter retry policy", () => {
    expect(resolveOpenRouterRetryPolicy({})).toEqual({
      maxRetries: DEFAULT_OPENROUTER_MAX_RETRIES,
      retryBaseDelayMs: DEFAULT_OPENROUTER_RETRY_BASE_DELAY_MS,
      maxRetryDelayMs: DEFAULT_OPENROUTER_MAX_RETRY_DELAY_MS,
    });
    expect(
      resolveOpenRouterRetryPolicy({
        [OPEN_SECURITY_OPENROUTER_MAX_RETRIES_ENV]: " 5 ",
        [OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS_ENV]: "01000",
        [OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS_ENV]: "300000",
      }),
    ).toEqual({
      maxRetries: 5,
      retryBaseDelayMs: 1_000,
      maxRetryDelayMs: 300_000,
    });
  });

  test("rejects malformed OpenRouter retry policies", () => {
    for (const [name, raw] of [
      [OPEN_SECURITY_OPENROUTER_MAX_RETRIES_ENV, "6"],
      [OPEN_SECURITY_OPENROUTER_MAX_RETRIES_ENV, "-1"],
      [OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS_ENV, "999"],
      [OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS_ENV, "300001"],
      [OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS_ENV, "1e3"],
    ] as const) {
      expect(() => resolveOpenRouterRetryPolicy({ [name]: raw })).toThrow(
        ProviderConfigurationError,
      );
    }
    expect(() =>
      resolveOpenRouterRetryPolicy({
        [OPEN_SECURITY_OPENROUTER_RETRY_BASE_DELAY_MS_ENV]: "60000",
        [OPEN_SECURITY_OPENROUTER_MAX_RETRY_DELAY_MS_ENV]: "30000",
      }),
    ).toThrow("must not exceed");
  });

  test("emits a fixed OpenRouter Responses API provider table", () => {
    expect(providerCodexOverrides("openrouter")).toEqual({
      model_provider: "openrouter",
      model_providers: {
        openrouter: {
          name: "OpenRouter",
          base_url: OPENROUTER_BASE_URL,
          env_key: OPENROUTER_API_KEY_ENV,
          wire_api: "responses",
        },
      },
    });
    expect(providerCodexOverrides("openai")).toEqual({});
  });
});

describe("model provider authentication", () => {
  test("keeps the OpenAI auto-auth behavior backward compatible", () => {
    expect(
      providerAuthentication({
        environment: { [OPENAI_API_KEY_ENV]: "synthetic-openai-key" },
        storedCredentialsAvailable: true,
      }),
    ).toEqual({
      provider: "openai",
      requestedMode: "auto",
      mode: "api-key",
      source: "environment",
      environmentVariable: OPENAI_API_KEY_ENV,
      credentialsAvailable: true,
    });

    expect(
      providerAuthentication({
        environment: {},
        storedCredentialsAvailable: true,
      }),
    ).toEqual({
      provider: "openai",
      requestedMode: "auto",
      mode: "chatgpt",
      source: "stored_credentials",
      credentialsAvailable: true,
    });
  });

  test("recognizes the legacy CODEX_API_KEY alias", () => {
    expect(
      providerEnvironmentCredential("openai", {
        [CODEX_API_KEY_ENV]: " synthetic-codex-key ",
      }),
    ).toEqual({
      environmentVariable: CODEX_API_KEY_ENV,
      value: "synthetic-codex-key",
    });
  });

  test("requires the OpenRouter environment credential", () => {
    expect(
      providerAuthentication({
        provider: "openrouter",
        environment: { [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key" },
        storedCredentialsAvailable: true,
      }),
    ).toEqual({
      provider: "openrouter",
      requestedMode: "auto",
      mode: "api-key",
      source: "environment",
      environmentVariable: OPENROUTER_API_KEY_ENV,
      credentialsAvailable: true,
    });

    expect(
      providerAuthentication({
        provider: "openrouter",
        authMode: "api-key",
        environment: {},
        storedCredentialsAvailable: true,
      }),
    ).toEqual({
      provider: "openrouter",
      requestedMode: "api-key",
      mode: "api-key",
      source: "environment",
      environmentVariable: OPENROUTER_API_KEY_ENV,
      credentialsAvailable: false,
    });
  });

  test("rejects ChatGPT auth and invalid auth modes for OpenRouter", () => {
    expect(() => validateProviderAuthMode("openrouter", "chatgpt")).toThrow(
      "OpenRouter does not support ChatGPT authentication",
    );
    expect(() =>
      providerAuthentication({
        provider: "openrouter",
        authMode: "oauth",
        environment: {},
      }),
    ).toThrow("Unsupported authentication mode");
  });
});

describe("model provider environment isolation", () => {
  const environment = {
    KEEP: "yes",
    [OPENAI_API_KEY_ENV]: "synthetic-openai-key",
    [CODEX_API_KEY_ENV]: "synthetic-codex-key",
    [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key",
    openai_api_key: "synthetic-lowercase-openai-key",
    openrouter_api_key: "synthetic-lowercase-openrouter-key",
  };

  test("OpenRouter model processes cannot inherit OpenAI credentials", () => {
    const isolated = modelProviderExecutionEnvironment(
      "openrouter",
      environment,
    );
    expect(isolated).toEqual({
      KEEP: "yes",
      [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key",
    });
    expect(environment[OPENAI_API_KEY_ENV]).toBe("synthetic-openai-key");
  });

  test("OpenAI model processes cannot inherit OpenRouter credentials", () => {
    expect(modelProviderExecutionEnvironment("openai", environment)).toEqual({
      KEEP: "yes",
      [OPENAI_API_KEY_ENV]: "synthetic-openai-key",
      [CODEX_API_KEY_ENV]: "synthetic-codex-key",
    });
  });

  test("canonicalizes a case-variant credential for the model runtime", () => {
    expect(
      modelProviderExecutionEnvironment("openrouter", {
        KEEP: "yes",
        openrouter_api_key: " synthetic-openrouter-key ",
      }),
    ).toEqual({
      KEEP: "yes",
      [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key",
    });
  });

  test("builds an isolated proxy-free environment for the loopback bridge", () => {
    const source = {
      KEEP: "yes",
      FTP_PROXY: "http://allowed.example.test",
      HTTP_PROXY: "http://proxy.example.test",
      http_proxy: "http://proxy-lower.example.test",
      HtTpS_pRoXy: "http://proxy-mixed.example.test",
      ALL_PROXY: "socks5://proxy.example.test",
      all_proxy: "socks5://proxy-lower.example.test",
      NO_PROXY: "example.test, localhost",
      no_proxy: "internal.test,EXAMPLE.TEST,127.0.0.1",
      No_PrOxY: "service.test",
      [OPENAI_API_KEY_ENV]: "synthetic-openai-key",
      [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key",
    };

    expect(
      openRouterBridgeExecutionEnvironment(
        source,
        "synthetic-ephemeral-bridge-key",
      ),
    ).toEqual({
      KEEP: "yes",
      FTP_PROXY: "http://allowed.example.test",
      [OPENROUTER_API_KEY_ENV]: "synthetic-ephemeral-bridge-key",
      NO_PROXY: "example.test,localhost,internal.test,127.0.0.1,service.test",
      no_proxy: "example.test,localhost,internal.test,127.0.0.1,service.test",
    });
    expect(source.HTTP_PROXY).toBe("http://proxy.example.test");
    expect(source[OPENAI_API_KEY_ENV]).toBe("synthetic-openai-key");
  });

  test("adds loopback exclusions when no NO_PROXY value is configured", () => {
    expect(
      openRouterBridgeExecutionEnvironment(
        {
          KEEP: "yes",
          [OPENROUTER_API_KEY_ENV]: "synthetic-openrouter-key",
        },
        "synthetic-ephemeral-bridge-key",
      ),
    ).toEqual({
      KEEP: "yes",
      [OPENROUTER_API_KEY_ENV]: "synthetic-ephemeral-bridge-key",
      NO_PROXY: "127.0.0.1,localhost",
      no_proxy: "127.0.0.1,localhost",
    });
  });

  test("helper processes cannot inherit any model-provider credential", () => {
    expect(helperProcessEnvironment(environment)).toEqual({ KEEP: "yes" });
  });
});
