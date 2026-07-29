import { randomUUID } from "node:crypto";
import { mkdir, open, rename, unlink } from "node:fs/promises";
import { dirname, join } from "node:path";
import { stringify } from "smol-toml";
import { ConfigurationError } from "./errors.js";
import {
  OPENROUTER_API_KEY_ENV,
  OPENROUTER_BASE_URL,
  providerCodexOverrides,
  resolveProviderSelection,
  type ScanProvider,
} from "./provider.js";
import type { ProcessEnvironment } from "./runtime.js";

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | JsonObject;
export interface JsonObject {
  [key: string]: JsonValue;
}

export interface CodexSecurityConfig {
  provider?: ScanProvider;
  pluginPath?: string;
  codexOverrides?: JsonObject;
  pythonPath?: string;
}

export interface ScanModelConfiguration {
  model: string;
  reasoningEffort: string;
}

export const DEFAULT_CODEX_CONFIG: Readonly<JsonObject> = {
  cli_auth_credentials_store: "file",
  model: "gpt-5.6-sol",
  model_reasoning_effort: "xhigh",
  features: {
    plugins: true,
    goals: true,
    multi_agent_v2: {
      enabled: true,
      max_concurrent_threads_per_session: 9,
    },
  },
};

deepFreezeJson(DEFAULT_CODEX_CONFIG);

export function scanModelConfiguration(
  config: Readonly<JsonObject>,
): ScanModelConfiguration {
  const model = config["model"];
  if (typeof model !== "string" || model.trim().length === 0) {
    throw new ConfigurationError(
      "The configured Codex model must be a nonempty string.",
    );
  }
  const reasoningEffort = config["model_reasoning_effort"];
  if (
    typeof reasoningEffort !== "string" ||
    reasoningEffort.trim().length === 0
  ) {
    throw new ConfigurationError(
      "The configured Codex reasoning effort must be a nonempty string.",
    );
  }
  return { model, reasoningEffort };
}

export async function mergedCodexConfig(
  config: CodexSecurityConfig,
  environment: ProcessEnvironment = {},
): Promise<JsonObject> {
  if (config.codexOverrides !== undefined && !isObject(config.codexOverrides)) {
    throw new ConfigurationError("codexOverrides must be an object.");
  }
  validateOverrideKeys(config.codexOverrides ?? {});
  const overrides = cloneJson(config.codexOverrides ?? {});
  validateOverrides(overrides);
  validateNativeMultiAgentV2Overrides(overrides);

  const explicitModel =
    typeof overrides["model"] === "string" ? overrides["model"] : undefined;
  const explicitReasoning =
    typeof overrides["model_reasoning_effort"] === "string"
      ? overrides["model_reasoning_effort"]
      : undefined;
  const selection = resolveProviderSelection({
    provider: config.provider,
    model: explicitModel,
    reasoningEffort: explicitReasoning,
    environment,
  });
  if (selection.provider === "openrouter" && selection.model === undefined) {
    throw new ConfigurationError(
      "OpenRouter scans require an explicit model via --model, codexOverrides.model, or OPEN_SECURITY_MODEL.",
    );
  }
  validateProviderOwnedOverrides(selection.provider, overrides);

  const providerDefaults = structuredClone(
    providerCodexOverrides(selection.provider),
  ) as JsonObject;
  const environmentDefaults: JsonObject = {
    ...(selection.model === undefined ? {} : { model: selection.model }),
    ...(selection.reasoningEffort === undefined
      ? {}
      : { model_reasoning_effort: selection.reasoningEffort }),
  };
  return deepMerge(
    deepMerge(
      deepMerge(cloneJson(DEFAULT_CODEX_CONFIG), providerDefaults),
      environmentDefaults,
    ),
    overrides,
  );
}

/**
 * Builds the internal runtime configuration for the loopback OpenRouter bridge.
 * The persisted canonical provider table remains owned by Open Security and the
 * caller's already-merged configuration is never mutated.
 */
export function openRouterBridgeRuntimeConfig(
  config: Readonly<JsonObject>,
  baseUrl: string,
): JsonObject {
  validateCanonicalOpenRouterConfig(config);
  if (baseUrl.trim().length === 0) {
    throw new ConfigurationError(
      "The OpenRouter bridge base URL must be nonempty.",
    );
  }

  const runtime = structuredClone(config) as JsonObject;
  const modelProviders = runtime["model_providers"] as JsonObject;
  const openrouter = modelProviders["openrouter"] as JsonObject;
  openrouter["base_url"] = baseUrl;

  const features = runtime["features"];
  if (!isObject(features)) {
    throw new ConfigurationError(
      "The merged OpenRouter configuration must contain a features table.",
    );
  }
  runtime["features"] = {
    ...features,
    enable_request_compression: false,
    responses_websockets: false,
    responses_websockets_v2: false,
    remote_compaction_v2: false,
  };
  return runtime;
}

export async function writeCodexConfig(
  path: string,
  config: JsonObject,
): Promise<void> {
  const parent = dirname(path);
  await mkdir(parent, { recursive: true, mode: 0o700 });
  let contents: string;
  try {
    contents = stringify(config);
  } catch (error) {
    throw new ConfigurationError("Invalid Codex configuration.", {
      cause: error,
    });
  }
  const temporary = join(parent, `.${randomUUID()}.config.toml.tmp`);
  let created = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    created = true;
    try {
      await handle.chmod(0o600);
      await handle.writeFile(contents, "utf8");
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, path);
    created = false;
  } finally {
    if (created) {
      await unlink(temporary).catch(() => undefined);
    }
  }
}

function validateCanonicalOpenRouterConfig(config: Readonly<JsonObject>): void {
  const modelProviders = config["model_providers"];
  const openrouter =
    isObject(modelProviders) && isObject(modelProviders["openrouter"])
      ? modelProviders["openrouter"]
      : undefined;
  if (
    config["model_provider"] !== "openrouter" ||
    openrouter === undefined ||
    openrouter["name"] !== "OpenRouter" ||
    openrouter["env_key"] !== OPENROUTER_API_KEY_ENV ||
    openrouter["wire_api"] !== "responses" ||
    openrouter["base_url"] !== OPENROUTER_BASE_URL
  ) {
    throw new ConfigurationError(
      "The OpenRouter bridge requires the canonical Open Security provider configuration.",
    );
  }
}

function validateOverrideKeys(value: JsonValue): void {
  if (Array.isArray(value)) {
    for (const item of value) validateOverrideKeys(item);
    return;
  }
  if (!isObject(value)) return;
  for (const [key, item] of Object.entries(value)) {
    if (["__proto__", "constructor", "prototype"].includes(key)) {
      throw new ConfigurationError(`Invalid Codex override key: ${key}.`);
    }
    validateOverrideKeys(item);
  }
}

function validateProviderOwnedOverrides(
  provider: ScanProvider,
  overrides: JsonObject,
): void {
  if ("model_provider" in overrides || "model_providers" in overrides) {
    throw new ConfigurationError(
      provider === "openrouter"
        ? "Open Security owns OpenRouter model_provider configuration; select the provider with --provider or OPEN_SECURITY_PROVIDER."
        : "Open Security owns model_provider configuration; select the provider with --provider or OPEN_SECURITY_PROVIDER.",
    );
  }

  const profiles = overrides["profiles"];
  if (!isObject(profiles)) return;
  const providerOwnedProfileKeys =
    provider === "openrouter"
      ? ([
          "model",
          "model_reasoning_effort",
          "model_provider",
          "model_providers",
        ] as const)
      : (["model_provider", "model_providers"] as const);
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) continue;
    const owned = providerOwnedProfileKeys.find((key) => key in profile);
    if (owned !== undefined) {
      throw new ConfigurationError(
        provider === "openrouter"
          ? `OpenRouter profile ${name} cannot override ${owned}; set the model and reasoning effort at the scan root.`
          : `Codex profile ${name} cannot override ${owned}; select the model provider at the scan root.`,
      );
    }
  }
}

function validateOverrides(overrides: JsonObject): void {
  if ("plugins" in overrides || "marketplaces" in overrides) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const features = overrides["features"];
  if ("features" in overrides && !isObject(features)) {
    throw new ConfigurationError(
      "Codex override features must be a TOML table.",
    );
  }
  if (isObject(features) && "plugins" in features) {
    throw new ConfigurationError(
      "Codex Security owns plugin loading configuration.",
    );
  }
  const profiles = overrides["profiles"];
  if (profiles === undefined) {
    return;
  }
  if (!isObject(profiles)) {
    throw new ConfigurationError(
      "Codex override profiles must be TOML tables.",
    );
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      throw new ConfigurationError(
        `Codex override profile ${name} must be a TOML table.`,
      );
    }
    const profileFeatures = profile["features"];
    if (profileFeatures !== undefined && !isObject(profileFeatures)) {
      throw new ConfigurationError(
        `Codex override profile ${name} features must be a TOML table.`,
      );
    }
    if (isObject(profileFeatures) && "plugins" in profileFeatures) {
      throw new ConfigurationError(
        `Codex Security owns plugin loading configuration in profile ${name}.`,
      );
    }
  }
}

function validateNativeMultiAgentV2Overrides(overrides: JsonObject): void {
  const agents = overrides["agents"];
  if (isObject(agents) && "max_threads" in agents) {
    throw new ConfigurationError(
      "The selected Codex Security plugin requires native multi-agent v2; " +
        "agents.max_threads is a legacy v1 setting. Use " +
        "features.multi_agent_v2.max_concurrent_threads_per_session instead.",
    );
  }
  if ("features" in overrides) {
    const features = overrides["features"];
    if (!isObject(features)) {
      throw new ConfigurationError(
        "The selected Codex Security plugin requires native multi-agent v2; " +
          "features must remain a table containing features.multi_agent_v2.",
      );
    }
    if ("multi_agent_v2" in features) {
      const multiAgentV2 = features["multi_agent_v2"];
      if (!isObject(multiAgentV2)) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2 must remain a table with enabled = true.",
        );
      }
      if ("enabled" in multiAgentV2 && multiAgentV2["enabled"] !== true) {
        throw new ConfigurationError(
          "The selected Codex Security plugin requires native multi-agent v2; " +
            "features.multi_agent_v2.enabled cannot be disabled.",
        );
      }
    }
  }

  const profiles = overrides["profiles"];
  if (!isObject(profiles)) {
    return;
  }
  for (const [name, profile] of Object.entries(profiles)) {
    if (!isObject(profile)) {
      continue;
    }
    const profileAgents = profile["agents"];
    if (isObject(profileAgents) && "max_threads" in profileAgents) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} agents.max_threads is a legacy v1 setting.`,
      );
    }
    const profileFeatures = profile["features"];
    if (!isObject(profileFeatures) || !("multi_agent_v2" in profileFeatures)) {
      continue;
    }
    const profileV2 = profileFeatures["multi_agent_v2"];
    if (
      !isObject(profileV2) ||
      ("enabled" in profileV2 && profileV2["enabled"] !== true)
    ) {
      throw new ConfigurationError(
        `The selected Codex Security plugin requires native multi-agent v2; profile ${name} features.multi_agent_v2 cannot be disabled.`,
      );
    }
  }
}

function deepMerge(base: JsonObject, overrides: JsonObject): JsonObject {
  for (const [key, value] of Object.entries(overrides)) {
    const existing = Object.hasOwn(base, key) ? base[key] : undefined;
    base[key] =
      isObject(value) && isObject(existing)
        ? deepMerge({ ...existing }, value)
        : cloneJson(value);
  }
  return base;
}

function cloneJson<T extends JsonValue>(value: T): T {
  return structuredClone(value);
}

function deepFreezeJson(value: JsonValue): void {
  if (typeof value !== "object" || value === null || Object.isFrozen(value)) {
    return;
  }
  for (const item of Array.isArray(value) ? value : Object.values(value)) {
    deepFreezeJson(item);
  }
  Object.freeze(value);
}

function isObject(value: unknown): value is Record<string, JsonValue> {
  if (typeof value !== "object" || value === null || Array.isArray(value)) {
    return false;
  }
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}
