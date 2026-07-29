import type { ProcessEnvironment } from "./runtime.js";

export type ScanProvider = "openai" | "openrouter";
export type ProviderAuthMode = "auto" | "chatgpt" | "api-key";
export type ResolvedProviderAuthMode = Exclude<ProviderAuthMode, "auto">;
export type ModelProviderSecretEnvironmentVariable =
  | typeof OPENAI_API_KEY_ENV
  | typeof CODEX_API_KEY_ENV
  | typeof OPENROUTER_API_KEY_ENV;

export const DEFAULT_SCAN_PROVIDER: ScanProvider = "openai";
export const DEFAULT_OPENROUTER_REASONING_EFFORT = "high" as const;
export const DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS = 16_384;
export const OPEN_SECURITY_PROVIDER_ENV = "OPEN_SECURITY_PROVIDER" as const;
export const OPEN_SECURITY_MODEL_ENV = "OPEN_SECURITY_MODEL" as const;
export const OPEN_SECURITY_REASONING_EFFORT_ENV =
  "OPEN_SECURITY_REASONING_EFFORT" as const;
export const OPEN_SECURITY_MAX_COST_USD_ENV =
  "OPEN_SECURITY_MAX_COST_USD" as const;
export const OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV =
  "OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS" as const;
export const OPENAI_API_KEY_ENV = "OPENAI_API_KEY" as const;
export const CODEX_API_KEY_ENV = "CODEX_API_KEY" as const;
export const OPENROUTER_API_KEY_ENV = "OPENROUTER_API_KEY" as const;
export const OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1" as const;

export const MODEL_PROVIDER_SECRET_ENV_KEYS = Object.freeze([
  OPENAI_API_KEY_ENV,
  CODEX_API_KEY_ENV,
  OPENROUTER_API_KEY_ENV,
] as const);

const OPENAI_API_KEY_ENVIRONMENTS = Object.freeze([
  OPENAI_API_KEY_ENV,
  CODEX_API_KEY_ENV,
] as const);
const OPENROUTER_API_KEY_ENVIRONMENTS = Object.freeze([
  OPENROUTER_API_KEY_ENV,
] as const);
const OPENROUTER_BRIDGE_PROXY_ENVIRONMENTS = Object.freeze([
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
] as const);
const MAX_OPENROUTER_OUTPUT_TOKENS = 65_536;

export class ProviderConfigurationError extends Error {
  public constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = new.target.name;
  }
}

export interface ProviderSelectionOptions {
  provider?: ScanProvider | string;
  model?: string;
  reasoningEffort?: string;
  environment?: ProcessEnvironment;
}

export interface ProviderSelection {
  provider: ScanProvider;
  model?: string;
  reasoningEffort?: string;
}

export interface OpenRouterCodexProviderDefinition {
  name: "OpenRouter";
  base_url: typeof OPENROUTER_BASE_URL;
  env_key: typeof OPENROUTER_API_KEY_ENV;
  wire_api: "responses";
}

export interface ProviderCodexOverrides {
  model_provider?: "openrouter";
  model_providers?: {
    openrouter: OpenRouterCodexProviderDefinition;
  };
}

export interface ProviderEnvironmentCredential {
  environmentVariable: ModelProviderSecretEnvironmentVariable;
  value: string;
}

export interface ProviderAuthenticationOptions {
  provider?: ScanProvider | string;
  authMode?: ProviderAuthMode | string;
  environment?: ProcessEnvironment;
  storedCredentialsAvailable?: boolean;
}

export type ProviderAuthentication =
  | {
      provider: ScanProvider;
      requestedMode: ProviderAuthMode;
      mode: "api-key";
      source: "environment";
      environmentVariable: ModelProviderSecretEnvironmentVariable;
      credentialsAvailable: boolean;
    }
  | {
      provider: "openai";
      requestedMode: ProviderAuthMode;
      mode: "chatgpt";
      source: "stored_credentials";
      credentialsAvailable: boolean;
    };

/**
 * Resolves provider defaults with explicit CLI/SDK values taking precedence over
 * environment defaults. Blank environment values are treated as unset.
 */
export function resolveProviderSelection(
  options: ProviderSelectionOptions = {},
): ProviderSelection {
  const environment = options.environment ?? process.env;
  const provider = normalizeProvider(
    options.provider ??
      optionalEnvironmentValue(environment, OPEN_SECURITY_PROVIDER_ENV),
  );
  const model = resolveOptionalOverride(
    options.model,
    environment,
    OPEN_SECURITY_MODEL_ENV,
    "model",
  );
  const configuredReasoningEffort = resolveOptionalOverride(
    options.reasoningEffort,
    environment,
    OPEN_SECURITY_REASONING_EFFORT_ENV,
    "reasoning effort",
  );
  const reasoningEffort =
    configuredReasoningEffort ??
    (provider === "openrouter"
      ? DEFAULT_OPENROUTER_REASONING_EFFORT
      : undefined);

  return {
    provider,
    ...(model === undefined ? {} : { model }),
    ...(reasoningEffort === undefined ? {} : { reasoningEffort }),
  };
}

/** Resolves the bounded OpenRouter response reservation used by the bridge. */
export function resolveOpenRouterMaxOutputTokens(
  environment: ProcessEnvironment = process.env,
): number {
  const raw =
    environment[OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV]?.trim();
  if (!raw) return DEFAULT_OPENROUTER_MAX_OUTPUT_TOKENS;
  if (!/^[0-9]+$/u.test(raw)) {
    throw invalidOpenRouterMaxOutputTokens();
  }
  const value = Number(raw);
  if (
    !Number.isSafeInteger(value) ||
    value < 1 ||
    value > MAX_OPENROUTER_OUTPUT_TOKENS
  ) {
    throw invalidOpenRouterMaxOutputTokens();
  }
  return value;
}

/** Returns the fixed Codex Responses provider table required by OpenRouter. */
export function providerCodexOverrides(
  provider: ScanProvider | string,
): ProviderCodexOverrides {
  if (normalizeProvider(provider) === "openai") return {};
  return {
    model_provider: "openrouter",
    model_providers: {
      openrouter: {
        name: "OpenRouter",
        base_url: OPENROUTER_BASE_URL,
        env_key: OPENROUTER_API_KEY_ENV,
        wire_api: "responses",
      },
    },
  };
}

/** Rejects authentication modes that cannot work with the selected provider. */
export function validateProviderAuthMode(
  provider: ScanProvider | string,
  authMode: ProviderAuthMode | string,
): asserts authMode is ProviderAuthMode {
  const normalizedProvider = normalizeProvider(provider);
  const normalizedAuthMode = normalizeAuthMode(authMode);
  if (normalizedProvider === "openrouter" && normalizedAuthMode === "chatgpt") {
    throw new ProviderConfigurationError(
      "OpenRouter does not support ChatGPT authentication; set OPENROUTER_API_KEY and use auto or api-key authentication.",
    );
  }
}

/** Locates a non-empty provider credential without logging or serializing it. */
export function providerEnvironmentCredential(
  provider: ScanProvider | string,
  environment: ProcessEnvironment = process.env,
): ProviderEnvironmentCredential | null {
  const names =
    normalizeProvider(provider) === "openrouter"
      ? OPENROUTER_API_KEY_ENVIRONMENTS
      : OPENAI_API_KEY_ENVIRONMENTS;
  for (const environmentVariable of names) {
    const value = canonicalEnvironmentValue(environment, environmentVariable);
    if (value !== undefined) return { environmentVariable, value };
  }
  return null;
}

/**
 * Resolves the provider-specific authentication path and reports credential
 * availability without exposing the credential value.
 */
export function providerAuthentication(
  options: ProviderAuthenticationOptions = {},
): ProviderAuthentication {
  const provider = normalizeProvider(options.provider);
  const requestedMode = normalizeAuthMode(options.authMode ?? "auto");
  validateProviderAuthMode(provider, requestedMode);
  const environment = options.environment ?? process.env;
  const credential = providerEnvironmentCredential(provider, environment);

  if (provider === "openrouter" || requestedMode === "api-key") {
    return {
      provider,
      requestedMode,
      mode: "api-key",
      source: "environment",
      environmentVariable:
        credential?.environmentVariable ??
        (provider === "openrouter"
          ? OPENROUTER_API_KEY_ENV
          : OPENAI_API_KEY_ENV),
      credentialsAvailable: credential !== null,
    };
  }
  if (requestedMode === "auto" && credential !== null) {
    return {
      provider,
      requestedMode,
      mode: "api-key",
      source: "environment",
      environmentVariable: credential.environmentVariable,
      credentialsAvailable: true,
    };
  }
  return {
    provider: "openai",
    requestedMode,
    mode: "chatgpt",
    source: "stored_credentials",
    credentialsAvailable: options.storedCredentialsAvailable === true,
  };
}

/**
 * Produces the environment for a model process, retaining only credentials that
 * belong to the selected provider.
 */
export function modelProviderExecutionEnvironment(
  provider: ScanProvider | string,
  environment: ProcessEnvironment = process.env,
): ProcessEnvironment {
  const normalizedProvider = normalizeProvider(provider);
  const selectedNames =
    normalizedProvider === "openrouter"
      ? OPENROUTER_API_KEY_ENVIRONMENTS
      : OPENAI_API_KEY_ENVIRONMENTS;
  const isolated = filterEnvironment(
    environment,
    (name) => !isEnvironmentName(name, MODEL_PROVIDER_SECRET_ENV_KEYS),
  );
  for (const canonicalName of selectedNames) {
    const value = canonicalEnvironmentValue(environment, canonicalName);
    if (value !== undefined) isolated[canonicalName] = value;
  }
  return isolated;
}

/**
 * Produces the isolated OpenRouter bridge environment. Ambient forward proxies
 * are disabled so loopback traffic cannot escape, while existing NO_PROXY
 * exclusions remain available to the model process.
 */
export function openRouterBridgeExecutionEnvironment(
  environment: ProcessEnvironment,
  bridgeCredential: string,
): ProcessEnvironment {
  if (!bridgeCredential.trim()) {
    throw new ProviderConfigurationError(
      "OpenRouter bridge credential must be non-empty.",
    );
  }
  const selected = modelProviderExecutionEnvironment("openrouter", environment);
  const exclusions = noProxyExclusions(selected);
  const bridged = filterEnvironment(
    selected,
    (name) =>
      !isEnvironmentName(name, OPENROUTER_BRIDGE_PROXY_ENVIRONMENTS) &&
      !isEnvironmentName(name, OPENROUTER_API_KEY_ENVIRONMENTS) &&
      name.toUpperCase() !== "NO_PROXY",
  );
  const noProxy = exclusions.join(",");
  bridged[OPENROUTER_API_KEY_ENV] = bridgeCredential;
  bridged["NO_PROXY"] = noProxy;
  bridged["no_proxy"] = noProxy;
  return bridged;
}

/** Produces a helper-process environment with every model credential removed. */
export function helperProcessEnvironment(
  environment: ProcessEnvironment = process.env,
): ProcessEnvironment {
  return filterEnvironment(
    environment,
    (name) => !isEnvironmentName(name, MODEL_PROVIDER_SECRET_ENV_KEYS),
  );
}

function invalidOpenRouterMaxOutputTokens(): ProviderConfigurationError {
  return new ProviderConfigurationError(
    `${OPEN_SECURITY_OPENROUTER_MAX_OUTPUT_TOKENS_ENV} must contain decimal digits for an integer from 1 through ${MAX_OPENROUTER_OUTPUT_TOKENS}.`,
  );
}

function noProxyExclusions(environment: ProcessEnvironment): string[] {
  const exclusions: string[] = [];
  const seen = new Set<string>();
  const append = (value: string): void => {
    const normalized = value.toLowerCase();
    if (seen.has(normalized)) return;
    seen.add(normalized);
    exclusions.push(value);
  };
  for (const [name, value] of Object.entries(environment)) {
    if (name.toUpperCase() !== "NO_PROXY" || value === undefined) continue;
    for (const exclusion of value.split(",")) {
      const trimmed = exclusion.trim();
      if (trimmed) append(trimmed);
    }
  }
  append("127.0.0.1");
  append("localhost");
  return exclusions;
}

function normalizeProvider(value: string | undefined): ScanProvider {
  const normalized = value?.trim().toLowerCase();
  if (!normalized) return DEFAULT_SCAN_PROVIDER;
  if (normalized === "openai" || normalized === "openrouter") return normalized;
  throw new ProviderConfigurationError(
    `Unsupported model provider: ${value}. Expected openai or openrouter.`,
  );
}

function normalizeAuthMode(value: string): ProviderAuthMode {
  const normalized = value.trim().toLowerCase();
  if (
    normalized === "auto" ||
    normalized === "chatgpt" ||
    normalized === "api-key"
  ) {
    return normalized;
  }
  throw new ProviderConfigurationError(
    `Unsupported authentication mode: ${value}. Expected auto, chatgpt, or api-key.`,
  );
}

function resolveOptionalOverride(
  explicit: string | undefined,
  environment: ProcessEnvironment,
  environmentVariable: string,
  label: string,
): string | undefined {
  if (explicit !== undefined) {
    const value = explicit.trim();
    if (!value) {
      throw new ProviderConfigurationError(`${label} must be non-empty.`);
    }
    return value;
  }
  return optionalEnvironmentValue(environment, environmentVariable);
}

function optionalEnvironmentValue(
  environment: ProcessEnvironment,
  name: string,
): string | undefined {
  const value = environment[name]?.trim();
  return value || undefined;
}

function canonicalEnvironmentValue(
  environment: ProcessEnvironment,
  canonicalName: string,
): string | undefined {
  const exact = environment[canonicalName]?.trim();
  if (exact) return exact;
  return Object.entries(environment)
    .find(
      ([name, value]) => name.toUpperCase() === canonicalName && value?.trim(),
    )?.[1]
    ?.trim();
}

function filterEnvironment(
  environment: ProcessEnvironment,
  include: (name: string) => boolean,
): ProcessEnvironment {
  return Object.fromEntries(
    Object.entries(environment).filter(([name]) => include(name)),
  );
}

function isEnvironmentName(
  candidate: string,
  names: readonly string[],
): boolean {
  const normalized = candidate.toUpperCase();
  return names.some((name) => name === normalized);
}
