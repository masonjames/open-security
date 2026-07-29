const NANODOLLARS_PER_DOLLAR = 1_000_000_000n;
const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_CACHE_TTL_MS = 60 * 60 * 1_000;
const MAX_PRICE_CHARACTERS = 64;
const MAX_MODEL_CATALOG_BYTES = 32 * 1024 * 1024;
const MAX_PROVIDER_ENDPOINT_BYTES = 4 * 1024 * 1024;

export const OPENROUTER_MODELS_URL = "https://openrouter.ai/api/v1/models";
export const OPENROUTER_MODEL_CATALOG_TTL_MS = DEFAULT_CACHE_TTL_MS;

export interface OpenRouterTokenPricingNanodollars {
  input: number;
  cachedInput: number;
  cacheWriteInput: number;
  output: number;
}

export interface OpenRouterModelMetadata {
  id: string;
  canonicalSlug: string | null;
  name: string | null;
  contextLength: number | null;
  supportedParameters: readonly string[];
  tokenPricingNanodollars: Readonly<OpenRouterTokenPricingNanodollars>;
  requestPricingNanodollars: number;
  unsupportedPricingNanodollars: number;
  pricingOverridesConsidered: number;
  providerEndpointsConsidered: number;
  fetchedAt: number;
}

export interface OpenRouterScanCapabilityRequirements {
  reasoning?: boolean;
}

export type OpenRouterCatalogFetch = (
  input: string,
  init?: RequestInit,
) => Promise<Response>;

export interface OpenRouterModelCatalogOptions {
  fetch?: OpenRouterCatalogFetch;
  now?: () => number;
  timeoutMs?: number;
  cacheTtlMs?: number;
  signal?: AbortSignal;
}

export type OpenRouterModelCatalogErrorCode =
  | "invalid-model-id"
  | "invalid-option"
  | "request-aborted"
  | "request-failed"
  | "request-timeout"
  | "http-error"
  | "invalid-response"
  | "model-not-found";

export class OpenRouterModelCatalogError extends Error {
  public readonly code: OpenRouterModelCatalogErrorCode;

  public constructor(code: OpenRouterModelCatalogErrorCode, message: string) {
    super(message);
    this.name = "OpenRouterModelCatalogError";
    this.code = code;
  }
}

export class OpenRouterModelCompatibilityError extends Error {
  public readonly modelId: string;
  public readonly missingParameters: readonly string[];

  public constructor(modelId: string, missingParameters: readonly string[]) {
    super(
      `OpenRouter model ${JSON.stringify(modelId)} does not advertise required ` +
        `parameter support: ${missingParameters.join(", ")}`,
    );
    this.name = "OpenRouterModelCompatibilityError";
    this.modelId = modelId;
    this.missingParameters = [...missingParameters];
  }
}

interface CatalogCache {
  expiresAt: number;
  fetchedAt: number;
  models: ReadonlyMap<string, unknown>;
}

interface ParsedPrice {
  nanodollars: number;
}

interface ParsedPricing {
  rates: OpenRouterTokenPricingNanodollars;
  request: number;
  unsupported: number;
  overrideCount: number;
}

interface ProviderEndpointCache {
  expiresAt: number;
  fetchedAt: number;
  pricing: ParsedPricing | null;
  endpointCount: number;
}

let catalogCache: CatalogCache | null = null;
const providerEndpointCache = new Map<string, ProviderEndpointCache>();

export async function fetchOpenRouterModel(
  modelId: string,
  options: OpenRouterModelCatalogOptions = {},
): Promise<OpenRouterModelMetadata> {
  const modelParts = validateModelId(modelId);
  const now = options.now ?? Date.now;
  const fetchedAt = now();
  if (!Number.isFinite(fetchedAt)) {
    throw new OpenRouterModelCatalogError(
      "invalid-option",
      "The OpenRouter catalog clock returned a non-finite value",
    );
  }
  const timeoutMs = positiveFiniteOption(
    options.timeoutMs,
    DEFAULT_TIMEOUT_MS,
    "timeoutMs",
  );
  const cacheTtlMs = nonNegativeFiniteOption(
    options.cacheTtlMs,
    DEFAULT_CACHE_TTL_MS,
    "cacheTtlMs",
  );
  const fetchFunction = options.fetch ?? globalThis.fetch;
  const requestOptions = { signal: options.signal, timeoutMs };
  throwIfRequestAborted(requestOptions.signal, "model catalog");

  let catalog = catalogCache;
  if (catalog === null || fetchedAt >= catalog.expiresAt) {
    const models = await requestCatalog(fetchFunction, requestOptions);
    catalog = {
      expiresAt: fetchedAt + cacheTtlMs,
      fetchedAt,
      models,
    };
    catalogCache = cacheTtlMs === 0 ? null : catalog;
  }

  const rawModel = catalog.models.get(modelId);
  if (rawModel === undefined) {
    throw new OpenRouterModelCatalogError(
      "model-not-found",
      `OpenRouter model ${JSON.stringify(modelId)} was not found in the public catalog`,
    );
  }
  const model = parseModel(rawModel, modelId, catalog.fetchedAt);
  const endpoints = await fetchProviderEndpoints(
    modelId,
    modelParts,
    fetchFunction,
    requestOptions,
    fetchedAt,
    cacheTtlMs,
  );
  return mergeProviderPricing(model, endpoints);
}

export function assertOpenRouterScanCapabilities(
  model: Pick<OpenRouterModelMetadata, "id" | "supportedParameters">,
  requirements: OpenRouterScanCapabilityRequirements = {},
): void {
  const supported = new Set(model.supportedParameters);
  const required = [
    "tools",
    "response_format",
    ...(requirements.reasoning === true ? ["reasoning"] : []),
  ];
  const missing = required.filter((parameter) => !supported.has(parameter));
  if (missing.length > 0) {
    throw new OpenRouterModelCompatibilityError(model.id, missing);
  }
}

export function clearOpenRouterModelCatalogCache(): void {
  catalogCache = null;
  providerEndpointCache.clear();
}

export function usdPerUnitToNanodollars(value: string): number {
  if (
    value.length === 0 ||
    value.length > MAX_PRICE_CHARACTERS ||
    !/^(?:0|[1-9]\d*)(?:\.\d+)?$/.test(value)
  ) {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `Invalid OpenRouter USD price ${JSON.stringify(value)}`,
    );
  }

  const [wholeText = "0", fractionText = ""] = value.split(".", 2);
  const whole = BigInt(wholeText);
  const firstNineDigits = fractionText.slice(0, 9).padEnd(9, "0");
  let nanodollars = whole * NANODOLLARS_PER_DOLLAR + BigInt(firstNineDigits);
  if (/[1-9]/.test(fractionText.slice(9))) nanodollars += 1n;
  if (nanodollars > BigInt(Number.MAX_SAFE_INTEGER)) {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `OpenRouter USD price ${JSON.stringify(value)} is too large`,
    );
  }
  return Number(nanodollars);
}

async function requestCatalog(
  fetchFunction: OpenRouterCatalogFetch,
  options: { signal?: AbortSignal; timeoutMs: number },
): Promise<ReadonlyMap<string, unknown>> {
  return parseCatalog(
    await requestOpenRouterJson(
      fetchFunction,
      OPENROUTER_MODELS_URL,
      "model catalog",
      options,
      MAX_MODEL_CATALOG_BYTES,
    ),
  );
}

async function requestOpenRouterJson(
  fetchFunction: OpenRouterCatalogFetch,
  url: string,
  resource: string,
  options: { signal?: AbortSignal; timeoutMs: number },
  maximumBytes: number,
): Promise<unknown> {
  if (typeof fetchFunction !== "function") {
    throw new OpenRouterModelCatalogError(
      "invalid-option",
      "No Fetch API implementation is available for OpenRouter metadata",
    );
  }
  const controller = new AbortController();
  let timedOut = false;
  const timeout = setTimeout(() => {
    timedOut = true;
    controller.abort();
  }, options.timeoutMs);
  timeout.unref?.();

  const abortFromCaller = () => controller.abort(options.signal?.reason);
  if (options.signal?.aborted === true) {
    abortFromCaller();
  } else {
    options.signal?.addEventListener("abort", abortFromCaller, { once: true });
  }

  try {
    let response: Response;
    try {
      response = await fetchFunction(url, {
        method: "GET",
        signal: controller.signal,
      });
    } catch (error) {
      if (timedOut) {
        throw new OpenRouterModelCatalogError(
          "request-timeout",
          `OpenRouter ${resource} request timed out after ${options.timeoutMs}ms`,
        );
      }
      if (controller.signal.aborted) {
        throw new OpenRouterModelCatalogError(
          "request-aborted",
          `OpenRouter ${resource} request was aborted`,
        );
      }
      throw new OpenRouterModelCatalogError(
        "request-failed",
        `OpenRouter ${resource} request failed: ${errorMessage(error)}`,
      );
    }

    if (!response.ok) {
      await response.body?.cancel().catch(() => undefined);
      throw new OpenRouterModelCatalogError(
        "http-error",
        `OpenRouter ${resource} returned HTTP ${response.status}`,
      );
    }
    try {
      return await readBoundedJsonResponse(response, resource, maximumBytes);
    } catch (error) {
      if (timedOut) {
        throw new OpenRouterModelCatalogError(
          "request-timeout",
          `OpenRouter ${resource} request timed out after ${options.timeoutMs}ms`,
        );
      }
      if (controller.signal.aborted) {
        throw new OpenRouterModelCatalogError(
          "request-aborted",
          `OpenRouter ${resource} request was aborted`,
        );
      }
      if (error instanceof OpenRouterModelCatalogError) throw error;
      throw new OpenRouterModelCatalogError(
        "invalid-response",
        `OpenRouter ${resource} did not return valid JSON`,
      );
    }
  } finally {
    clearTimeout(timeout);
    options.signal?.removeEventListener("abort", abortFromCaller);
  }
}

async function readBoundedJsonResponse(
  response: Response,
  resource: string,
  maximumBytes: number,
): Promise<unknown> {
  const declaredLength = response.headers.get("content-length");
  if (
    declaredLength !== null &&
    /^(?:0|[1-9]\d*)$/.test(declaredLength) &&
    Number(declaredLength) > maximumBytes
  ) {
    await response.body?.cancel().catch(() => undefined);
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `OpenRouter ${resource} response exceeds the ${maximumBytes}-byte limit`,
    );
  }
  if (response.body === null) {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `OpenRouter ${resource} did not return a response body`,
    );
  }

  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let totalBytes = 0;
  try {
    while (true) {
      const chunk = await reader.read();
      if (chunk.done) break;
      totalBytes += chunk.value.byteLength;
      if (totalBytes > maximumBytes) {
        await reader.cancel().catch(() => undefined);
        throw new OpenRouterModelCatalogError(
          "invalid-response",
          `OpenRouter ${resource} response exceeds the ${maximumBytes}-byte limit`,
        );
      }
      chunks.push(chunk.value);
    }
  } finally {
    reader.releaseLock();
  }

  const bytes = new Uint8Array(totalBytes);
  let offset = 0;
  for (const chunk of chunks) {
    bytes.set(chunk, offset);
    offset += chunk.byteLength;
  }
  let text: string;
  try {
    text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `OpenRouter ${resource} did not return valid UTF-8 JSON`,
    );
  }
  try {
    return JSON.parse(text) as unknown;
  } catch {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      `OpenRouter ${resource} did not return valid JSON`,
    );
  }
}

function parseCatalog(value: unknown): ReadonlyMap<string, unknown> {
  if (!isRecord(value) || !Array.isArray(value["data"])) {
    throw new OpenRouterModelCatalogError(
      "invalid-response",
      "OpenRouter model catalog response must contain a data array",
    );
  }
  const models = new Map<string, unknown>();
  for (const entry of value["data"]) {
    if (!isRecord(entry) || typeof entry["id"] !== "string") {
      throw new OpenRouterModelCatalogError(
        "invalid-response",
        "Every OpenRouter model catalog entry must have a string id",
      );
    }
    const id = entry["id"];
    if (id.length === 0 || models.has(id)) {
      throw new OpenRouterModelCatalogError(
        "invalid-response",
        `OpenRouter model catalog contains an invalid or duplicate id ${JSON.stringify(id)}`,
      );
    }
    models.set(id, entry);
  }
  return models;
}

function throwIfRequestAborted(
  signal: AbortSignal | undefined,
  resource: string,
): void {
  if (signal?.aborted !== true) return;
  throw new OpenRouterModelCatalogError(
    "request-aborted",
    `OpenRouter ${resource} request was aborted`,
  );
}

async function fetchProviderEndpoints(
  modelId: string,
  modelParts: readonly [author: string, slug: string],
  fetchFunction: OpenRouterCatalogFetch,
  requestOptions: { signal?: AbortSignal; timeoutMs: number },
  fetchedAt: number,
  cacheTtlMs: number,
): Promise<ProviderEndpointCache> {
  throwIfRequestAborted(requestOptions.signal, "provider endpoint catalog");
  const cached = providerEndpointCache.get(modelId);
  if (cached !== undefined && fetchedAt < cached.expiresAt) return cached;

  const [author, slug] = modelParts;
  const encodedAuthor = encodeModelIdPart(author, modelId);
  const encodedSlug = encodeModelIdPart(slug, modelId);
  const url = `${OPENROUTER_MODELS_URL}/${encodedAuthor}/${encodedSlug}/endpoints`;
  const response = await requestOpenRouterJson(
    fetchFunction,
    url,
    "provider endpoint catalog",
    requestOptions,
    MAX_PROVIDER_ENDPOINT_BYTES,
  );
  const parsed = parseProviderEndpoints(response, modelId);
  const next = {
    expiresAt: fetchedAt + cacheTtlMs,
    fetchedAt,
    ...parsed,
  };
  if (cacheTtlMs === 0) {
    providerEndpointCache.delete(modelId);
  } else {
    providerEndpointCache.set(modelId, next);
  }
  return next;
}

function parseProviderEndpoints(
  value: unknown,
  modelId: string,
): Pick<ProviderEndpointCache, "pricing" | "endpointCount"> {
  if (!isRecord(value) || !isRecord(value["data"])) {
    throw invalidModel(
      modelId,
      "provider endpoint response must contain a data object",
    );
  }
  const data = value["data"];
  if (data["id"] !== modelId) {
    throw invalidModel(modelId, "provider endpoint response id does not match");
  }
  if (!Array.isArray(data["endpoints"])) {
    throw invalidModel(
      modelId,
      "provider endpoint response must contain an endpoints array",
    );
  }
  if (data["endpoints"].length === 0) {
    throw invalidModel(
      modelId,
      "provider endpoint response has no routable provider endpoints",
    );
  }

  let pricing: ParsedPricing | null = null;
  for (const [index, endpoint] of data["endpoints"].entries()) {
    if (!isRecord(endpoint)) {
      throw invalidModel(modelId, `endpoints[${index}] must be an object`);
    }
    if (endpoint["model_id"] !== modelId) {
      throw invalidModel(
        modelId,
        `endpoints[${index}].model_id does not match`,
      );
    }
    if (!isRecord(endpoint["pricing"])) {
      throw invalidModel(
        modelId,
        `endpoints[${index}].pricing must be an object`,
      );
    }
    const endpointPricing = parsePricing(
      endpoint["pricing"],
      modelId,
      `endpoints[${index}].pricing`,
    );
    pricing =
      pricing === null
        ? endpointPricing
        : maximumPricing(pricing, endpointPricing);
  }
  return { pricing, endpointCount: data["endpoints"].length };
}

function mergeProviderPricing(
  model: OpenRouterModelMetadata,
  endpoints: ProviderEndpointCache,
): OpenRouterModelMetadata {
  const basePricing: ParsedPricing = {
    rates: model.tokenPricingNanodollars,
    request: model.requestPricingNanodollars,
    unsupported: model.unsupportedPricingNanodollars,
    overrideCount: model.pricingOverridesConsidered,
  };
  const pricing =
    endpoints.pricing === null
      ? basePricing
      : maximumPricing(basePricing, endpoints.pricing);
  return {
    ...model,
    tokenPricingNanodollars: pricing.rates,
    requestPricingNanodollars: pricing.request,
    unsupportedPricingNanodollars: pricing.unsupported,
    pricingOverridesConsidered: pricing.overrideCount,
    providerEndpointsConsidered: endpoints.endpointCount,
    fetchedAt: Math.max(model.fetchedAt, endpoints.fetchedAt),
  };
}

function maximumPricing(
  left: ParsedPricing,
  right: ParsedPricing,
): ParsedPricing {
  return {
    rates: {
      input: Math.max(left.rates.input, right.rates.input),
      cachedInput: Math.max(left.rates.cachedInput, right.rates.cachedInput),
      cacheWriteInput: Math.max(
        left.rates.cacheWriteInput,
        right.rates.cacheWriteInput,
      ),
      output: Math.max(left.rates.output, right.rates.output),
    },
    request: Math.max(left.request, right.request),
    unsupported: Math.max(left.unsupported, right.unsupported),
    overrideCount: left.overrideCount + right.overrideCount,
  };
}

function parseModel(
  value: unknown,
  expectedId: string,
  fetchedAt: number,
): OpenRouterModelMetadata {
  if (!isRecord(value) || value["id"] !== expectedId) {
    throw invalidModel(expectedId, "id does not match the requested model");
  }
  const canonicalSlug = nullableString(
    value["canonical_slug"],
    expectedId,
    "canonical_slug",
  );
  const name = nullableString(value["name"], expectedId, "name");
  const contextLength = nullableNonNegativeInteger(
    value["context_length"],
    expectedId,
    "context_length",
  );
  const supportedParameters = stringArray(
    value["supported_parameters"],
    expectedId,
    "supported_parameters",
  );
  if (!isRecord(value["pricing"])) {
    throw invalidModel(expectedId, "pricing must be an object");
  }
  const pricing = parsePricing(value["pricing"], expectedId);

  return {
    id: expectedId,
    canonicalSlug,
    name,
    contextLength,
    supportedParameters,
    tokenPricingNanodollars: pricing.rates,
    requestPricingNanodollars: pricing.request,
    unsupportedPricingNanodollars: pricing.unsupported,
    pricingOverridesConsidered: pricing.overrideCount,
    providerEndpointsConsidered: 0,
    fetchedAt,
  };
}

function parsePricing(
  pricing: Record<string, unknown>,
  modelId: string,
  path = "pricing",
): ParsedPricing {
  validateZeroDiscount(pricing["discount"], modelId, `${path}.discount`);
  const prompt = requiredPrice(pricing["prompt"], modelId, `${path}.prompt`);
  const completion = requiredPrice(
    pricing["completion"],
    modelId,
    `${path}.completion`,
  );
  const request = optionalPrice(pricing["request"], modelId, `${path}.request`);
  const cacheRead = optionalPrice(
    pricing["input_cache_read"],
    modelId,
    `${path}.input_cache_read`,
  );
  const cacheWrite = optionalPrice(
    pricing["input_cache_write"],
    modelId,
    `${path}.input_cache_write`,
  );
  let unsupportedPrice = maximumUnsupportedPrice(
    pricing,
    new Set([
      "prompt",
      "completion",
      "request",
      "input_cache_read",
      "input_cache_write",
      "discount",
      "overrides",
    ]),
    modelId,
    path,
  );
  const overridesValue = pricing["overrides"];
  if (overridesValue !== undefined && !Array.isArray(overridesValue)) {
    throw invalidModel(
      modelId,
      `${path}.overrides must be an array when present`,
    );
  }
  const overrides = overridesValue ?? [];

  let input = prompt.nanodollars;
  let output = completion.nanodollars;
  let requestPrice = request?.nanodollars ?? 0;
  let cachedInput = cacheRead?.nanodollars;
  let cacheWriteInput = cacheWrite?.nanodollars;
  for (const [index, value] of overrides.entries()) {
    if (!isRecord(value)) {
      throw invalidModel(
        modelId,
        `pricing.overrides[${index}] must be an object`,
      );
    }
    validateOverrideCondition(value, modelId, index, path);
    const prefix = `${path}.overrides[${index}]`;
    validateZeroDiscount(value["discount"], modelId, `${prefix}.discount`);
    const overridePrompt = optionalPrice(
      value["prompt"],
      modelId,
      `${prefix}.prompt`,
    );
    const overrideCompletion = optionalPrice(
      value["completion"],
      modelId,
      `${prefix}.completion`,
    );
    const overrideRequest = optionalPrice(
      value["request"],
      modelId,
      `${prefix}.request`,
    );
    const overrideCacheRead = optionalPrice(
      value["input_cache_read"],
      modelId,
      `${prefix}.input_cache_read`,
    );
    const overrideCacheWrite = optionalPrice(
      value["input_cache_write"],
      modelId,
      `${prefix}.input_cache_write`,
    );
    unsupportedPrice = Math.max(
      unsupportedPrice,
      maximumUnsupportedPrice(
        value,
        new Set([
          "min_prompt_tokens",
          "utc_start",
          "utc_end",
          "prompt",
          "completion",
          "request",
          "input_cache_read",
          "input_cache_write",
          "discount",
        ]),
        modelId,
        prefix,
      ),
    );
    input = Math.max(input, overridePrompt?.nanodollars ?? input);
    output = Math.max(output, overrideCompletion?.nanodollars ?? output);
    requestPrice = Math.max(
      requestPrice,
      overrideRequest?.nanodollars ?? requestPrice,
    );
    if (overrideCacheRead !== null) {
      cachedInput = Math.max(cachedInput ?? 0, overrideCacheRead.nanodollars);
    }
    if (overrideCacheWrite !== null) {
      cacheWriteInput = Math.max(
        cacheWriteInput ?? 0,
        overrideCacheWrite.nanodollars,
      );
    }
  }

  return {
    rates: {
      input,
      cachedInput:
        cacheRead === null ? Math.max(input, cachedInput ?? 0) : cachedInput!,
      cacheWriteInput:
        cacheWrite === null
          ? Math.max(input, cacheWriteInput ?? 0)
          : cacheWriteInput!,
      output,
    },
    request: requestPrice,
    unsupported: unsupportedPrice,
    overrideCount: overrides.length,
  };
}

function validateZeroDiscount(
  value: unknown,
  modelId: string,
  path: string,
): void {
  if (value === undefined || value === 0 || value === "0") return;
  throw invalidModel(
    modelId,
    `${path} must be zero until discount accounting is supported`,
  );
}

function maximumUnsupportedPrice(
  pricing: Record<string, unknown>,
  supportedKeys: ReadonlySet<string>,
  modelId: string,
  path: string,
): number {
  let maximum = 0;
  for (const [key, value] of Object.entries(pricing)) {
    if (supportedKeys.has(key)) continue;
    maximum = Math.max(
      maximum,
      requiredPrice(value, modelId, `${path}.${key}`).nanodollars,
    );
  }
  return maximum;
}

function validateOverrideCondition(
  value: Record<string, unknown>,
  modelId: string,
  index: number,
  pricingPath: string,
): void {
  const prefix = `${pricingPath}.overrides[${index}]`;
  if (
    value["min_prompt_tokens"] !== undefined &&
    !isNonNegativeInteger(value["min_prompt_tokens"])
  ) {
    throw invalidModel(
      modelId,
      `${prefix}.min_prompt_tokens must be a non-negative integer`,
    );
  }
  for (const field of ["utc_start", "utc_end"] as const) {
    const clock = value[field];
    if (clock !== undefined && !isUtcClock(clock)) {
      throw invalidModel(
        modelId,
        `${prefix}.${field} must be a valid HHMM integer`,
      );
    }
  }
}

function requiredPrice(
  value: unknown,
  modelId: string,
  path: string,
): ParsedPrice {
  const price = optionalPrice(value, modelId, path);
  if (price === null)
    throw invalidModel(modelId, `${path} must be a price string`);
  return price;
}

function optionalPrice(
  value: unknown,
  modelId: string,
  path: string,
): ParsedPrice | null {
  if (value === undefined) return null;
  if (typeof value !== "string") {
    throw invalidModel(modelId, `${path} must be a price string`);
  }
  try {
    return { nanodollars: usdPerUnitToNanodollars(value) };
  } catch (error) {
    if (error instanceof OpenRouterModelCatalogError) {
      throw invalidModel(modelId, `${path} is invalid: ${error.message}`);
    }
    throw error;
  }
}

function encodeModelIdPart(part: string, modelId: string): string {
  try {
    return encodeURIComponent(part);
  } catch {
    throw new OpenRouterModelCatalogError(
      "invalid-model-id",
      `Invalid OpenRouter model id ${JSON.stringify(modelId)}`,
    );
  }
}

function validateModelId(
  modelId: string,
): readonly [author: string, slug: string] {
  const parts = modelId.split("/");
  const author = parts[0];
  const slug = parts[1];
  if (
    modelId.length === 0 ||
    modelId.length > 512 ||
    modelId.trim() !== modelId ||
    /\s|[\u0000-\u001f\u007f]/.test(modelId) ||
    parts.length !== 2 ||
    author === undefined ||
    slug === undefined ||
    author.length === 0 ||
    slug.length === 0 ||
    author === "." ||
    author === ".." ||
    slug === "." ||
    slug === ".."
  ) {
    throw new OpenRouterModelCatalogError(
      "invalid-model-id",
      `Invalid OpenRouter model id ${JSON.stringify(modelId)}`,
    );
  }
  encodeModelIdPart(author, modelId);
  encodeModelIdPart(slug, modelId);
  return [author, slug];
}

function positiveFiniteOption(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isFinite(resolved) || resolved <= 0) {
    throw new OpenRouterModelCatalogError(
      "invalid-option",
      `${name} must be a positive finite number`,
    );
  }
  return resolved;
}

function nonNegativeFiniteOption(
  value: number | undefined,
  fallback: number,
  name: string,
): number {
  const resolved = value ?? fallback;
  if (!Number.isFinite(resolved) || resolved < 0) {
    throw new OpenRouterModelCatalogError(
      "invalid-option",
      `${name} must be a non-negative finite number`,
    );
  }
  return resolved;
}

function nullableString(
  value: unknown,
  modelId: string,
  field: string,
): string | null {
  if (value === undefined || value === null) return null;
  if (typeof value !== "string") {
    throw invalidModel(modelId, `${field} must be a string or null`);
  }
  return value;
}

function nullableNonNegativeInteger(
  value: unknown,
  modelId: string,
  field: string,
): number | null {
  if (value === undefined || value === null) return null;
  if (!isNonNegativeInteger(value)) {
    throw invalidModel(
      modelId,
      `${field} must be a non-negative integer or null`,
    );
  }
  return value;
}

function stringArray(
  value: unknown,
  modelId: string,
  field: string,
): readonly string[] {
  if (
    !Array.isArray(value) ||
    value.some((entry) => typeof entry !== "string")
  ) {
    throw invalidModel(modelId, `${field} must be an array of strings`);
  }
  return [...new Set(value)];
}

function isNonNegativeInteger(value: unknown): value is number {
  return Number.isSafeInteger(value) && (value as number) >= 0;
}

function isUtcClock(value: unknown): value is number {
  if (
    !Number.isInteger(value) ||
    (value as number) < 0 ||
    (value as number) > 2359
  ) {
    return false;
  }
  return (value as number) % 100 < 60;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function invalidModel(
  modelId: string,
  detail: string,
): OpenRouterModelCatalogError {
  return new OpenRouterModelCatalogError(
    "invalid-response",
    `Invalid catalog data for OpenRouter model ${JSON.stringify(modelId)}: ${detail}`,
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
