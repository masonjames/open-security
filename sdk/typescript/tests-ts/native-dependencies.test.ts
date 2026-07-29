import { spawnSync } from "node:child_process";
import { copyFile, mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterEach, describe, expect, test } from "bun:test";

const temporaryDirectories: string[] = [];
const sourceScript = fileURLToPath(
  new URL("../scripts/check-native-dependencies.mjs", import.meta.url),
);

afterEach(async () => {
  await Promise.all(
    temporaryDirectories
      .splice(0)
      .map((path) => rm(path, { recursive: true, force: true })),
  );
});

async function writePackage(
  root: string,
  name: string,
  options: { main?: string } = {},
): Promise<string> {
  const directory = join(root, "node_modules", ...name.split("/"));
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "package.json"),
    JSON.stringify({ name, version: "0.0.0", ...options }),
  );
  return directory;
}

async function nativeDependencyFixture(
  options: {
    codex?: boolean;
    canvas?: "available" | "missing" | "without-dom-matrix";
  } = {},
): Promise<string> {
  const root = await mkdtemp(
    join(tmpdir(), "codex-security-native-dependencies-"),
  );
  temporaryDirectories.push(root);

  const script = join(root, "check-native-dependencies.mjs");
  await copyFile(sourceScript, script);
  await writePackage(root, "@openai/codex");
  await writePackage(root, "pdfjs-dist");

  if (options.codex !== false) {
    await writePackage(
      root,
      `@openai/codex-${process.platform}-${process.arch}`,
    );
  }

  if (options.canvas !== "missing") {
    const directory = await writePackage(root, "@napi-rs/canvas", {
      main: "index.cjs",
    });
    await writeFile(
      join(directory, "index.cjs"),
      options.canvas === "without-dom-matrix"
        ? "module.exports = {};\n"
        : "module.exports = { DOMMatrix: class DOMMatrix {} };\n",
    );
  }

  return script;
}

function runNativeDependencyCheck(script: string) {
  return spawnSync("node", [script], {
    encoding: "utf8",
    timeout: 5_000,
    windowsHide: true,
  });
}

describe("native CI dependencies", () => {
  test("accepts available platform-native Codex and PDF dependencies", async () => {
    const result = runNativeDependencyCheck(await nativeDependencyFixture());

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    expect(result.stdout).toContain(
      `@openai/codex-${process.platform}-${process.arch}`,
    );
    expect(result.stdout).toContain("native PDF canvas dependencies");
  });

  test("rejects a silently omitted platform-native Codex package", async () => {
    const result = runNativeDependencyCheck(
      await nativeDependencyFixture({ codex: false }),
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain(
      `@openai/codex-${process.platform}-${process.arch}/package.json`,
    );
  });

  test("rejects a silently omitted native PDF canvas package", async () => {
    const result = runNativeDependencyCheck(
      await nativeDependencyFixture({ canvas: "missing" }),
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("@napi-rs/canvas");
  });

  test("rejects a PDF canvas without a usable native DOMMatrix", async () => {
    const result = runNativeDependencyCheck(
      await nativeDependencyFixture({ canvas: "without-dom-matrix" }),
    );

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(1);
    expect(result.stderr).toContain("does not provide DOMMatrix");
  });
});
