import { createRequire } from "node:module";

const require = createRequire(import.meta.url);
const codexRequire = createRequire(
  require.resolve("@openai/codex/package.json"),
);
const codexPackage = `@openai/codex-${process.platform}-${process.arch}`;

codexRequire.resolve(`${codexPackage}/package.json`);

const pdfRequire = createRequire(require.resolve("pdfjs-dist/package.json"));
const canvas = pdfRequire("@napi-rs/canvas");

if (typeof canvas.DOMMatrix !== "function") {
  throw new Error(
    "The native PDF canvas dependency does not provide DOMMatrix.",
  );
}

console.log(
  `Verified ${codexPackage} and native PDF canvas dependencies for ${process.platform}-${process.arch}.`,
);
