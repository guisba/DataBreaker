import { build } from "esbuild";
import path from "node:path";
import process from "node:process";

const output = path.resolve(process.argv[2] || "dist");

await build({
  entryPoints: ["web/exiftool_runtime_entry.js"],
  bundle: true,
  format: "esm",
  platform: "browser",
  target: ["es2022"],
  outfile: path.join(output, "exiftool-runtime.js"),
  loader: { ".wasm": "file", ".txt": "text" },
  assetNames: "exiftool/[name]-[hash]",
  logLevel: "info"
});
