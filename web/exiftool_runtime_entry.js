import { parseMetadata } from "@uswriting/exiftool";
import zeroperlWasm from "@6over3/zeroperl-ts/zeroperl.wasm";

export const EXIFTOOL_VERSION = "13.42";
export const EXIFTOOL_ALL_ARGS = Object.freeze([
  "-json",
  "-a",
  "-u",
  "-G0:4",
  "-s",
  "-ee3",
  "-api",
  "RequestAll=3",
  "-api",
  "LargeFileSupport=1"
]);

function localWasmFetch() {
  return fetch(new URL(zeroperlWasm, import.meta.url));
}

export async function extractAllMetadata(name, data) {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const result = await parseMetadata(
    { name, data: bytes },
    {
      args: [...EXIFTOOL_ALL_ARGS],
      fetch: localWasmFetch,
      transform: (text) => JSON.parse(text)
    }
  );

  if (!result.success) {
    throw new Error(result.error || "ExifTool-WASM returned no metadata");
  }

  const rows = Array.isArray(result.data) ? result.data : [];
  return rows[0] || {};
}
