from __future__ import annotations

import argparse
import hashlib
import shutil
import subprocess
import tarfile
import tempfile
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "databreaker" / "static"
PACKAGE = ROOT / "databreaker"

PYODIDE_VERSION = "314.0.7"
PYODIDE_CORE_URL = (
    "https://github.com/pyodide/pyodide/releases/download/"
    f"{PYODIDE_VERSION}/pyodide-core-{PYODIDE_VERSION}.tar.bz2"
)
PYODIDE_CORE_SHA256 = "2abdcc2e35208af406e07724cffa85bc582ced97e9028383ecf5462541393f95"
PYODIDE_RUNTIME_FILES = {
    "pyodide.js",
    "pyodide.mjs",
    "pyodide.asm.mjs",
    "pyodide.asm.wasm",
    "pyodide-lock.json",
    "python_stdlib.zip",
}


def _download_pyodide_core(destination: Path) -> None:
    destination.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory() as tmp:
        archive = Path(tmp) / "pyodide-core.tar.bz2"
        request = urllib.request.Request(
            PYODIDE_CORE_URL,
            headers={"User-Agent": "DataBreaker-web-build/0.2"},
        )
        with urllib.request.urlopen(request, timeout=120) as response, archive.open("wb") as fh:
            shutil.copyfileobj(response, fh)

        digest = hashlib.sha256(archive.read_bytes()).hexdigest()
        if digest != PYODIDE_CORE_SHA256:
            raise RuntimeError(
                f"Pyodide core checksum mismatch: expected {PYODIDE_CORE_SHA256}, got {digest}"
            )

        extracted: set[str] = set()
        with tarfile.open(archive, "r:bz2") as bundle:
            for member in bundle.getmembers():
                path = Path(member.name)
                if len(path.parts) != 2 or path.parts[0] != "pyodide":
                    continue
                filename = path.name
                if filename not in PYODIDE_RUNTIME_FILES or not member.isfile():
                    continue
                source = bundle.extractfile(member)
                if source is None:
                    raise RuntimeError(f"Unable to extract {member.name}")
                with source, (destination / filename).open("wb") as target:
                    shutil.copyfileobj(source, target)
                extracted.add(filename)

        missing = PYODIDE_RUNTIME_FILES - extracted
        if missing:
            raise RuntimeError(f"Pyodide core archive missing required files: {sorted(missing)}")


def build(output: Path, *, vendor_pyodide: bool = False, vendor_exiftool: bool = False) -> Path:
    if output.exists():
        shutil.rmtree(output)
    output.mkdir(parents=True)

    html = (STATIC / "index.html").read_text(encoding="utf-8")
    html = html.replace('href="/static/styles.css"', 'href="./styles.css"')
    html = html.replace('src="/static/app.js"', 'src="./app.js"')
    html = html.replace(
        "</head>",
        '  <script>window.__DATABREAKER_BROWSER_ONLY__=true;</script>\n</head>',
    )
    (output / "index.html").write_text(html, encoding="utf-8")
    shutil.copy2(STATIC / "styles.css", output / "styles.css")
    shutil.copy2(STATIC / "app.js", output / "app.js")

    worker = (STATIC / "worker.js").read_text(encoding="utf-8")
    if vendor_pyodide:
        worker = worker.replace(
            "const PYODIDE_BASE=PYODIDE_CDN_BASE;",
            "const PYODIDE_BASE='./pyodide/';",
        )
        _download_pyodide_core(output / "pyodide")
    (output / "worker.js").write_text(worker, encoding="utf-8")

    shutil.copytree(STATIC / "i18n", output / "i18n")

    if vendor_exiftool:
        subprocess.run(
            ["node", "scripts/build_exiftool.mjs", str(output)],
            cwd=ROOT,
            check=True,
        )
        if not (output / "exiftool-runtime.js").is_file():
            raise RuntimeError("ExifTool browser bundle was not generated")
        if not any((output / "exiftool").glob("*.wasm")):
            raise RuntimeError("ExifTool ZeroPerl WASM asset was not generated")

    target_pkg = output / "python" / "databreaker"
    shutil.copytree(PACKAGE, target_pkg)
    shutil.rmtree(target_pkg / "static", ignore_errors=True)
    for filename in ("app.py", "__main__.py"):
        (target_pkg / filename).unlink(missing_ok=True)
    for pycache in target_pkg.rglob("__pycache__"):
        shutil.rmtree(pycache, ignore_errors=True)

    (output / "robots.txt").write_text("User-agent: *\nAllow: /\n", encoding="utf-8")
    return output


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(ROOT / "dist"))
    parser.add_argument(
        "--vendor-pyodide",
        action="store_true",
        help="Bundle the verified Pyodide core so uploads do not depend on a runtime CDN.",
    )
    parser.add_argument(
        "--vendor-exiftool",
        action="store_true",
        help="Bundle ExifTool/ZeroPerl WASM so full metadata inventory runs locally in the browser.",
    )
    args = parser.parse_args()
    build(
        Path(args.output).resolve(),
        vendor_pyodide=args.vendor_pyodide,
        vendor_exiftool=args.vendor_exiftool,
    )


if __name__ == "__main__":
    main()
