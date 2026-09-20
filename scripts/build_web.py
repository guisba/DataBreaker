from __future__ import annotations

import argparse
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
STATIC = ROOT / "databreaker" / "static"
PACKAGE = ROOT / "databreaker"


def build(output: Path) -> Path:
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
    shutil.copy2(STATIC / "worker.js", output / "worker.js")
    shutil.copytree(STATIC / "i18n", output / "i18n")

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
    args = parser.parse_args()
    build(Path(args.output).resolve())


if __name__ == "__main__":
    main()
