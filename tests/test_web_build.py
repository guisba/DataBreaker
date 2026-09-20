from pathlib import Path

from scripts.build_web import build


def test_static_web_build_is_browser_only(tmp_path: Path):
    out = build(tmp_path / "site")
    html = (out / "index.html").read_text(encoding="utf-8")
    assert "window.__DATABREAKER_BROWSER_ONLY__=true" in html
    assert '/static/styles.css' not in html
    assert '/static/app.js' not in html
    assert (out / "worker.js").is_file()
    assert (out / "i18n" / "en.json").is_file()
    assert (out / "python" / "databreaker" / "engine.py").is_file()
    assert not (out / "python" / "databreaker" / "app.py").exists()


def test_ui_avoids_decorative_ai_slop_patterns():
    root = Path(__file__).parents[1]
    css = (root / "databreaker" / "static" / "styles.css").read_text(encoding="utf-8")
    html = (root / "databreaker" / "static" / "index.html").read_text(encoding="utf-8")
    assert "linear-gradient" not in css
    assert "radial-gradient" not in css
    assert "filter:blur" not in css.replace(" ", "")
    assert 'id="themeBtn"' in html
    assert 'data-theme="mono"' in html
    assert 'html[data-theme="red"]' in css


def test_vercel_config_serves_static_browser_build_only():
    import json
    root = Path(__file__).parents[1]
    config = json.loads((root / "vercel.json").read_text(encoding="utf-8"))
    assert config["outputDirectory"] == "dist"
    assert "build_web.py" in config["buildCommand"]
    assert "--vendor-pyodide" in config["buildCommand"]
    assert "functions" not in config


def test_browser_worker_uses_versioned_pyodide_and_pinned_parsers():
    root = Path(__file__).parents[1]
    worker = (root / "databreaker" / "static" / "worker.js").read_text(encoding="utf-8")
    assert "PYODIDE_VERSION='314.0.7'" in worker
    assert "PYODIDE_CDN_BASE" in worker
    assert "packageBaseUrl:PYODIDE_CDN_BASE" in worker
    assert "/dev/" not in worker
    assert "pypdf>=5,<7" in worker
    assert "mutagen>=1.47,<2" in worker


def test_public_bundle_targets_vercel_not_appdeploy():
    root = Path(__file__).parents[1]
    app = (root / "databreaker" / "static" / "app.js").read_text(encoding="utf-8").lower()
    readme = (root / "README.md").read_text(encoding="utf-8").lower()
    privacy = (root / "PRIVACY.md").read_text(encoding="utf-8").lower()
    assert ".vercel.app" in app
    assert "appdeploy" not in app
    assert "github pages edition" not in readme
    assert "public vercel edition" in privacy
    assert "appdeploy" not in readme
    assert "appdeploy" not in privacy


def test_readme_preview_asset_exists_and_is_jpeg():
    root = Path(__file__).parents[1]
    preview = root / "docs" / "preview-v0.2.jpg"
    assert preview.is_file()
    assert preview.read_bytes().startswith(b"\xff\xd8\xff")
    assert "docs/preview-v0.2.jpg" in (root / "README.md").read_text(encoding="utf-8")


def test_image_upload_path_does_not_require_optional_parsers():
    root = Path(__file__).parents[1]
    worker = (root / "databreaker" / "static" / "worker.js").read_text(encoding="utf-8")
    init_block = worker.split("async function init(){", 1)[1].split("function optionalPackageFor", 1)[0]
    assert "micropip.install" not in init_block
    assert "loadPackage('micropip')" not in init_block
    assert "if(lower.endsWith('.pdf'))return 'pypdf';" in worker
    assert "mp3|flac|ogg|wav|mp4|mov|m4a|m4b" in worker


def test_finding_filters_bind_to_all_buttons():
    root = Path(__file__).parents[1]
    app = (root / "databreaker" / "static" / "app.js").read_text(encoding="utf-8")
    good = ";" + "$" + "$" + "('.filter').forEach"
    bad = ";" + "$" + "('.filter').forEach"
    assert good in app
    assert bad not in app

def test_scan_errors_are_isolated_per_file():
    root = Path(__file__).parents[1]
    app = (root / "databreaker" / "static" / "app.js").read_text(encoding="utf-8")
    assert "const valid=[],errors=[];" in app
    assert "errors.push" in app
    assert "if(valid.length)" in app


def test_pyodide_core_download_is_pinned_by_checksum():
    root = Path(__file__).parents[1]
    builder = (root / "scripts" / "build_web.py").read_text(encoding="utf-8")
    assert 'PYODIDE_VERSION = "314.0.7"' in builder
    assert "pyodide-core-{PYODIDE_VERSION}.tar.bz2" in builder
    assert 'PYODIDE_CORE_SHA256 = "2abdcc2e35208af406e07724cffa85bc582ced97e9028383ecf5462541393f95"' in builder
    assert "const PYODIDE_BASE='./pyodide/';" in builder


def test_pyodide_uses_module_worker():
    root = Path(__file__).parents[1]
    app = (root / "databreaker" / "static" / "app.js").read_text(encoding="utf-8")
    worker = (root / "databreaker" / "static" / "worker.js").read_text(encoding="utf-8")
    assert "new Worker('./worker.js',{type:'module'})" in app
    assert "pyodide.mjs" in worker
    assert "importScripts(" not in worker


def test_hosting_metadata_has_no_stale_deployment_references():
    root = Path(__file__).parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8").lower()
    privacy = (root / "PRIVACY.md").read_text(encoding="utf-8").lower()
    pyproject = (root / "pyproject.toml").read_text(encoding="utf-8").lower()
    release = (root / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8").lower()

    assert "****" not in readme
    assert "appdeploy" not in readme
    assert "appdeploy" not in privacy
    assert "appdeploy" not in release
    assert "[tool.vercel]" not in pyproject
    assert "vercel deployment pending verification" in release
    assert "vendors the pyodide core runtime" in privacy
