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
    assert "functions" not in config


def test_browser_worker_uses_versioned_pyodide_and_pinned_parsers():
    root = Path(__file__).parents[1]
    worker = (root / "databreaker" / "static" / "worker.js").read_text(encoding="utf-8")
    assert "PYODIDE_VERSION='314.0.7'" in worker
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


def test_readme_preview_asset_exists_and_is_jpeg():
    root = Path(__file__).parents[1]
    preview = root / "docs" / "preview-v0.2.jpg"
    assert preview.is_file()
    assert preview.read_bytes().startswith(b"\x89PNG\r\n\x1a\n")
    assert "docs/preview-v0.2.jpg" in (root / "README.md").read_text(encoding="utf-8")
