from __future__ import annotations

import binascii
import os
import struct
import tempfile
import zlib
from pathlib import Path

from playwright.sync_api import sync_playwright

PNG_SIG = b"\x89PNG\r\n\x1a\n"


def chunk(kind: bytes, payload: bytes) -> bytes:
    crc = binascii.crc32(kind + payload) & 0xFFFFFFFF
    return struct.pack(">I", len(payload)) + kind + payload + struct.pack(">I", crc)


def make_png(path: Path) -> None:
    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    raw = b"\x00\xff\x00\x00"
    data = (
        PNG_SIG
        + chunk(b"IHDR", ihdr)
        + chunk(b"tEXt", b"Author\x00Alice")
        + chunk(b"IDAT", zlib.compress(raw))
        + chunk(b"IEND", b"")
    )
    path.write_bytes(data)


def make_jpeg(path: Path) -> None:
    tiff = (
        b"II"
        + struct.pack("<H", 42)
        + struct.pack("<I", 8)
        + struct.pack("<H", 1)
        + struct.pack("<HHI", 0x0131, 2, 5)
        + struct.pack("<I", 26)
        + struct.pack("<I", 0)
        + b"Test\x00"
    )
    app1 = b"Exif\x00\x00" + tiff
    segment = b"\xff\xe1" + struct.pack(">H", len(app1) + 2) + app1
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    path.write_bytes(b"\xff\xd8" + segment + sos + b"\x11\x22\x33\xff\xd9")


def main() -> None:
    base_url = os.environ.get("DATABREAKER_E2E_URL", "http://127.0.0.1:8765/")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        png = tmp_path / "photo.png"
        jpg = tmp_path / "photo.jpg"
        make_png(png)
        make_jpeg(jpg)

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            console_errors: list[str] = []
            request_failures: list[str] = []
            page.on("pageerror", lambda exc: console_errors.append(str(exc)))
            page.on("requestfailed", lambda req: request_failures.append(f"{req.url}: {req.failure}"))
            page.goto(base_url, wait_until="domcontentloaded", timeout=60_000)
            page.locator("#fileInput").set_input_files([str(png), str(jpg)])

            page.wait_for_function(
                """() => document.querySelectorAll('.file-tab').length === 2 ||
                    !document.querySelector('#errorBanner').classList.contains('hidden')""",
                timeout=180_000,
            )
            if not page.locator("#errorBanner").evaluate("(el) => el.classList.contains('hidden')"):
                raise AssertionError(
                    "Browser engine failed before image tabs were created: "
                    + page.locator("#errorBanner").inner_text()
                    + (" | request failures: " + " ; ".join(request_failures) if request_failures else "")
                )
            page.wait_for_selector("#resultPanel:not(.hidden)", timeout=30_000)
            assert page.locator("#errorBanner").evaluate(
                "(el) => el.classList.contains('hidden')"
            ), page.locator("#errorBanner").inner_text()

            page.locator(".file-tab").nth(0).click()
            page.wait_for_timeout(100)
            assert "Author" in page.locator("#findings").inner_text()

            page.locator(".file-tab").nth(1).click()
            page.wait_for_timeout(100)
            assert "Software" in page.locator("#findings").inner_text()

            page.locator("#cleanBtn").click()
            page.wait_for_selector("#diffPanel:not(.hidden)", timeout=120_000)
            href = page.locator("#downloadBtn").get_attribute("href") or ""
            assert href.startswith("blob:"), href
            assert not console_errors, console_errors
            assert not request_failures, request_failures
            browser.close()


if __name__ == "__main__":
    main()
