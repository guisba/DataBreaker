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
        + chunk(b"tEXt", b"Author\x00Bob")
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
    sof0 = b"\xff\xc0\x00\x0b\x08\x00\x01\x00\x01\x01\x01\x11\x00"
    sos = b"\xff\xda\x00\x08\x01\x01\x00\x00\x3f\x00"
    path.write_bytes(b"\xff\xd8" + segment + sof0 + sos + b"\x11\x22\x33\xff\xd9")


def main() -> None:
    base_url = os.environ.get("DATABREAKER_E2E_URL", "http://127.0.0.1:8765/")
    with tempfile.TemporaryDirectory() as tmp:
        tmp_path = Path(tmp)
        png = tmp_path / "photo.png"
        jpg = tmp_path / "photo.jpg"
        make_png(png)
        make_jpeg(jpg)
        c2pa = Path(__file__).parent / "fixtures" / "c2pa.svg"
        modern_c2pa_env = os.environ.get("DATABREAKER_MODERN_C2PA_FIXTURE")
        modern_c2pa = Path(modern_c2pa_env) if modern_c2pa_env else None

        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1440, "height": 1000})
            console_errors: list[str] = []
            request_failures: list[str] = []
            page.on("pageerror", lambda exc: console_errors.append(str(exc)))
            page.on("requestfailed", lambda req: request_failures.append(f"{req.url}: {req.failure}"))
            page.goto(base_url, wait_until="domcontentloaded", timeout=60_000)
            upload_files = [str(png), str(jpg), str(c2pa)]
            if modern_c2pa is not None:
                assert modern_c2pa.is_file(), modern_c2pa
                upload_files.append(str(modern_c2pa))
            page.locator("#fileInput").set_input_files(upload_files)

            expected_tabs = len(upload_files)
            page.wait_for_function(
                f"""() => document.querySelectorAll('.file-tab').length === {expected_tabs} ||
                    !document.querySelector('#errorBanner').classList.contains('hidden')""",
                timeout=300_000,
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
            png_text = page.locator("#findings").inner_text()
            for field in ("Author", "FileName", "FileType", "MIMEType", "ImageWidth", "ImageHeight", "BitDepth", "Compression"):
                assert field in png_text, (field, png_text)
            assert "Alice" in png_text, png_text
            assert "Bob" in png_text, png_text

            page.locator(".file-tab").nth(1).click()
            page.wait_for_timeout(100)
            jpg_text = page.locator("#findings").inner_text()
            for field in ("Software", "FileName", "FileType", "MIMEType", "ImageWidth", "ImageHeight"):
                assert field in jpg_text, (field, jpg_text)

            page.locator(".file-tab").nth(2).click()
            page.wait_for_timeout(100)
            c2pa_text = page.locator("#findings").inner_text()
            assert "JUMDType" in c2pa_text, c2pa_text
            assert "JUMDLabel" in c2pa_text, c2pa_text


            if modern_c2pa is not None:
                page.locator(".file-tab").nth(3).click()
                page.wait_for_timeout(100)
                modern_text = page.locator("#findings").inner_text()
                for field in (
                    "JUMDLabel",
                    "ActionsAction",
                    "ActionsSoftwareAgentName",
                    "ActionsDigitalSourceType",
                    "Claim_Generator_InfoName",
                ):
                    assert field in modern_text, (field, modern_text)
                assert "trainedAlgorithmicMedia" in modern_text, modern_text
                assert "ChatGPT" in modern_text or "GPT-4o" in modern_text, modern_text

            page.locator(".file-tab").nth(1).click()
            page.locator("#cleanBtn").click()
            page.wait_for_selector("#diffPanel:not(.hidden)", timeout=120_000)
            href = page.locator("#downloadBtn").get_attribute("href") or ""
            assert href.startswith("blob:"), href
            assert not console_errors, console_errors
            assert not request_failures, request_failures
            browser.close()


if __name__ == "__main__":
    main()
