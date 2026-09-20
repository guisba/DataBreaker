from __future__ import annotations

import re
import xml.etree.ElementTree as ET


KNOWN_NS = {
    "http://ns.adobe.com/xap/1.0/": "xmp",
    "http://purl.org/dc/elements/1.1/": "dc",
    "http://ns.adobe.com/photoshop/1.0/": "photoshop",
    "http://ns.adobe.com/exif/1.0/": "exif",
    "http://ns.adobe.com/tiff/1.0/": "tiff",
    "http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/": "iptc-core",
    "http://iptc.org/std/Iptc4xmpExt/2008-02-29/": "iptc-ext",
    "http://ns.adobe.com/xmp/1.0/mm/": "xmpMM",
    "http://ns.adobe.com/xap/1.0/rights/": "xmpRights",
}


def parse_xmp(payload: bytes) -> tuple[list[tuple[str, str, str]], list[str]]:
    text = payload.decode("utf-8", "replace")
    start = text.find("<")
    if start > 0:
        text = text[start:]
    items: list[tuple[str, str, str]] = []
    unknown_ns: list[str] = []
    for uri in set(re.findall(r'xmlns(?::\w+)?=["\']([^"\']+)', text)):
        if uri not in KNOWN_NS and not uri.startswith("http://www.w3.org/"):
            unknown_ns.append(uri)
    try:
        root = ET.fromstring(text)
    except ET.ParseError:
        return items, unknown_ns
    for elem in root.iter():
        for key, value in elem.attrib.items():
            if value and len(value) <= 16384:
                items.append((key, value, "attribute"))
        if elem.text and elem.text.strip() and len(elem.text.strip()) <= 16384:
            tag = elem.tag
            items.append((tag, elem.text.strip(), "element"))
    return items, unknown_ns
