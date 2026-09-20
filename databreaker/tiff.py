from __future__ import annotations

import struct
from dataclasses import dataclass


TAGS = {
    0x010E: "ImageDescription", 0x010F: "Make", 0x0110: "Model", 0x0112: "Orientation",
    0x0131: "Software", 0x0132: "DateTime", 0x013B: "Artist", 0x8298: "Copyright",
    0x8769: "ExifIFDPointer", 0x8825: "GPSInfoIFDPointer", 0xA420: "ImageUniqueID",
    0xA431: "BodySerialNumber", 0xA432: "LensSpecification", 0xA433: "LensMake",
    0xA434: "LensModel", 0xA435: "LensSerialNumber", 0x927C: "MakerNote",
    0x9003: "DateTimeOriginal", 0x9004: "DateTimeDigitized", 0x9010: "OffsetTime",
    0x9011: "OffsetTimeOriginal", 0x9012: "OffsetTimeDigitized", 0xA430: "CameraOwnerName",
}
GPS_TAGS = {0: "GPSVersionID", 1: "GPSLatitudeRef", 2: "GPSLatitude", 3: "GPSLongitudeRef", 4: "GPSLongitude", 5: "GPSAltitudeRef", 6: "GPSAltitude", 7: "GPSTimeStamp", 18: "GPSMapDatum", 29: "GPSDateStamp"}
TYPE_SIZE = {1: 1, 2: 1, 3: 2, 4: 4, 5: 8, 7: 1, 9: 4, 10: 8, 12: 8}


@dataclass
class TiffValue:
    name: str
    raw_tag: str
    value: object
    location: str


def _decode_value(data: bytes, endian: str, typ: int, count: int, raw: bytes, base_offset: int) -> object:
    size = TYPE_SIZE.get(typ, 1) * count
    if size > 4:
        off = struct.unpack(endian + "I", raw)[0]
        if off < 0 or off + size > len(data):
            return f"<invalid offset {off}>"
        buf = data[off:off + size]
    else:
        buf = raw[:size]
    try:
        if typ == 2:
            return buf.rstrip(b"\x00").decode("utf-8", "replace")
        if typ == 3:
            return list(struct.unpack(endian + f"{count}H", buf)) if count > 1 else struct.unpack(endian + "H", buf)[0]
        if typ == 4:
            return list(struct.unpack(endian + f"{count}I", buf)) if count > 1 else struct.unpack(endian + "I", buf)[0]
        if typ == 5:
            vals = []
            for i in range(count):
                n, d = struct.unpack(endian + "II", buf[i*8:i*8+8]); vals.append(n / d if d else None)
            return vals if count > 1 else vals[0]
        if typ in (1, 7):
            return buf.hex() if len(buf) > 32 else list(buf)
        return buf.hex()[:1024]
    except (struct.error, ValueError):
        return "<unparseable>"


def parse_tiff(data: bytes) -> list[TiffValue]:
    if data.startswith(b"Exif\x00\x00"):
        data = data[6:]
    if len(data) < 8 or data[:2] not in (b"II", b"MM"):
        return []
    endian = "<" if data[:2] == b"II" else ">"
    try:
        if struct.unpack(endian + "H", data[2:4])[0] != 42:
            return []
        first_ifd = struct.unpack(endian + "I", data[4:8])[0]
    except struct.error:
        return []
    values: list[TiffValue] = []
    visited: set[int] = set()

    def walk(off: int, label: str, names: dict[int, str], depth: int = 0) -> None:
        if depth > 4 or off in visited or off < 0 or off + 2 > len(data):
            return
        visited.add(off)
        try:
            count = struct.unpack(endian + "H", data[off:off+2])[0]
        except struct.error:
            return
        if count > 4096:
            return
        p = off + 2
        for _ in range(count):
            if p + 12 > len(data):
                break
            tag, typ, n = struct.unpack(endian + "HHI", data[p:p+8])
            raw = data[p+8:p+12]
            name = names.get(tag, f"UnknownTag0x{tag:04X}")
            val = _decode_value(data, endian, typ, n, raw, 0)
            values.append(TiffValue(name, f"0x{tag:04X}", val, label))
            if tag in (0x8769, 0x8825) and typ == 4 and n == 1:
                child = struct.unpack(endian + "I", raw)[0]
                walk(child, "GPS IFD" if tag == 0x8825 else "Exif IFD", GPS_TAGS if tag == 0x8825 else TAGS, depth + 1)
            p += 12
    walk(first_ifd, "IFD0", TAGS)
    return values
