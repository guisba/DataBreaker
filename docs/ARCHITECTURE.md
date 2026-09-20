# DataBreaker architecture

DataBreaker is a local-first Python application. The browser UI talks only to a FastAPI process bound to `127.0.0.1`. Uploaded files are written to a private temporary directory created by the local process; the application does not include analytics, telemetry, remote upload, or cloud parsing.

## Processing pipeline

`detector → format handler → extractor → origin analyzer → privacy classifier → cleaner → validator → second scan → diff/report`

The engine does not treat a library call returning successfully as proof of sanitization. A cleaned output is reopened with the format handler, rescanned, and compared with the requested policy. Where a content hash can be separated from container metadata, DataBreaker records a primary-content hash and compares it before/after.

## Format handlers

- `JPEGHandler`: JPEG markers, APP0–APP15, EXIF/TIFF IFDs, XMP, Photoshop/IPTC APP13, ICC APP2, JUMBF/C2PA indicators, unknown APP segments. Rewrites metadata segments without decoding/recompressing image data.
- `PNGHandler`: validates signature/chunk CRCs, reads textual chunks, eXIf, iCCP, C2PA-like ancillary chunks and unknown ancillary chunks. Rewrites chunks and preserves IDAT bytes.
- `WebPHandler`: RIFF chunk inspection for EXIF/XMP/ICCP and unknown chunks. Rewrites the RIFF container and fixes VP8X metadata flags without transcoding VP8/VP8L payloads.
- `SVGHandler`: XML metadata/editor namespaces. Cleaning is XML reserialization and therefore reported explicitly.
- `OOXMLHandler`: DOCX/XLSX/PPTX package properties, custom XML, comments, revisions, external relationships, thumbnails and ZIP metadata. It sanitizes package properties and archive metadata; comments, revisions and embedded content are reported but never silently deleted.
- `ArchiveHandler`: ZIP/TAR metadata, paths, timestamps, extra fields, permissions, UID/GID and compression-ratio checks. ZIP rewriting preserves member payload bytes.
- `PDFHandler`: Info dictionary, XMP/catalog signals, attachments, annotations, JavaScript, `/ID`, incremental update markers and signatures. PDF cleaning is conservative and warns that structural rewriting invalidates byte-level signatures.
- `AudioHandler`: Mutagen-backed tags for MP3/FLAC/OGG/WAV without audio transcoding.
- `ISOBMFFHandler`: MP4/MOV/M4A/HEIF/AVIF boxes, QuickTime privacy keys, XMP/C2PA indicators and media-data hashing. MP4/MOV/M4A tags can be rewritten through Mutagen; HEIF/AVIF is analysis-only by default.

## Optional local enrichment

If `exiftool` already exists on `PATH`, DataBreaker invokes it read-only with JSON/group/unknown-tag options. This improves coverage of MakerNotes and manufacturer-specific fields without making ExifTool a required dependency. Findings discovered only through ExifTool are not claimed as removed by the core cleaner.

DataBreaker does not invoke network-based provenance verification by default. C2PA structures are recognized locally; cryptographic trust validation is intentionally kept separate from ordinary metadata removal.

## Confidence model

- **Confirmed** — direct structured field, tag, or parser result.
- **High confidence** — strong format/application-specific indicator.
- **Possible** — plausible origin signal with ambiguity.
- **Weak indicator** — low-specificity string or context clue.
- **Unknown** — unclassified/custom structure.

Derived origin findings always retain their evidence field. A software string is not treated as cryptographic proof of origin.

## Cleaning modes

- **Safe Clean** removes common privacy metadata while preserving compatibility-oriented structural data.
- **Deep Clean** additionally removes uncommon/application metadata when the handler has a content-preserving rewrite.
- **Clean Everything** removes every known nonessential field the handler can safely rewrite. It may remove provenance blocks and therefore warns about C2PA/signatures. Content-like items remain untouched unless a future explicit user-controlled operation is added.

Normalization profiles influence structural preservation and required placeholder values. `Preserve Compatibility` keeps compatibility-sensitive metadata such as ICC profiles and package timestamps. `Minimal` uses the smallest valid placeholder where a format requires one. `Generic` uses neutral valid values and records those normalized fields as synthetic in the local report. `Custom` exposes explicit switches for ICC/color-profile and archive/package-timestamp preservation. DataBreaker does not fabricate manufacturer identities, device serials, certificate chains or C2PA claims.

## Security boundaries

Files are hostile input. The current boundary includes per-file and file-count limits, bounded metadata decoding, archive path checks, entry/uncompressed-size/compression-ratio limits, disabled nested-archive expansion in 0.1, CRC/structure validation, safe temporary names, no embedded-code execution, and no automatic network access. Parsers use defensive offsets/count limits and surface malformed structures rather than trusting them.

The local web process has the same filesystem permissions as the user who launched it. DataBreaker should therefore be run as an ordinary user, not with administrator/root privileges.
