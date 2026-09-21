# Metadata and provenance research

This document records the technical basis for DataBreaker 0.3. It is deliberately conservative: metadata ecosystems are open-ended, proprietary MakerNotes evolve, and some provenance is embedded in media content rather than removable metadata. “No known sensitive metadata detected” is not equivalent to proof that a file has no identifying signal.

## Full-inventory baseline

DataBreaker 0.3 uses ExifTool 13.59 as its broad metadata inventory baseline in the public browser edition, bundled through WebAssembly/ZeroPerl. The inventory command enables duplicate tags (`-a`), unknown tags (`-u`), unique group-qualified JSON keys (`-G0:4`), deep embedded-document extraction (`-ee3`) and `RequestAll=3`. The local native-ExifTool integration uses the same extraction strategy.

This is intentionally different from maintaining a finite list of "supported metadata fields": ExifTool-decoded fields are surfaced even when DataBreaker does not yet have a semantic explanation for them. Unknown and proprietary tags remain visible raw. DataBreaker native parsers then add risk/origin interpretation and provide conservative writers for formats where sanitization can be verified.

Pics.io's public metadata viewers are used as a product parity baseline for common families such as JPEG/PNG/GIF/WebP/JFIF, PDF, common camera RAW formats, and MP4/MOV/M4V. DataBreaker is not affiliated with Pics.io; parity means the product should not omit an ExifTool-visible metadata field merely because it is not part of DataBreaker's native parser vocabulary.

ExifTool's `File*`/System values require special handling. Access time, inode-change time and permissions describe filesystem state, not necessarily bytes embedded in the source asset. They are displayed, but categorized as filesystem/runtime metadata so browser/temp-file values are not misrepresented as original embedded metadata.

Sources:
- ExifTool application documentation: https://exiftool.org/exiftool_pod.html
- ExifTool tag tables: https://exiftool.org/TagNames/
- ExifTool C2PA/JUMBF tags: https://exiftool.org/TagNames/Jpeg2000.html
- Pics.io Metadata Viewer: https://pics.io/metadata-viewer

## Images

### EXIF / TIFF / MakerNotes

EXIF uses TIFF-style Image File Directories (IFDs). Privacy-relevant fields include device make/model, software, timestamps and timezone offsets, GPS IFDs, camera owner, body/lens serials, image unique IDs and MakerNotes. MakerNotes are manufacturer-specific and can be offset-sensitive. DataBreaker’s built-in TIFF reader extracts common fields and records unrecognized tags; the v0.3 full-inventory layer also exposes ExifTool-decoded vendor-specific, duplicate and unknown tags in both browser and local workflows.

ExifTool’s documentation is especially important for cleaning policy: it warns that Make/Model can be needed to interpret MakerNotes and that careless MakerNote rewriting can damage interpretation. DataBreaker therefore avoids pretending that generic tag deletion is always safe for RAW or proprietary camera structures.

Sources:
- CIPA Exif specifications: https://www.cipa.jp/std/documents/e/DC-008-Translation-2023-E.pdf
- ExifTool application documentation: https://exiftool.org/exiftool_pod.html
- ExifTool FAQ / MakerNote cautions: https://exiftool.org/faq.html
- ExifTool tag tables: https://exiftool.org/TagNames/

### JPEG

JPEG application markers can carry multiple metadata families. APP1 commonly carries EXIF or XMP; APP2 can carry ICC profiles; APP13 can carry Photoshop Image Resource Blocks (8BIM) and IPTC IIM; APP11 is used by JPEG Universal Metadata Box Format structures including C2PA/JUMBF packaging. Unknown APP segments are retained as unknown instead of guessed.

Color profiles are compatibility-sensitive rather than inherently private, so Safe Clean does not remove them. Embedded thumbnails and MakerNotes can contain secondary copies or identifiers and are treated as metadata-bearing structures.

Sources:
- CIPA Exif specification above
- IPTC Photo Metadata Standard 2025.1: https://www.iptc.org/std/photometadata/specification/IPTC-PhotoMetadata-2025.1.html
- C2PA specification: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html

### PNG

PNG is chunk-based. The W3C specification defines textual `tEXt`, `zTXt` and `iTXt`, EXIF `eXIf`, ICC `iCCP`, and rules for private/unknown ancillary chunks. DataBreaker validates chunk CRCs, extracts known text/EXIF and labels unfamiliar ancillary chunks as unknown.

Source:
- W3C PNG Third Edition: https://www.w3.org/TR/png-3/

### WebP

WebP uses RIFF. Extended WebP can contain `ICCP`, `EXIF` and `XMP ` chunks, plus unknown chunks that readers are expected to ignore. DataBreaker scans these directly and clears corresponding VP8X feature bits when metadata chunks are removed.

Source:
- Google WebP container specification: https://developers.google.com/speed/webp/docs/riff_container

### IPTC / XMP

IPTC Core and Extension are widely stored in XMP; legacy IPTC-IIM commonly appears in Photoshop IRB resources. XMP is RDF/XML and extensible, so unknown namespaces are meaningful to expose even when DataBreaker does not know their semantics. IPTC 2025.1 also defines AI-related properties such as AI Prompt Information, AI System Used and AI System Version Used; these are metadata claims, not cryptographic proof.

Sources:
- IPTC Photo Metadata Standard: https://iptc.org/standards/photo-metadata/iptc-standard/
- IPTC 2025.1: https://www.iptc.org/std/photometadata/specification/IPTC-PhotoMetadata-2025.1.html
- XMP overview/specification links: https://developer.adobe.com/xmp/docs/

### HEIF / HEIC / AVIF

These formats use ISO Base Media File Format structures and can carry Exif/XMP/provenance in item properties and boxes. The built-in handler performs conservative box-level inspection and origin scanning but does not rewrite HEIF/AVIF in 0.1 because safe removal requires correctly rebuilding item locations, properties and references.

Sources:
- HEIF overview / ISO references: https://nokiatech.github.io/heif/
- AV1 Image File Format: https://aomediacodec.github.io/av1-avif/

## PDF

A PDF can expose metadata through the Document Information Dictionary and XMP metadata streams, plus `/ID` document identifiers. Privacy and security review also needs to consider annotations/comments, embedded files, forms, JavaScript, optional-content layers, XML, font/application fingerprints, incremental update chains (`/Prev`), and signatures (`/ByteRange`). Not all of these are “metadata”: annotations and attachments can be user content, while object structure can be required for correct rendering.

DataBreaker therefore separates ordinary metadata from content/structure. Its cleaner removes ordinary metadata conservatively and rewrites through pypdf, then reopens/rescans the result. A PDF rewrite changes byte offsets and invalidates existing cryptographic signatures; DataBreaker never fabricates a replacement signature or claims signature continuity.

Sources:
- PDF Association resources: https://pdfa.org/resource/pdf-specification-index/
- Adobe PDF 1.7 reference: https://opensource.adobe.com/dc-acrobat-sdk-docs/pdfstandards/pdfreference1.7old.pdf
- ISO 32000 family reference: https://www.iso.org/standard/75839.html

## Microsoft Office / OOXML

DOCX/XLSX/PPTX are ZIP packages. Core properties are stored in `docProps/core.xml`; extended application properties commonly live in `docProps/app.xml`; custom properties can live in `docProps/custom.xml`. Privacy-relevant information can also appear in custom XML, relationships (including external targets), comments, tracked revisions, template links, embedded objects/thumbnails and ZIP metadata.

Comments and tracked revisions can contain deleted text and author information, but they are document content/workflow state. DataBreaker reports them and does not silently accept/reject changes or delete comments. Package property cleaning is followed by ZIP CRC validation and a second metadata scan.

Sources:
- ECMA-376 Office Open XML: https://ecma-international.org/publications-and-standards/standards/ecma-376/
- Microsoft Open XML documentation: https://learn.microsoft.com/en-us/office/open-xml/open-xml-sdk

## Archives and containers

ZIP metadata includes archive comments, member timestamps, host/platform attributes and extra fields. Extra fields may carry extended timestamps, NTFS information or Unix ownership. TAR headers can expose UID/GID, account/group names, permissions and timestamps. Filenames themselves can leak usernames, client names and directory layout.

Archive parsing is a security boundary. DataBreaker limits entry count and aggregate size, flags suspicious compression ratios, rejects path traversal during rewrite, and does not expand nested containers recursively in 0.1. This intentionally avoids recursive decompression-bomb chains until a separately budgeted recursive scanner is implemented. The 7z format is detected but deep parsing is intentionally not a required dependency in 0.1.

Sources:
- PKWARE ZIP APPNOTE: https://pkware.cachefly.net/webdocs/casestudies/APPNOTE.TXT
- Python tarfile security context: https://docs.python.org/3/library/tarfile.html

## Audio and video

### MP3 / ID3

ID3 can carry ordinary descriptive tags plus unique/private fields such as UFID and PRIV, comments, original filenames, ownership and encoder information. DataBreaker uses Mutagen for structured reading/removal and reports that cover artwork may be meaningful content.

Source:
- ID3v2.4 frames: https://id3.org/id3v2.4.0-frames

### FLAC / OGG / WAV

FLAC metadata blocks and Vorbis comments can expose encoder/application/comment information; WAV can carry RIFF INFO and ID3-style metadata depending on the writer. Mutagen is used where it has a format-aware, non-transcoding metadata rewrite.

Sources:
- FLAC format: https://xiph.org/flac/format.html
- Vorbis comment: https://xiph.org/vorbis/doc/v-comment.html

### MP4 / MOV / M4A and QuickTime metadata

ISO-BMFF/QuickTime containers may include encoder, creation time, handler/vendor/application information and keyed metadata. Apple documents location metadata using ISO 6709 and QuickTime metadata identifiers including location. Device make/model, software, creation date, artist/author and host-computer keys are high-value privacy indicators when present. DataBreaker scans boxes/strings and uses Mutagen for common MP4/M4A/MOV tag rewrites without transcoding media streams.

Sources:
- Apple QuickTime location metadata: https://developer.apple.com/documentation/quicktime-file-format/location_metadata
- Apple AVFoundation metadata identifiers: https://developer.apple.com/documentation/avfoundation/avmetadataidentifier

### Matroska / WebM

Matroska supports tags and attachments, including cover art, fonts and arbitrary associated files. DataBreaker 0.1 recognizes the container but does not yet ship a full EBML parser/cleaner.

Sources:
- Matroska element specification: https://www.matroska.org/technical/elements.html
- Matroska attachments: https://www.matroska.org/technical/attachments.html

## AI-generated / AI-edited provenance

Detection must distinguish *workflow metadata* from *cryptographic provenance* and from *content watermarks*.

### C2PA / Content Credentials

C2PA manifest stores use JUMBF structures and contain claims, assertions, signatures and hard bindings to the asset. Removal or rewriting can make provenance unavailable or invalid; it is not equivalent to deleting a normal `Author` tag. DataBreaker marks C2PA separately and never creates fake manifests, certificate chains, signing organizations or signatures.

The open-source `c2patool` can produce summary/detailed JSON reports and validate C2PA structures. DataBreaker 0.1 does not invoke it automatically because current tooling can resolve remote manifests; automatic network access would violate the default local-only privacy model. Future integration should be explicit opt-in with network disabled unless the user requests remote verification.

Sources:
- C2PA 2.4 specification: https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html
- c2patool: https://github.com/contentauth/c2patool

### OpenAI / ChatGPT and SynthID

As of 2026, OpenAI documents use of Content Credentials (C2PA) and SynthID for supported generated images, and SynthID for supported generated audio. SynthID is embedded in the media content rather than ordinary removable metadata. Therefore DataBreaker may identify C2PA metadata when present, but it must not claim that “cleaning metadata” removes SynthID or proves non-AI origin.

Sources:
- OpenAI provenance documentation: https://help.openai.com/en/articles/8912793-c2pa-in-chatgpt-images
- OpenAI verification overview: https://openai.com/research/verify/

### Google Gemini / Imagen

Google describes SynthID as an imperceptible watermark embedded directly into generated image/audio/video/text content. It can survive some transformations and is intentionally distinct from file metadata. DataBreaker does not attempt to strip or falsify such content-level watermarking.

Source:
- Google DeepMind SynthID: https://deepmind.google/models/synthid/

### Adobe Firefly / Photoshop generative features

Adobe documents automatic Content Credentials for qualifying Firefly outputs. This is strong evidence when a valid signed manifest is present; an Adobe software string alone is only an application fingerprint and cannot establish that generative AI was used.

Source:
- Adobe Firefly Content Credentials overview: https://helpx.adobe.com/firefly/web/get-started/learn-the-basics/content-credentials-overview.html

### Microsoft Designer / Copilot-adjacent image workflows

Microsoft documents C2PA-based Content Credentials for images created with Designer editing features. DataBreaker can report C2PA/application evidence when present but does not infer Microsoft AI origin from generic Microsoft metadata alone.

Source:
- Microsoft Designer FAQ: https://support.microsoft.com/en-us/designer/frequently-asked-questions-about-microsoft-designer

### AUTOMATIC1111 / Stable Diffusion ecosystems

AUTOMATIC1111 documents that PNG generation parameters are stored in a PNG text chunk. These can expose prompt text, seed, sampler, model/model hash, dimensions and other generation settings. DataBreaker recognizes a `parameters` text field as high-confidence workflow evidence and extracts selected structured values. This is not signed provenance and can be copied, edited or removed.

Source:
- AUTOMATIC1111 feature documentation: https://github.com/AUTOMATIC1111/stable-diffusion-webui/wiki/Features

### ComfyUI

Current ComfyUI source constructs PNG metadata with `prompt` plus extra PNG info; workflow data may therefore be recoverable directly from exported files unless metadata is disabled. Current source also shows metadata handling for animated PNG and WebP. DataBreaker treats `prompt`/`workflow` fields as high-confidence ComfyUI-style workflow evidence while avoiding a claim that every file with a field named `prompt` came from ComfyUI.

Source:
- ComfyUI source: https://github.com/Comfy-Org/ComfyUI/blob/master/comfy_api/latest/_ui.py

### InvokeAI

InvokeAI source contains import logic for historic `sd-metadata` and `invokeai` PNG metadata variants with model, seed, sampler/scheduler, prompt and generation settings. These are strong workflow indicators when the corresponding structured fields are present, not cryptographic authenticity.

Source:
- InvokeAI metadata import code: https://github.com/invoke-ai/InvokeAI/blob/main/invokeai/frontend/install/import_images.py

### Midjourney, Runway, Canva, Picsart, FLUX and other pipelines

Public behavior varies by product/version/export path. DataBreaker does not invent signatures for products where a stable documented on-file identifier is unavailable. It can surface software/generator strings, C2PA manifests, XMP namespaces and workflow data as evidence with an appropriate confidence level. Canva’s current AI terms explicitly refer to provenance/metadata including C2PA, but that does not mean every Canva export contains the same detectable structure.

Source:
- Canva AI Product Terms: https://www.canva.com/policies/ai-product-terms/

## Confidence and false positives

A signed/validated C2PA assertion naming a claim generator is stronger evidence than a plaintext `Software` field. A `Software=Adobe Photoshop` field proves only that Photoshop (or something imitating that string) wrote metadata; it does not prove Firefly use. A `Make=Apple` / `Model=iPhone…` pair strongly indicates camera/device metadata but may survive later editing. Arbitrary metadata is writable, so DataBreaker always presents evidence rather than declaring origin from one weak field.

## Current technical limitations

- DataBreaker exposes every field ExifTool 13.59 reports plus unknown structures found by native parsers, but no software can guarantee semantic discovery/removal of every future proprietary or steganographic signal.
- Content watermarks such as SynthID are outside ordinary metadata cleaning.
- HEIF/AVIF rewriting is disabled in 0.1 to avoid unsafe item-table rewrites.
- Matroska/WebM and 7z are detected but not deeply cleaned in the minimal dependency set.
- PDF rewrites can invalidate signatures and can discard byte-level incremental history; visible/rendered equivalence is not cryptographic equivalence.
- Office comments/revisions/custom XML may be content or functional state, so they are not silently removed.
- ICC/color data can affect rendering; compatibility profiles preserve it.
- The browser full-inventory layer uses ExifTool 13.59 read-only; the local edition uses a native ExifTool executable when available. Findings found only by ExifTool are not automatically claimed as removable by DataBreaker’s built-in writers.
- A file with no recognized AI metadata may still have been generated or edited by AI.
