# DataBreaker interface — accessible description

The interface is intentionally dark-first and privacy-oriented. It is designed as a single-page workflow rather than a traditional dashboard with many routes.

## Top bar

A compact header shows the DataBreaker mark and name on the left. On the right are the language toggle (English / Portuguese) and a GitHub link.

## Hero and privacy status

The hero headline reads “See what your files say about you.” / “Veja o que seus arquivos revelam sobre você.” A short paragraph explains that the tool analyzes hidden metadata, origin fingerprints and provenance. Directly below it, a small status strip summarizes the execution model, telemetry status and the automatic rescan after cleaning.

On the public Vercel edition, a green browser-mode notice explains that files are processed inside the browser with WebAssembly and are not uploaded to a DataBreaker backend. If the FastAPI application is deployed to a remote server instead, an amber hosted-mode notice explains that files are temporarily sent to that server and recommends the local/browser-only modes for maximum privacy.

## File drop area

The main entry point is a large rounded drag-and-drop card with a geometric plus icon, supported-format text, a “Choose files” button and the current file-size limit. The card is keyboard focusable and supports Enter/Space activation.

## Scan workspace

After upload, the page opens a scan session area. Multiple files appear as horizontal tabs. During parsing, an animated concentric scanner indicator is shown.

The result area has two columns on desktop:

- a summary card with the number of findings, file name, format, size, truncated SHA-256 and parser-validation status;
- a detailed findings panel with filters for All, Critical, Origin and Unknown.

Each finding displays its normalized name, raw source location, confidence label, value, privacy-impact badge and a plain-language explanation. Critical privacy findings are additionally summarized in a red-tinted alert banner. Unknown structures remain visible instead of being silently discarded.

## Cleaning policy

The cleaning section presents three large cards:

1. **Safe Clean** — common privacy metadata with the lowest compatibility risk.
2. **Deep Clean** — adds uncommon and application-specific metadata.
3. **Clean Everything** — aggressively removes every known nonessential field that the handler can safely rewrite.

Below the cards is a normalization selector with Preserve Compatibility, Minimal, Generic and Custom profiles. Custom mode exposes switches for ICC/color-profile preservation and archive/package timestamp preservation.

A policy preview explains what the chosen mode may affect before the user starts cleaning.

## Verification and downloads

After cleaning, the output is reopened and rescanned. The final panel is titled **Original → Sanitized** and shows counts for removed, retained, normalized and still-sensitive findings plus warnings.

The user can download the sanitized file and JSON or plain-text reports. The application deliberately avoids a “100% clean” claim; it reports what was verified and what may remain.

## Responsive and accessibility behavior

On narrower screens the two-column scan layout collapses into a single column, policy cards stack vertically, and download buttons become a vertical group. Keyboard focus states are visible. Motion-heavy effects are disabled when the operating system requests reduced motion.
