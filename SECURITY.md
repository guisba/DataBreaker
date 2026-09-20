# Security Policy

DataBreaker parses files that may be malformed or intentionally hostile. Treat the project as security-sensitive software even though it does not execute embedded document code.

## Supported version

Security fixes are applied to the latest tagged release and the `main` branch.

## Reporting a vulnerability

Please do **not** attach confidential sample files to a public GitHub issue. Report the problem with the smallest non-sensitive reproduction you can provide and include:

- affected DataBreaker version/commit;
- file format and approximate size;
- whether the issue occurs in the local, browser-only, or hosted-server mode;
- expected behavior and actual behavior;
- crash/error text with personal paths or identifiers removed;
- whether the issue can cause code execution, path traversal, excessive memory/CPU use, data retention, or incorrect privacy claims.

If a private security-reporting channel is enabled for the repository, prefer it for vulnerabilities that could expose user data or enable code execution. Otherwise open an issue containing no sensitive payload and ask for a private handoff.

## Security boundaries

DataBreaker does not execute macros, scripts, attachments, or media content. Archive rewriting rejects traversal paths. File sizes, archive entry counts, decompressed totals, metadata values, TIFF offsets and parser recursion are bounded. Browser-only mode runs the Python engine in a WebAssembly sandbox in the user's browser. Optional ExifTool integration is local and read-only.

No parser can guarantee safety for every malformed input. Run the local edition as an ordinary user, not as administrator/root, and keep Python/dependencies updated.
