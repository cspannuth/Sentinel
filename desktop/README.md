# Sentinel desktop prototype

A Windows-focused Tauri 2 application over the existing Rust engine. React and TypeScript render custom-scan reports and streaming full-system sessions; the frontend does not classify files. No REST server, cloud service, Python runtime, or authentication is needed.

## Run

Install stable Rust/MSVC, the Windows SDK, Node.js 22.12+ (prefer a supported LTS), and WebView2. See the root [setup instructions](../README.md).

From this directory:

```powershell
npm ci
npm run tauri dev
```

Use **Choose folder** to select `../samples/files`, then **Start scan**. Six harmless text fixtures should produce one no-detections result, one test match, three suspicious results, and one known-malicious-pattern match. The latter is a deliberately matching synthetic file, not live malware. Detection details display rule authors, descriptions, licenses, and sampled locations.

To exercise hash detection, select `../samples/hash-test.json` under **Detection sources → Hash database**, then scan `../samples/files/test-marker.txt`. Expect a test hash match. Use **Use bundled** to restore the normal indicator collection.

`npm run dev` alone opens a browser preview with native actions disabled. Use the Tauri command to scan real files.

## Build and validate

```powershell
npm run build
npm test
npm run format:check
cargo fmt --manifest-path src-tauri/Cargo.toml --check
cargo test --manifest-path src-tauri/Cargo.toml --locked
cargo clippy --manifest-path src-tauri/Cargo.toml --all-targets --locked -- -D warnings
npm run tauri build
```

Run the root Rust checks from the repository root as well. Both Cargo and npm lockfiles are committed project inputs. First builds download dependencies and may take several minutes. The Tauri bundler may download NSIS packaging tools on its first run.

The executable is normally `src-tauri/target/release/sentinel-desktop.exe`; the per-user installer is under `src-tauri/target/release/bundle/nsis/`. To reuse the root build cache, set `$env:CARGO_TARGET_DIR = (Resolve-Path ../target).Path` before running Tauri/Cargo; artifacts then appear in the root `target` directory. Installers are unsigned and not a production release. WebView2 is required at runtime; installer bootstrap may retrieve it if absent, while scanning itself remains offline.

## Small desktop boundary

- `src/App.tsx`: selection, background-scan state, summary, filtering, source information, and export action.
- `src/Details.tsx`: per-file overview, signature/hash evidence, PE observations, and incomplete checks.
- `src/FullSystemScan.tsx`: drive selection, live status/cancellation, paginated files/issues, and system export.
- `src/report.ts`: TypeScript report contract and display helpers.
- `src/styles.css`: local styling with system fonts, focus indicators, text verdicts, and reduced-motion support.
- `src-tauri/src/backend.rs`: native dialogs, native selected paths, a single-operation guard, worker dispatch, retained engine report, and controlled JSON export.
- `src-tauri/src/system_scan.rs`: drive discovery, validated drive IDs, background session lifecycle, and focused desktop commands.
- `src-tauri/src/result_store.rs`: temporary SQLite storage, filtering/paging, and streaming export.
- `src-tauri/tauri.conf.json`: window, CSP, Windows installer, and required third-party notices.

The Tauri backend depends on the root package through `path = "../.."`. Selected paths remain native Rust `PathBuf`s; display strings are never used to reconstruct paths. Custom scans delegate to `sentinel::scan_with_options`; full-system sessions use `sentinel::scan_streaming`. The engine's verdict and completeness remain independent, including positive findings in partial scans. A failed worker/IPC call displays an error without inventing a report. Custom source errors remain structured engine results.

The frontend has no filesystem, shell, opener, or networking plugin permissions. Native dialogs and scanning use focused Rust commands. Export receives neither a destination path nor report content from JavaScript: Rust asks for a native destination and writes the retained report with exclusive file creation. Existing files, linked ancestors/reparse points, Windows device names, and alternate data streams are rejected. These ancestor checks are best effort, not atomic protection against concurrent filesystem changes. Reports can contain sensitive paths; choose an appropriate export location.

## Prototype limits and tests

The engine remains sequential. Custom scans retain their original in-memory report contract and indeterminate activity. **Full-system scan** adds drive selection, live status, cooperative cancellation, disk-backed results, paginated files/issues, and streaming export. Full-system status/results can be restored within the same running app; there is no persistent history or session recovery after restart. One scan or export operation can run at a time. Closing the window does not promise to finish an active scan. See [full-system scanning](../docs/full-system-scanning.md) for its scope, implementation, storage limits, export schema, and tests.

The desktop uses the engine's [current detection collections and resource limits](../docs/detection-coverage.md), including the 128 MiB PE/YARA input cap. Incomplete-state semantics are preserved. PE image bases beyond JavaScript's exact integer range are flagged in the UI; the original Rust JSON export preserves them exactly. Native non-Unicode paths likewise retain original units in exported reports.

Backend tests compare desktop results against the engine, verify UTF-8 report export and overwrite refusal, check single-operation guards, and cover invalid targets/sources and empty folders. Frontend tests use a schema-4 report generated by the real CLI against the harmless `samples/files` collection. They exercise selection/cancellation, result filtering, author attribution, partial reports, worker errors, empty folders, source overrides, and export dispatch. The fixture in `src/__fixtures__/samples.json` is test-only and is not imported by the application.

Before saving a generated fixture, replace its target/file paths with generic `C:\samples\files` paths and set local modification timestamps to `null`. Preserve detection evidence and public source attribution. Inspect all remaining fields, including native path units and diagnostics, for local identifying data. Do not check in raw scan reports or screenshots of personal directories. The frontend suite checks these fixture privacy requirements; runtime reports retain accurate paths for the user.

Suggested manual checks:

1. Scan the harmless sample folder; inspect both a suspicious pattern and the test marker.
2. Scan the built Sentinel CLI to inspect a PE file, then expand its sections/imports.
3. Select an empty rules folder: available hashes/PE results remain, and source failures are shown.
4. Scan a folder containing an inaccessible or malformed file: inspect partial status and file issues.
5. Export a report with a new filename, compare it with the CLI, and verify that export refuses an existing filename.
