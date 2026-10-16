# Full-system scanning

In the desktop app, select **Full-system scan**, review the detected fixed local drive letters, and choose which to inspect. All discovered fixed drives are initially selected. The shared **Detection sources** controls replace bundled YARA rules or hash indicators for the next scan. Sources are loaded once for the whole session; invalid sources are displayed immediately while available checks continue.

The scanner shows the current path, actual bytes read, processed entries, suspicious/known-malicious file counts, skipped/failed/incomplete entries, scan issues, and elapsed time. There is no percentage or completion estimate because discovery does not know the total workload. **Cancel scan** cooperatively stops work and preserves collected results in an explicitly partial report, distinguishing roots not yet visited. Cancellation checks occur between directory entries, read buffers, and analysis calls. A blocked OS operation, trusted-rule compilation, or active PE/YARA call must return first.

The results table initially shows suspicious/known-malicious findings. Select **All results** for ordinary and test matches. Searches are literal text, with SQLite's ASCII case-insensitive matching. Files and issues are loaded in pages of at most 100 rows; full file reports are fetched by result ID. File rows are ordered by detection category and insertion order. Rule authors/licenses remain visible in detection details.

## Scope and coverage

Windows drive discovery uses `GetLogicalDrives` and `GetDriveTypeW`; only letters Windows identifies as fixed drives are offered. The backend validates selected IDs against current discovery before starting. It does not accept arbitrary scan paths from JavaScript for a system scan. Drive discovery itself does not inspect the drive contents.

Only accessible regular-file primary streams are inspected. The scan is read-only, sequential, static, and offline. It does not elevate privileges, execute files, quarantine data, or upload results. Permissions, locked files, and files that change during scanning remain explicit coverage gaps. Reparse points, junctions, mounted-folder volumes, and cloud placeholders are skipped. Network/removable-type drives, unlettered volumes, archive contents, alternate streams, memory, and boot sectors are not separately enumerated. Windows may classify some external media as fixed; the UI shows the exact selected drive letters.

The scanner explicitly excludes its own temporary result directory to avoid inspecting files it is actively writing. These exclusions appear in engine session metadata and encountered entries are marked skipped. Streaming discovery retains at most 256 open directory levels; exceeding this bound produces an explicit traversal issue. Full-system scanning uses the engine's [current detection collections and resource limits](detection-coverage.md), including the 128 MiB PE/YARA input cap. Selecting more drives increases the files inspected; detection coverage depends on the loaded signatures and indicators.

## Implementation

- `src/session.rs` provides `scan_streaming`, a cooperative `ScanControl`, and a `ScanSink` boundary. It loads sources once, streams outcomes immediately, maintains summaries/evidence, and returns metadata with per-root status. Duplicate/overlapping roots and parent-directory components are rejected.
- `src/scanner.rs` shares the existing file inspection pipeline with the streaming API and checks cancellation between hashing buffers/analysis calls. The original CLI/custom-scan API and schema 4 remain intact.
- `desktop/src-tauri/src/system_scan.rs` discovers drives, validates selection, dispatches background work, and exposes status/cancellation, paged results, file details, and export. Session IDs reject stale requests. Worker/storage failures never produce a fabricated completed engine report.
- `desktop/src-tauri/src/result_store.rs` stores each file/issue in temporary SQLite. SQL predicates are fixed and values are bound parameters. File details and exports retain original Rust JSON, including native non-Unicode path units and exact integer values.
- `desktop/src/FullSystemScan.tsx` renders progress and pages; it does not classify files or reconstruct native paths.

`rusqlite` with bundled SQLite provides storage, indexed filtering, and paging without a server or runtime installation. `tempfile` owns session directory lifetimes. `windows-sys` provides direct Windows drive APIs. These dependencies are confined to the desktop backend; the Rust engine remains desktop-independent.

## Storage and export

The SQLite page cache is configured to 4 MiB and the main database is capped at 2 GiB. Journal files and SQLite operations require additional disk space; this is not a hard total-process-memory or total-disk cap. Results are committed in small batches. Storage errors/exhaustion stop the scan and remain visible; available records are not represented as complete filesystem coverage. Per-file parsing/serialization still uses operation-sized memory, but the complete scan's file list is not retained in RAM.

Temporary storage normally disappears when the session is replaced or the app shuts down cleanly. Crashes or forced termination can leave temporary files. The database contains paths, hashes, and findings and should be treated as sensitive local data. There is no persistent scan-history feature or restart recovery.

**Export system JSON** streams the stored records to a new UTF-8 JSON file, using the same protected destination checks as custom export. The outer fields are:

```text
session   # Desktop session metadata; schema_version 1
files     # Streamed original FileReport records
issues    # Streamed original ScanIssue records
```

`session.report` contains streaming-engine schema 1: aggregate verdict/completeness, per-root summaries, cancellation, source versions/fingerprints, and working-directory exclusions. A worker/storage failure sets `session.phase` to `failed`, records an error, and leaves `session.report` absent. Retained records can still be exported if storage remains readable. Export refuses overwriting existing files, linked ancestors/reparse points, Windows devices, and alternate streams. Ancestor checks remain best effort against concurrent filesystem changes.

## Verification

Root tests cover parity with regular scans, combined roots, cancellation before/during work, interrupted hashing, empty/missing roots, overlapping scopes, storage failures, working-directory exclusions, junctions/locked files, and a harmless synthetic directory tree. Desktop tests cover Windows drive enumeration/selection validation, stale sessions, source/worker failures, cancellation, SQLite paging/filtering/issue storage, and exact integer export. Frontend tests cover selected drive IDs, live status, cancellation/partial evidence, paging, detail IDs, source errors, export dispatch, and failed-start handling.

Tests use harmless temporary fixtures and do not run a full scan of the developer's disks. Existing CLI and signature/PE/hash regression tests are retained. See the desktop README for build/check commands. Installers remain unsigned prototypes.
