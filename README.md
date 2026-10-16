# Sentinel

**Offline malware signature detection and static file analysis for Windows.**

Sentinel combines a reusable Rust scanning engine with a command-line interface and a Tauri desktop application. It inspects files without executing them, compares local detection evidence, and reports findings alongside analysis errors and coverage gaps.

The project demonstrates systems programming, defensive security, binary parsing, and desktop application development. The current release is a working prototype; detection accuracy has not been measured against a representative malware corpus.

## Features

- **File and folder scanning:** recursive discovery, streaming SHA-256 hashing, metadata collection, and structured errors.
- **Local detection:** 20 bundled YARA-X rules and 507 ESET-published SHA-256 indicators, with rule authors, licenses, source fingerprints, and matching evidence.
- **Windows executable analysis:** content-based PE identification, architecture, headers, sections, normal imports, and section entropy.
- **Desktop workflow:** file/folder selection, result filtering, detection details, custom detection sources, and JSON export.
- **Full-system scanning:** selected Windows fixed drives, live progress, cooperative cancellation, and paginated results backed by temporary SQLite storage.

Scanning is read-only and offline. Target files, hashes, and reports are never uploaded, and ordinary scans require no administrator privileges.

## Architecture

```text
React + TypeScript --> Tauri 2 --+
                                +--> Rust scanning library --> Scan reports
Rust CLI ----------------------+
```

The Rust library owns scanning logic and verdicts. The CLI and desktop call the same engine; the frontend does not classify files. Full-system results are stored on disk to avoid retaining every file report in memory.

**Stack:** Rust, SHA-256 (`sha2`), Goblin, YARA-X, Serde, Tauri 2, React, TypeScript, Vite, and SQLite (`rusqlite`).

Scan completeness and detection verdicts are independent. A signature match remains visible when another check fails; skipped or failed checks cannot become a successful `no_detections` result. Reports preserve native paths, including non-Unicode filenames.

## Run locally

For Windows development, install:

- [Stable Rust](https://rust-lang.org/tools/install/) with the MSVC toolchain, Visual Studio C++ build tools, and a Windows SDK. See [Rust's Windows prerequisites](https://rust-lang.github.io/rustup/installation/windows-msvc.html).
- For the desktop: [Node.js](https://nodejs.org/en/download) 22.12+ and [Microsoft Edge WebView2](https://developer.microsoft.com/en-us/microsoft-edge/webview2/). See [Tauri's prerequisites](https://v2.tauri.app/start/prerequisites/#windows).

First builds download dependencies; scanning itself requires no network connection.

### CLI

From the repository root:

```powershell
cargo run --locked -- scan .\samples\files
cargo run --locked -- scan "C:\path\to\file.exe"

# Build and run the standalone CLI
cargo build --release --locked
.\target\release\sentinel.exe scan "C:\path\to\folder"
```

JSON reports go to standard output. Optional `--rules <directory>` and `--hashes <file>` replace bundled sources; hash databases use Sentinel's JSON format. Invalid sources are reported without silently falling back to defaults.

| Exit code | Meaning |
| --- | --- |
| `0` | Complete scan with no actionable detections, including harmless test matches |
| `1` | Partial, failed, or skipped scan, including incomplete scans with detections |
| `2` | Invalid arguments |
| `3` | Complete scan with suspicious or known-malicious indicator matches |

### Desktop

```powershell
cd desktop
npm ci
npm run tauri dev
```

Choose a file or folder, start a scan, and select a result to inspect its evidence. **Full-system scan** adds fixed-drive selection, progress, and cancellation. **Export JSON** saves the original report to a new file.

Run `npm run tauri build` from `desktop` to create the Windows executable and NSIS installer. Default outputs are under `desktop/src-tauri/target/release/`, with the installer in `bundle/nsis/`; `CARGO_TARGET_DIR` overrides this location. Installers are currently unsigned.

## Harmless demonstration

Scan `samples/files` using either interface. The six fixtures should produce one `no_detections`, one `test_match`, three `suspicious`, and one `known_malicious_match` result. They contain planted patterns without malicious payloads; the CLI returns exit code `3`.

To demonstrate exact hash comparison with a separate test database:

```powershell
cargo run --locked -- scan .\samples\files\test-marker.txt --hashes .\samples\hash-test.json
```

Expect `test_match`, one hash match, and exit code `0`. Production indicators contain no demonstration hashes. See [sample instructions](samples/README.md) for individual cases and expected findings.

## Validation

From the repository root:

```powershell
rustup component add rustfmt clippy
cargo fmt --check
cargo test --locked
cargo clippy --all-targets --locked -- -D warnings
```

Tests cover known hashes, malformed PE files, traversal errors, links and loops, file changes, YARA matches and near misses, source integrity, resource limits, and cancellation. The expanded signatures include 100 synthetic branch cases compared against upstream rules. Fixtures are never executed; tests verify behavior rather than real-world detection rates.

Frontend checks run from `desktop`:

```powershell
npm run build
npm test
npm run format:check
```

See the [desktop guide](desktop/README.md#build-and-validate) for native backend checks and packaging instructions.

## Current limitations

- Detection is limited to loaded rules and exact hashes. `no_detections` does not certify safety, and PE observations alone do not classify malware.
- PE/YARA input is capped at 128 MiB per file; larger files are still hashed and receive explicit incomplete analysis. Processing remains sequential, with bounded analysis resources and cooperative timeouts/cancellation.
- Full-system scans inspect accessible primary file streams on selected fixed drive letters. Links/reparse points, archive contents, alternate data streams, and unlettered volumes are not traversed.
- Custom scans retain results in memory; full-system scans use temporary storage with a 2 GiB main-database cap. Persistent history, ML inference, real-time blocking, and automatic quarantine are not implemented.

## Documentation

| Topic | Reference |
| --- | --- |
| Reports, verdicts, and PE parsing | [Scan report contract](docs/scan-report.md) |
| Detection coverage and resource limits | [Coverage details](docs/detection-coverage.md) |
| Full-system scan scope, storage, and cancellation | [Full-system scanning](docs/full-system-scanning.md) |
| Desktop development and packaging | [Desktop guide](desktop/README.md) |
| YARA sources, adaptations, and licensing | [Rules](rules/README.md) / [Third-party notices](rules/THIRD_PARTY.md) |
| Hash provenance and database format | [Hash indicators](indicators/README.md) |
| Research toward future ML features | [PE feature compatibility](docs/pe-feature-compatibility.md) |

Third-party rules and indicators retain their own licenses. Distribute the [rule notices](rules/THIRD_PARTY.md), [rule licenses](rules/licenses/), and [ESET hash notice](indicators/LICENSE-ESET.txt) with binaries that embed them.
