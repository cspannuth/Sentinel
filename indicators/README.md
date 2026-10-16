# Offline SHA-256 reputation

Sentinel embeds `known_hashes.json` and compares it with each consistently read file's SHA-256. No scanned files, digests, or reports are uploaded. A match means the source listed that exact digest; an unknown hash does not establish safety.

## Source and provenance

The bundle contains **507 indicators** from eight reviewed ESET investigations: AsyncRAT (22), Bandook (136), Groundbait/Prikormka (298), Emotet (9), Lumma Stealer (13), Grandoreiro (12), HybridPetya (10), and Ukraine wipers/worm/ransomware (7). ESET's [repository documentation](https://github.com/eset/malware-ioc) identifies `samples.sha256` as malware sample hashes. Investigation context was also reviewed; the Embargo collection was excluded because it contains a legitimate vulnerable driver.

All lists were retrieved on 2026-10-16 at commit `705ead5a0a86fefae3c2390f91a339852384f438`. [The manifest](upstream/manifest.json) records pinned URLs, SHA-256 fingerprints of exact upstream source bytes and counts. Checked-in `upstream/eset-*.sha256` files preserve those lists; accompanying README snapshots preserve research context. The runtime JSON normalizes digests to lowercase and keeps campaign descriptions; its source URL identifies the common pinned ESET repository. Exact SHA-256-to-variant mapping is not inferred from separate SHA-1 tables or row order. The original AsyncRAT collection remains included.

Import version: `eset-selected-2026-10-16-v2`, bundled origin: `bundled-v2`. Retrieval date is not first/last-seen or a freshness guarantee. No live malware was downloaded. The [BSD 2-Clause notice](LICENSE-ESET.txt) must accompany binaries; distribute this documentation and the manifest too. This remains a small historical collection rather than comprehensive malware/ransomware coverage.

Reports fingerprint the exact JSON bytes and include collection version, source URL/name, license, retrieval date, path, origin, and entry count. Fingerprints do not authenticate authorship or verify malware classifications. Research IOC collections may contain legitimate supporting tools; review context rather than blindly classifying every artifact malicious.

## Usage and database format

```powershell
cargo run -- scan "C:\path\to\file.exe"
cargo run -- scan "C:\path\to\folder" --hashes .\indicators\known_hashes.json
cargo run -- scan "C:\path\to\folder" --rules .\rules --hashes .\indicators\known_hashes.json
```

`--hashes` replaces the bundle with a JSON database, **not** a raw `.sha256` list. Both options can appear in either order. Invalid replacements never fall back silently. The library exposes `scan_with_options(path, &ScanOptions { hash_database: Some(path), ..Default::default() })`; existing `scan` and `scan_with_rules` calls keep using bundled hashes.

Each collection has one source and one entry per distinct SHA-256. Descriptions can include documented family/context information. This test-only example matches the harmless ASCII bytes `abc`:

```json
{
  "schema_version": 1,
  "version": "example-v1",
  "source": "Harmless test fixtures",
  "source_url": "https://example.invalid/fixtures",
  "license": "CC0-1.0",
  "retrieved_date": "2026-10-16",
  "entries": [
    {
      "sha256": "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
      "category": "test",
      "description": "Harmless abc fixture, not malware"
    }
  ]
}
```

Metadata/descriptions must be nonblank strings of at most 1024 UTF-8 bytes. Dates/URLs are curator-provided text, not independently verified dates or reachable URLs. Database `schema_version` is 1. Categories are `known_malicious` or `test`. Hashes must be exactly 64 ASCII hexadecimal characters; uppercase is normalized. Duplicate hashes (including case-only duplicates), empty collections, unsupported schemas, unknown fields/categories, and malformed JSON reject the entire collection. No invalid entries are silently skipped.

Database loading rejects known links/reparse points and linked ancestors, checks for changes, and accepts only ordinary regular files. Limits: **64 MiB source input**, **250,000 entries**. Entry counts are checked after bounded JSON deserialization; this is not a hard process-memory cap. The lookup uses a standard-library `HashMap`, with no new dependency. No automatic updates/expiry, fuzzy hashes, MD5/SHA-1 comparison, persistence, or hosted lookup is included.

## Reports and failures

Report schema **4** adds top-level `hash_database` (`ready` with provenance, or `failed` with a typed error), per-file `hash_reputation`, and summary counts:

- `hash_reputation.status: complete`, `matched: null`: checked and unknown to the collection.
- `complete` with a `matched` object: normalized SHA-256, category, description, source URL/name, and database version.
- `failed`: database/check failure. `hash_reputation: null` means no consistent file hash was available, so no conclusion is published.
- `hash_checked`: completed lookups; `hash_matches`: matched files including tests; `hash_incomplete`: failed checks for successfully hashed files. Read failures remain in existing file failure counts.

Known malicious hash evidence produces `known_malicious_match`, separately from YARA/PE findings. Independent analysis errors cannot erase a verified hash match, but keep the scan partial with exit code 1. Invalid databases also make otherwise complete scans partial, including empty directories. Without actionable positive evidence, database failures prevent `no_detections`/`test_match`: the scan verdict is `error`, while consistently hashed files are individually `inconclusive`. Test-only hash matches produce `test_match` only when all checks complete and no stronger evidence exists.

Renaming ordinarily preserves a hash; changing content changes it. Updated/repacked malware can evade exact-match lists. A file containing a published hash as text has its own different digest. Reputation reuses the existing streamed hash after file consistency checks without rereading targets, and is not subject to the 128 MiB PE/YARA input cap.

## Harmless verification and updates

```powershell
cargo test --locked --test reputation
cargo run -- scan .\samples\files\test-marker.txt --hashes .\samples\hash-test.json
```

The demo expects exit code 0, `test_match`, and one hash match alongside the YARA test match. Its digest is absent from production intelligence. Tests check all 507 imported hashes and source fingerprints without obtaining malware files; temporary harmless files exercise matches, renames/changes, invalid databases, independent failures, larger databases, and CLI behavior. Synthetic `known_malicious` test entries never enter the shipped list.

Updating requires source/license review, a new reference snapshot, an updated JSON/version/date, entry parity checks, formatting/tests/Clippy, and a rebuild. Larger feeds and automatic updates remain separate future tasks.
