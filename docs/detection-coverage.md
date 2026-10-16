# Detection coverage and resource limits

The October 16 expansion ships 20 YARA rules and 507 exact SHA-256 indicators. Eight new ESET signatures add selected TA410 and InvisiMole detection patterns. Hash coverage now includes eight reviewed ESET investigations, including HybridPetya and Ukraine wiper/ransomware artifacts. See [rule provenance](../rules/THIRD_PARTY.md) and [hash provenance](../indicators/README.md) for precise sources, licenses and limitations.

| Resource | Previous | Current |
| --- | --- | --- |
| PE/YARA complete file input | 64 MiB | 128 MiB |
| PE entropy work, counting overlapping sections | 64 MiB | 128 MiB |
| Combined local YARA source bytes | 1 MiB | 8 MiB |
| Local YARA source files | 32 | 128 |
| Compiled YARA rules | 128 | 1,024 |
| Total YARA patterns | 256 | 4,096 |
| Local hash JSON input | 16 MiB | 64 MiB |
| Local hash indicators | 100,000 | 250,000 |

Larger capacities allow more files and curated collections to be analyzed. They do not independently improve detection accuracy. The shipped collections are much smaller than the capacity limits. Hashing remains streaming with no file-size cap; exact reputation lookup works above the PE/YARA cap. PE analysis remains descriptive: headers, architecture, sections, imports and entropy. High entropy or unusual permissions alone are not malware verdicts, and no new PE heuristic verdict is introduced here.

Scanning remains sequential, retaining at most 128 MiB of input shared between PE and YARA (in addition to engine/parser/report memory). More eligible bytes can increase scan time and memory. The five-second PE analysis budget and best-effort YARA timeout, 256 sections, 16,384 imports, 256 DLLs, and 1,024-byte names remain. YARA's 4,096-occurrence saturation guard remains separate from the total pattern limit: saturation makes analysis inconclusive. Source/rule/pattern/database bounds are not hard process-memory or compilation-time limits. Rules are trusted local configuration; YARA optional modules and includes remain unavailable.

Files exceeding a bound are still reported with skipped/incomplete analysis; no prefix-only check becomes a completed clean result. Full-system scans use these same engine settings, cancellation and disk-backed results. Files, hashes and findings stay local; there are no updates or uploads at runtime.

Validation uses inert synthetic containers, 100 new signature branch fixtures and near misses, a valid synthetic PE with an end marker at the 128 MiB boundary, larger local rule collections, and larger hash databases. Source snapshots and all imported hashes are checked for equality/fingerprints. No live malware is downloaded or executed. These checks do not establish a real-world detection rate or replace antivirus protection. The next useful development step is a versioned benign evaluation corpus and a reviewed update process with false-positive regression checks.

On 2026-10-16, the release CLI completed read-only smoke scans of `kernel32.dll`, `user32.dll`, `cmd.exe`, `notepad.exe`, `whoami.exe`, and Windows PowerShell under `C:\Windows\System32`, plus the rebuilt CLI and desktop executable. All eight reported `complete` / `no_detections`, zero YARA/hash matches, and exit code zero. This small local check is not a measured false-positive rate. Root tests (72), desktop backend tests (12), frontend tests (11), formatting, Rust Clippy, frontend production build, CLI release build and Windows installer packaging passed.
