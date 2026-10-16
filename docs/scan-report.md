# Scan reports and PE analysis

This reference describes the schema-4 reports returned by the CLI and custom desktop scans. Streaming full-system sessions use a separate envelope documented in [full-system scanning](full-system-scanning.md).

## Report contract (schema version 4)

The top-level fields are `schema_version`, `target`, `status`, `verdict`, `rules`, `hash_database`, `summary`, `files`, and `issues`. Version 4 adds offline hash reputation and collection provenance to the version 3 YARA/hash/PE report. JSON consumers should check the version.

| Scan status | Meaning |
| --- | --- |
| `complete` | All discovered regular files were hashed, with PE completed/not applicable, signatures and hash reputation completed, and no skipped entries or reported failures. Detection matches do not make a scan incomplete. |
| `partial` | A check or traversal was skipped, failed, inconclusive, or limited; rule setup failed; or a single-file consistency check failed. Successful results remain. |
| `failed` | The target could not be inspected, a single file failed, or root enumeration failed without any entry results. |
| `skipped` | The explicitly requested target is unsupported, linked, or has a linked ancestor. |

The `files` array includes regular files and skipped filesystem entries. Each has a native path representation, observed metadata when available (`size_bytes`, `readonly`, `modified_unix_ms`), and one outcome:

- `hashed`: includes a lowercase hexadecimal `sha256`.
- `skipped`: includes `symlink_or_reparse_point` or `non_regular_file` as the reason.
- `inconclusive`: includes a consistency-check explanation and **no digest**.
- `failed`: includes a structured error and **no digest**.

Unknown/missing metadata and directory enumeration failures appear in `issues`, rather than masquerading as successfully scanned files. Summary counts match the corresponding outcomes and issue count; `summary.failed` counts per-file failures, so check `summary.issues` too. Results are sorted by native path; directory enumeration order is not guaranteed. Error kinds serialize using Rust's debug names, such as `NotFound` and `PermissionDenied`; human-readable messages and OS codes are platform-dependent.

Each entry now also has an independent `pe` field:

| PE status | Meaning |
| --- | --- |
| `not_pe` | Content is not an MZ candidate, or a recognizable NE/LE/LX signature identifies a legacy format. This is normal, not an analysis error. |
| `analyzed` | Includes a `report` containing PE32/PE32+ format, architecture/raw machine code, DLL flag, COFF timestamp, characteristics, subsystem, entry-point RVA, image base, image/header sizes and alignment, sections, and normal imports. |
| `skipped` | Includes a typed `reason` and numeric `limit`; analysis exceeded a documented resource limit. Overall scan is partial. |
| `failed` | Includes a `message` describing malformed/unsupported structures or allocation failure. Overall scan is partial. |
| `null` | Hashing was skipped, failed, or inconsistent; PE findings were withheld. |

`summary.pe_analyzed` counts parsed PE files; `summary.pe_incomplete` counts skipped/failed PE analyses. `hashed` and `failed` still describe hashing independently. A file can therefore be `hashed` with PE `failed`, while its scan is `partial` with exit code `1`.

The per-file `signatures` field is `complete` (with a possibly empty `matches` list), `skipped` (with typed `reason` and `limit`), `failed` (with typed `error`), or `null` when file inspection did not complete consistently. Each rule match contains rule/namespace IDs, category, description, version, author, license, and sampled pattern offsets/lengths; raw matched file bytes are not copied into reports. `summary.signature_scanned` counts completed signature checks, `signature_incomplete` counts skipped/failed ones, and `signature_matches` counts matching rules across files, including test rules.

Top-level `rules.status` is `ready` with collection information or `failed` with a setup error. The collection fingerprint hashes the concatenation of each sorted source's little-endian 64-bit byte length followed by its exact bytes. Per-source hashes and paths are also reported. The fingerprint is reproducible for the supplied ordered content, not proof of trusted provenance.

| Verdict | Meaning |
| --- | --- |
| `known_malicious_match` | A local rule or exact SHA-256 indicator categorized as known malicious matched. Sentinel does not independently validate the curator's claim. |
| `suspicious` | A suspicious-category rule matched; review context and possible false positives. |
| `test_match` | Only harmless test evidence was found and all requested checks completed. |
| `no_detections` | All configured checks completed with no YARA or hash matches. This does not mean safe or cover threats outside the selected collections. |
| `inconclusive` | A requested check was incomplete or an entry was skipped, without actionable positive evidence. |
| `error` | File inspection or scan/rule setup failed. |

Verified positive YARA or hash evidence has priority over incomplete checks, while completeness remains `partial`. If no actionable positive evidence exists, incomplete work prevents `no_detections`/`test_match`; a rule or hash-database setup failure gives the scan an `error` verdict while successfully hashed files are individually `inconclusive`. A file-change failure withholds all findings. No numerical risk score is invented from unrelated signals.

Sections include raw eight-byte names, display names, raw/virtual extents, characteristics, readable/writable/executable flags, and Shannon entropy. Entropy uses exactly the raw on-disk section bytes, including padding, without allocating virtual zero-fill. Empty sections have entropy `0.0`. Imports are grouped by DLL and distinguish names (with hints) from ordinals. Numeric flags and unknown machine codes are retained. COFF timestamps are untrusted header values, not verified compilation dates. PE parsing does not establish whether Windows would load the file or whether it is malicious.

## PE analysis limits

| Resource | Limit |
| --- | --- |
| Candidate input retained in memory | 128 MiB |
| Sections | 256 |
| Normal import descriptors/libraries | 256 |
| Imported symbols across all descriptors | 16,384 |
| Each DLL, symbol, or indirect section name | 1,024 bytes (excluding terminator) |
| Total section bytes examined for entropy, counting overlap | 128 MiB |
| Cooperative PE processing budget | 5,000 milliseconds, starting after hashing |

Identification uses MZ, the declared PE offset, and the PE signature, independent of filename extensions. Malformed MZ candidates are analysis failures; an MZ prefix alone never produces a parsed PE report. Input over the limit is still streamed through SHA-256, but candidate analysis is skipped. Non-MZ files are not subject to the PE input-size limit.

PE candidates use the same bounded buffer retained for signatures during hashing. If rule setup fails, only bounded PE candidates need buffering. After analysis, file metadata/path consistency checks must still pass before observations are published. Goblin parses fixed COFF/optional headers and sections; a bounded import walker uses Scroll's checked little-endian decoders so counts, strings, and time are checked before repeated parsing and allocations. This avoids parsing unrelated resource/export/debug/certificate trees. The input-buffer limit is not a cap on total process memory, which also includes report structures.

The time budget is cooperative, checked between bounded operations and entropy chunks. It does not interrupt a filesystem read or forcibly terminate a parser call. A hard deadline or process isolation is not implemented. When any PE check fails or reaches a limit, partial PE fields are withheld rather than presented as complete.

JSON paths are objects such as `{"display":"C:\\samples\\file.exe"}`. If a path cannot be represented as Unicode, `display` is lossy and an additional `native` object preserves its exact units: `{"encoding":"windows_utf16","units":[...]}` on Windows or `{"encoding":"unix_bytes","units":[...]}` on Unix. Use native units, not display text, to identify those paths. Timestamps are milliseconds since the Unix epoch, or `null` when unavailable, out of range, or before the epoch. Metadata for skipped directories describes the entry, not the total contents beneath it.

See [detection coverage](detection-coverage.md) for YARA and hash database limits, and the [hash database documentation](../indicators/README.md) for reputation fields.
