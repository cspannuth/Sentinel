# Third-party signature sources

Sentinel collection `bundled-v3` includes **seventeen selected upstream rules** alongside the three original Sentinel rules. The original nine copies were inspected through public source pages on 2026-10-15; eight additional ESET rules were retrieved at a pinned commit on 2026-10-16 (details below). They are a small selection from two repositories represented in [YARA Forge](https://github.com/YARAHQ/yara-forge), **not an import of the Forge Core package**, and their membership in any particular Core release has not been verified. Individual public rule excerpts form the reference for this selection.

## Source and coverage

| Local source | Upstream source | Selected rules |
| --- | --- | --- |
| `eset.yar` | [ESET gazer.yar](https://github.com/eset/malware-ioc/blob/master/turla/gazer.yar) | `Gazer_certificate` |
| `eset.yar` | [ESET turla-outlook.yar](https://github.com/eset/malware-ioc/blob/master/turla/turla-outlook.yar) | `turla_outlook_log`, `turla_outlook_pdf` |
| `signature_base.yar` | [Signature-Base crime_wannacry.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/crime_wannacry.yar) | `WannaCry_Ransomware_Gen`, `WannCry_m_vbs`, `WannCry_BAT`, `WannaCry_RansomNote` |
| `signature_base.yar` | [Signature-Base apt_apt27_hyperbro.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/apt_apt27_hyperbro.yar) | `HvS_APT27_HyperBro_Stage3` |
| `signature_base.yar` | [Signature-Base apt_alienspy_rat.yar](https://github.com/Neo23x0/signature-base/blob/master/yara/apt_alienspy_rat.yar) | `crime_win_rat_AlienSpy` |

Original rule identifiers, authors, research references, dates, and supplied sample-hash metadata are retained. A metadata sample hash documents an upstream example; it is **not** used for hash reputation matching. For the original nine rules, source URLs name moving upstream branches; no upstream commit identity was verified through those pages. Browser caches can also contain older content. The checked-in, formatting-normalized selected excerpts are the pinned reference for this import, not claims about the latest upstream versions or byte-for-byte full upstream files.

| Reference snapshot | SHA-256 of checked-in UTF-8 bytes |
| --- | --- |
| `upstream/eset-selected.yar` | `0295f6c560c3e9b1e9106b69829f8843b0cf99c1d86025737a15ec0f207027cc` |
| `upstream/signature-base-selected.yar` | `88902c10cf2e0e494cfed285db5236316d5ddd9058fe2ab755c25dd0d0c8e374` |

The runtime report additionally fingerprints every adapted source and the complete supplied collection. Files in `upstream/` are reference excerpts used in differential tests; they are neither embedded nor loaded by `--rules .\rules`, which reads only immediate files. Keep their LF line endings when verifying these snapshot fingerprints.

## Adaptations and verdicts

The runtime copies add `category`, `version = "sentinel-import-1"`, and `source_url` metadata. Missing Signature-Base licenses are filled from that repository's default DRL 1.1 policy; existing license metadata is retained. No optional engine modules are needed. Only module-independent rules are selected, so unused file-level `pe` imports and unrelated rules are not included.

One detection expression receives an equivalent normalization: AlienSpy defines `plugins/Server.classPK` twice, as `$sa_3` and `$sb_3`. YARA-X warns about the duplicate. The adapted rule removes `$sb_3` and changes the second alternative from `all of ($sb_*)` to `(all of ($sb_*) and $sa_3)`. The shared string remains required in both alternatives. Other patterns and conditions are preserved. The engine still rejects all compiler warnings for loaded collections.

| Category | Rules | Interpretation and limits |
| --- | --- | --- |
| `known_malicious` | `WannaCry_Ransomware_Gen` | Requires an MZ header, size below 5000 KiB, and all five upstream strings, including two SMB placeholders. It matches a specific upstream WannaCry signature, not every ransomware family or every WannaCry variant. |
| `known_malicious` | `HvS_APT27_HyperBro_Stage3` | Requires MZ, size below 300 KiB, and four patterns from one of two UTF-16 groups. Targets the exposed stage-3 content, not an arbitrary packed/encrypted outer payload. |
| `known_malicious` | `crime_win_rat_AlienSpy` | Requires PK, size below 800 KiB, and one complete group of Java archive-related strings. Searches the original file's bytes; no ZIP decompression or archive validation is added. |
| `suspicious` | `WannCry_m_vbs`, `WannCry_BAT`, `WannaCry_RansomNote` | Script/note artifacts associated with WannaCry. Notes and script text can be copied into harmless examples. The BAT rule requires only one matching string alongside its prefix/size checks. |
| `suspicious` | `Gazer_certificate` | An MZ file below 2 MiB contains one of two byte indicators. This does not validate a certificate, its location, signature chain, or signer identity. |
| `suspicious` | `turla_outlook_log`, `turla_outlook_pdf` | Recognizes an encrypted-log prefix or five of six document patterns. These are associated artifacts, not proof that the file executes malware. |

`known_malicious_match` means a curator-selected malware-family signature matched. It does not independently establish a file's identity, intent, or safety; synthetic fixtures can intentionally satisfy the same condition. Evidence and scan completeness remain separate.

Not selected: PE-module-dependent rules and private rule dependencies; alternate-license HyperBro rules; broad filename-only or certificate-subject rules; generic cryptographic capability rules. Copying every rule indiscriminately would add compatibility requirements and false positives. The updated resource limits are documented in [detection coverage](../docs/detection-coverage.md). The imported rules provide limited, predominantly historical coverage, not antivirus-level coverage or protection against unseen families.

## License and distribution

- ESET rules retain the 2017, 2018, 2021 and 2022 copyright notices and use [BSD 2-Clause](licenses/BSD-2-Clause-ESET.txt). The full notice is also included in the runtime source. Binary distributions must include the notice, conditions, and disclaimer in accompanying materials.
- Selected Signature-Base rules use [Detection Rule License 1.1](licenses/DRL-1.1.txt). Preserve authorship, source links, and the license when distributing them. Match messages must preserve the supplied author; Sentinel's JSON rule findings already do so. Any future UI must display that attribution too.
- The original Sentinel rules remain CC0-1.0. Their license does not replace the upstream rule licenses.

Ship this document and `licenses/` with distributed binaries containing the embedded third-party rules. No automatic fetching, updates, uploads, or telemetry are introduced.

## Validation and updates

`cargo test --locked --test community_rules` exercises every imported rule using inert synthetic containers, pattern/threshold near misses, exact size boundaries, and header/offset requirements. It also compares adapted-rule matches against the checked-in upstream excerpts, including both HyperBro branches and all three AlienSpy alternatives. Tests cover benign text, empty files, a synthetic PE, an archive-like negative, a PDF-like negative, arbitrary bytes, rule sources, and parity between bundled and explicitly loaded collections. CLI tests check attribution, detection exit codes, and a self-scan of Sentinel.

These tests verify integration and the conditions represented in the fixtures. No live malware was downloaded or executed. They do not establish real-malware recall, numerical false-positive rates, or complete YARA/YARA-X behavioral parity. A small benign Windows-file smoke scan is also useful, but is not a representative corpus benchmark.

On 2026-10-15, manual read-only scans of `C:\Windows\System32\kernel32.dll`, `user32.dll`, `cmd.exe`, `notepad.exe`, `whoami.exe`, and `WindowsPowerShell\v1.0\powershell.exe` each completed with zero signature matches and exit code 0. This records six local smoke checks, not a general false-positive-rate estimate. For example, rerun `cargo run --locked -- scan C:\Windows\System32\kernel32.dll` on your own Windows installation.

For an update, review the exact upstream changes and per-rule licenses; update both the reference excerpts and adaptations; record new snapshot fingerprints and increment the import/bundle version. Re-run formatting, tests, Clippy, a standalone CLI smoke test, and a benign-file scan. Do not silently accept a collection with omitted rules, weakened conditions, or compiler warnings.

## Pinned ESET expansion, 2026-10-16

Commit `705ead5a0a86fefae3c2390f91a339852384f438` supplies eight additional rules. [The import manifest](upstream/eset-extended-manifest.json) records full upstream source fingerprints, URLs, selected identifiers and the selected-excerpt fingerprint. Full source snapshots are preserved as `upstream/eset-full-*.yar` for verification; they are not runtime rules. [Selected reference excerpts](upstream/eset-extended-selected.yar) retain original rule bodies and notices; `eset_extended.yar` adds Sentinel category metadata, normalizes the license name and changes the version to `sentinel-import-2`. Pattern bytes, modifiers, thresholds and conditions are unchanged. Unused `import "pe"` is omitted because none of these selected rules uses that module. No parser-dependent rule is weakened to fit the engine.

| Upstream source | Selected rules | Category |
| --- | --- | --- |
| [TA410](https://github.com/eset/malware-ioc/blob/705ead5a0a86fefae3c2390f91a339852384f438/ta410/ta410.yar) | `apt_Windows_TA410_Tendyron_dropper`, `apt_Windows_TA410_Tendyron_installer`, `apt_Windows_TA410_Tendyron_Downloader`, `apt_Windows_TA410_LookBack_loader`, `apt_Windows_TA410_LookBack_HTTP` | known_malicious |
| TA410 | `apt_Windows_TA410_X4_hash_values`, `apt_Windows_TA410_LookBack_decryption` | suspicious; hash constants or a cipher implementation alone may be reused |
| [InvisiMole](https://github.com/eset/malware-ioc/blob/705ead5a0a86fefae3c2390f91a339852384f438/invisimole/invisimole.yar) | `apt_Windows_InvisiMole_SFX_Dropper` | known_malicious |

`tests/expanded_detection.rs` compares reference/adapted matches on 100 inert branch fixtures, near misses and broken headers, then exercises full engine reporting and attribution. It includes every 4-of-6 dropper, 3-of-5 installer and 4-of-8 constant combination. These fixtures establish integration and threshold behavior, not measured malware recall. Broad single-string rules and rule-text matches in programs embedding these sources were deliberately avoided in this selection. Recheck Sentinel itself and benign executables after any update.
