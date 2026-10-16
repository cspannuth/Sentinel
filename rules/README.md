# Sentinel local rules, collection version 3

The bundle contains **20 rules**: three original Sentinel rules (CC0-1.0) and seventeen selected rules copied from public ESET and Signature-Base sources (BSD 2-Clause and DRL 1.1 respectively). They inspect file content only. The selection adds specific malware-family signatures and associated artifacts; coverage remains limited and is not a replacement for an antivirus product. [Third-party provenance, exact rule list, adaptations, licenses, and validation](THIRD_PARTY.md) describe the imported collection. This is not the complete YARA Forge Core package.

The original rules are:

| Rule | Category | Purpose and limitations |
| --- | --- | --- |
| `Sentinel_PowerShell_Download_And_Execute` | suspicious | An ASCII PowerShell command at byte zero combines `DownloadString` with `IEX` or `Invoke-Expression`. This suggests downloading text and evaluating an expression. Legitimate scripts can match; the rule does not prove a runtime data flow. |
| `Sentinel_PowerShell_Encoded_Command` | suspicious | An ASCII PowerShell command at byte zero contains the full `-EncodedCommand` argument. Encoding is also used in legitimate administration. |
| `Sentinel_Benign_Test` | test | The entire file is exactly the 23 ASCII bytes `SENTINEL_TEST_SIGNATURE`. A match verifies the pipeline and never yields suspicious/malicious status by itself. |

The command-at-zero checks deliberately limit scope and avoid matching ordinary documentation or the embedded rule text inside Sentinel's executable. Leading whitespace/BOMs, UTF-16 commands, argument abbreviations, alternate download/execution methods, and scripts without the command prefix are not covered. Renaming a file does not affect these checks.

Defaults are embedded from these `.yar` files at build time, so the executable works independently of its working directory. Rebuild to update the bundled collection. `--rules <directory>` replaces the bundle with the sorted, immediate `.yar`/`.yara` files in that directory; it does not merge or recursively discover sources. Extensions are lowercase. There are no automatic updates or downloads.

The embedded sources are `eset.yar`, `eset_extended.yar`, `powershell.yar`, `self_test.yar`, and `signature_base.yar`, in sorted order. The collection origin is `bundled-v3`. Files under `upstream/` are preserved selected excerpts for comparison tests, not additional runtime rules. Include `THIRD_PARTY.md` and `licenses/` when distributing the binary.

Each rule must contain string metadata `category`, `description`, `version`, `author`, and `license` (1..1024 UTF-8 bytes). Categories are exactly `known_malicious`, `suspicious`, or `test`. Private/global rules, includes, unavailable modules, slow-loop/pattern compiler errors, and all compiler warnings reject the entire collection. No collection is silently reduced to the sources that happened to compile.

Treat custom rules as trusted local code/configuration. A category is a curator's assertion, not something Sentinel verifies against a threat-intelligence service. Use `known_malicious` only for a vetted specific indicator with documented provenance and validation. Hashes in reports fingerprint the supplied rule bytes; they do not authenticate their author. Required descriptions should explain evidence and uncertainty.

Source bytes and file counts are bounded before compilation. Rule/pattern counts are checked after compilation, so these limits are not a hard bound on compiler memory or compilation time. There is no compilation sandbox or hard compilation deadline. Review rule sources before loading them.
