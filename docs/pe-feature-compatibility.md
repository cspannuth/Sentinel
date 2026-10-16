# PE feature compatibility investigation

Stage 2 produces descriptive observations, not a training feature vector. No dataset download, training, Python runtime dependency, or model inference is introduced.

Reviewed on 2026-10-15: EMBER2024's [feature-version-3 implementation](https://github.com/FutureComputing4AI/EMBER2024/blob/main/src/thrember/features.py) and [project documentation](https://github.com/FutureComputing4AI/EMBER2024). The reference uses `pefile`; Sentinel uses Goblin and explicit bounds. Similar field names do not establish numerical parity.

| Reference feature family | Available from Sentinel | Alignment still required |
| --- | --- | --- |
| COFF/optional headers | Machine, timestamp, characteristics, subsystem, entry point, image base, sizes/alignment | Categorical encoding, missing values, omitted fields, parser differences |
| Sections | Raw/virtual size, name bytes, characteristics, entropy | Reference name normalization, exact bytes passed to entropy, entry-section selection |
| Imports | DLLs, names/hints, ordinals, counts derivable from lists | Lowercasing, deduplication, ordinal text encoding, hashing, string clipping |
| Other feature families | Not implemented | DOS/Rich details, exports, data-directory features, strings, byte statistics, overlay, signatures, warnings |

Reference section entropy calls `pefile`'s `get_entropy()`; Sentinel explicitly uses validated `SizeOfRawData` bytes including padding. Boundary cases need comparison. Reference name normalization and vector hashing are not reproduced here. These are compatibility risks, not measured discrepancies.

Before Stage 5, pin a reference extractor/version and define a small feature schema with exact field order, numeric types, normalization, and missing/error semantics. Compare both extractors on the same benign PE32/PE32+ files, including empty sections, raw/virtual-size differences, names, duplicate/ordinal imports, and malformed candidates. Bound-limited or failed analyses must not silently become complete zero-valued vectors. Establish tolerances for floating-point entropy and document excluded samples. Select only features whose semantics can be demonstrated to align; a pretrained EMBER2024 model is not compatible with the current report as-is.

This inspection establishes candidate overlap only. The dataset's size, license, labels, split strategy, and feature coverage still require review before any download or training. The complete original feature vector is outside Stage 2.
