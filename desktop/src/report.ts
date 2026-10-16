// Mirrors engine report schema 4. Native path units are retained in exported JSON.
export type ReportPath = {
  display: string;
  native?: { encoding: string; units: number[] };
};
export type Verdict =
  | "known_malicious_match"
  | "suspicious"
  | "test_match"
  | "no_detections"
  | "inconclusive"
  | "error";
type Failure = { kind: string; message: string };
type Source<T> =
  { status: "ready"; info: T } | { status: "failed"; error: Failure };
export type RuleMatch = {
  rule_id: string;
  namespace: string;
  category: string;
  description: string;
  version: string;
  author: string;
  license: string;
  locations: { pattern_id: string; offset: number; length: number }[];
};
type HashMatch = {
  sha256: string;
  category: string;
  description: string;
  source: string;
  source_url: string;
  database_version: string;
};
export type PeReport = {
  format: string;
  machine: number;
  architecture: string;
  is_dll: boolean;
  coff_timestamp: number;
  characteristics: number;
  subsystem: number;
  dll_characteristics: number;
  entry_point_rva: number;
  image_base: number;
  size_of_image: number;
  size_of_headers: number;
  section_alignment: number;
  file_alignment: number;
  sections: {
    name: string;
    raw_size: number;
    virtual_size: number;
    virtual_address: number;
    raw_offset: number;
    characteristics: number;
    readable: boolean;
    writable: boolean;
    executable: boolean;
    entropy: number;
  }[];
  imports: {
    dll: string;
    symbols: (
      | { kind: "name"; name: string; hint: number }
      | { kind: "ordinal"; ordinal: number }
    )[];
  }[];
};
type Limited = { status: "skipped"; reason: string; limit: number };
export type FileReport = {
  path: ReportPath;
  metadata: {
    size_bytes: number;
    readonly: boolean;
    modified_unix_ms: number | null;
  } | null;
  verdict: Verdict;
  pe:
    | (
        | { status: "not_pe" }
        | { status: "analyzed"; report: PeReport }
        | Limited
        | { status: "failed"; message: string }
      )
    | null;
  signatures:
    | (
        | { status: "complete"; matches: RuleMatch[] }
        | Limited
        | { status: "failed"; error: Failure }
      )
    | null;
  hash_reputation:
    | (
        | { status: "complete"; matched: HashMatch | null }
        | { status: "failed"; error: Failure }
      )
    | null;
} & (
  | { status: "hashed"; sha256: string }
  | { status: "skipped" | "inconclusive"; reason: string }
  | { status: "failed"; error: Failure & { operation: string } }
);
export type ScanReport = {
  schema_version: number;
  target: ReportPath;
  status: "complete" | "partial" | "failed" | "skipped";
  verdict: Verdict;
  summary: {
    hashed: number;
    skipped: number;
    inconclusive: number;
    failed: number;
    issues: number;
    pe_analyzed: number;
    pe_incomplete: number;
    signature_scanned: number;
    signature_incomplete: number;
    signature_matches: number;
    hash_checked: number;
    hash_matches: number;
    hash_incomplete: number;
  };
  rules: Source<{
    origin: string;
    sha256: string;
    engine_version: string;
    rule_count: number;
    sources: { path: ReportPath; sha256: string }[];
  }>;
  hash_database: Source<{
    origin: string;
    path: ReportPath;
    version: string;
    source: string;
    source_url: string;
    license: string;
    retrieved_date: string;
    sha256: string;
    entry_count: number;
  }>;
  files: FileReport[];
  issues: { path: ReportPath; error: Failure & { operation: string } }[];
};

export const verdictLabels: Record<Verdict, string> = {
  known_malicious_match: "Known malicious match",
  suspicious: "Suspicious",
  test_match: "Test match",
  no_detections: "No detections",
  inconclusive: "Inconclusive",
  error: "Error",
};
export const filename = (path: string) =>
  path.split(/[\\/]/).filter(Boolean).at(-1) ?? path;
export const readable = (value: string) => value.replaceAll("_", " ");
export const bytes = (size: number) =>
  size >= 1024 ** 4
    ? `${(size / 1024 ** 4).toFixed(1)} TiB`
    : size >= 1024 ** 3
      ? `${(size / 1024 ** 3).toFixed(1)} GiB`
      : size < 1024
        ? `${size} B`
        : size < 1024 ** 2
          ? `${(size / 1024).toFixed(1)} KiB`
          : `${(size / 1024 ** 2).toFixed(1)} MiB`;
export function checksComplete(file: FileReport) {
  return (
    file.status === "hashed" &&
    (file.pe?.status === "not_pe" || file.pe?.status === "analyzed") &&
    file.signatures?.status === "complete" &&
    file.hash_reputation?.status === "complete"
  );
}
export function fileIssues(file: FileReport): string[] {
  const issues: string[] = [];
  if (file.status === "failed")
    issues.push(`File ${file.error.operation}: ${file.error.message}`);
  if (file.status === "skipped" || file.status === "inconclusive")
    issues.push(`File ${file.status}: ${readable(file.reason)}`);
  for (const [label, check] of [
    ["PE analysis", file.pe],
    ["YARA", file.signatures],
    ["Hash reputation", file.hash_reputation],
  ] as const) {
    if (!check) issues.push(`${label}: not performed.`);
    else if (check.status === "failed")
      issues.push(
        `${label}: ${"error" in check ? check.error.message : check.message}`,
      );
    else if (check.status === "skipped")
      issues.push(
        `${label}: ${readable(check.reason)} limit (${check.limit}).`,
      );
  }
  return issues;
}
