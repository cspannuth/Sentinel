import { useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import Details, { Badge } from "./Details";
import FullSystemScan from "./FullSystemScan";
import {
  bytes,
  checksComplete,
  filename,
  readable,
  verdictLabels,
  type ScanReport,
} from "./report";

type Choice = "file" | "folder" | "rules" | "hashes";
const message = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export default function App() {
  const [mode, setMode] = useState<"custom" | "system">("custom");
  const [target, setTarget] = useState("");
  const [rules, setRules] = useState("");
  const [hashes, setHashes] = useState("");
  const [busy, setBusy] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [elapsed, setElapsed] = useState(0);
  const [report, setReport] = useState<ScanReport | null>(null);
  const [selected, setSelected] = useState(0);
  const [filter, setFilter] = useState("all");
  const [query, setQuery] = useState("");
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [about, setAbout] = useState(false);
  const operation = useRef(false);
  const desktop = isTauri();

  useEffect(() => {
    if (!scanning) return;
    const start = Date.now();
    const timer = setInterval(
      () => setElapsed(Math.floor((Date.now() - start) / 1000)),
      1000,
    );
    return () => clearInterval(timer);
  }, [scanning]);

  async function perform(action: () => Promise<void>) {
    if (operation.current) return;
    operation.current = true;
    setBusy(true);
    setError("");
    setNotice("");
    try {
      await action();
    } catch (error) {
      setError(message(error));
    } finally {
      operation.current = false;
      setBusy(false);
    }
  }
  function choose(kind: Choice) {
    void perform(async () => {
      const path = await invoke<string | null>("choose_path", { kind });
      if (path !== null)
        (kind === "rules"
          ? setRules
          : kind === "hashes"
            ? setHashes
            : setTarget)(path);
    });
  }
  function clear(kind: "rules" | "hashes") {
    void perform(async () => {
      await invoke("clear_override", { kind });
      (kind === "rules" ? setRules : setHashes)("");
    });
  }
  function scan() {
    void perform(async () => {
      setReport(null);
      setSelected(0);
      setFilter("all");
      setQuery("");
      setElapsed(0);
      setScanning(true);
      try {
        const result = await invoke<ScanReport>("start_scan");
        if (result.schema_version !== 4)
          throw new Error(
            `Unsupported report schema ${result.schema_version}. Update the desktop application.`,
          );
        setReport(result);
      } finally {
        setScanning(false);
      }
    });
  }
  function exportReport() {
    void perform(async () => {
      const path = await invoke<string | null>("export_report");
      if (path) setNotice(`Report exported to ${path}`);
    });
  }
  const rows =
    report?.files
      .map((file, index) => ({ file, index }))
      .filter(({ file }) => {
        const matchesFilter =
          filter === "all" ||
          (filter === "incomplete"
            ? !checksComplete(file)
            : file.verdict === filter);
        return (
          matchesFilter &&
          file.path.display
            .toLocaleLowerCase()
            .includes(query.toLocaleLowerCase())
        );
      }) ?? [];
  const selectedFile = rows.find((row) => row.index === selected)?.file;
  const incomplete =
    report?.files.filter((file) => !checksComplete(file)).length ?? 0;

  return (
    <div className="app-shell">
      <header className="app-header">
        <div className="brand">
          <span className="shield" aria-hidden="true">
            S
          </span>
          <div>
            <strong>Sentinel</strong>
            <span>STATIC FILE ANALYSIS</span>
          </div>
        </div>
        <div className="header-right">
          <span className="offline">
            <i /> Offline engine
          </span>
          <button
            className="quiet"
            onClick={() => setAbout(!about)}
            aria-expanded={about}
          >
            About & sources
          </button>
        </div>
      </header>
      <main>
        <div className="page-title">
          <div>
            <span className="eyebrow">WORKSPACE / SCAN</span>
            <h1>Inspect. Understand.</h1>
            <p>Local file analysis with transparent evidence.</p>
          </div>
          <span className="privacy">
            Read-only scanning · Files stay on this device
          </span>
        </div>
        {!desktop && (
          <div role="alert" className="alert">
            Browser preview only. Open Sentinel with{" "}
            <code>npm run tauri dev</code> to use native file selection and the
            Rust scanner.
          </div>
        )}
        {about && (
          <section className="panel about">
            <h2>Sentinel 0.1.0</h2>
            <p>
              A local static analysis prototype. Files are never executed or
              uploaded. SHA-256 reputation, YARA-X signatures, and PE structure
              provide separate evidence; no result certifies safety.
            </p>
            <p>
              Bundled rules include Sentinel, ESET (BSD-2-Clause), and selected
              Signature-Base rules (DRL-1.1). Hash indicators are from ESET.
              Matching rule authors and licenses appear under Detections.
              Distribution notices are included in the installer’s licenses
              folder.
            </p>
            <p>
              Current limits: sequential scans, 128 MiB PE/YARA input limit, no
              ML model or persistent scan history. Full-system scans support
              live counts and cooperative cancellation. Exact collection
              versions and fingerprints appear below after scanning.
            </p>
          </section>
        )}
        <div className="scan-modes" aria-label="Scan mode">
          <button
            disabled={busy}
            aria-pressed={mode === "custom"}
            onClick={() => {
              setMode("custom");
              setError("");
              setNotice("");
            }}
          >
            Custom scan
          </button>
          <button
            disabled={busy}
            aria-pressed={mode === "system"}
            onClick={() => {
              setMode("system");
              setError("");
              setNotice("");
            }}
          >
            Full-system scan
          </button>
        </div>
        <section className="panel scan-panel" aria-label="Scan controls">
          <div className="section-heading">
            <h2>New scan</h2>
            <span className="eyebrow">01 / SELECT A TARGET</span>
          </div>
          {mode === "custom" && (
            <div className="target-picker">
              <div className="target-path">
                <span className="path-icon" aria-hidden="true">
                  ⌕
                </span>
                <span className={target ? "mono" : "muted"}>
                  {target || "Choose a file or folder to inspect"}
                </span>
              </div>
              <button
                disabled={busy || !desktop}
                onClick={() => choose("file")}
              >
                Choose file
              </button>
              <button
                disabled={busy || !desktop}
                onClick={() => choose("folder")}
              >
                Choose folder
              </button>
              <button
                className="primary"
                disabled={!target || busy || !desktop}
                onClick={scan}
              >
                {scanning ? "Scanning…" : "Start scan →"}
              </button>
            </div>
          )}
          <details className="advanced">
            <summary>
              Detection sources <span>Bundled by default</span>
            </summary>
            <div className="overrides">
              <div>
                <label>YARA rules</label>
                <span className="mono">
                  {rules || "Bundled curated collection"}
                </span>
                <button
                  disabled={busy || !desktop}
                  onClick={() => choose("rules")}
                >
                  Change folder
                </button>
                {rules && (
                  <button disabled={busy} onClick={() => clear("rules")}>
                    Use bundled
                  </button>
                )}
              </div>
              <div>
                <label>Hash database</label>
                <span className="mono">
                  {hashes || "Bundled ESET indicators"}
                </span>
                <button
                  disabled={busy || !desktop}
                  onClick={() => choose("hashes")}
                >
                  Change JSON
                </button>
                {hashes && (
                  <button disabled={busy} onClick={() => clear("hashes")}>
                    Use bundled
                  </button>
                )}
              </div>
              <p className="note">
                Custom sources replace their bundle for the next scan. Invalid
                sources are reported as errors.
              </p>
            </div>
          </details>
        </section>
        {mode === "system" && <FullSystemScan onBusyChange={setBusy} />}
        {error && (
          <div className="alert" role="alert">
            {error}
          </div>
        )}
        {notice && (
          <div className="notice" role="status">
            {notice}
          </div>
        )}
        {mode === "custom" && scanning && (
          <section className="panel scanning" role="status">
            <span className="spinner" />
            <div>
              <h2>Inspecting selected files</h2>
              <p>
                {elapsed}s elapsed · Hashing, PE analysis, and local detection
                checks
              </p>
              <span className="note">
                Results appear when scanning finishes. This prototype does not
                yet support cancellation.
              </span>
            </div>
          </section>
        )}
        {mode === "custom" && !report && !scanning && (
          <section className="empty">
            <div className="empty-symbol" aria-hidden="true">
              ⌕
            </div>
            <h2>Every finding starts with evidence.</h2>
            <p>
              Choose a file or folder to see its hashes, signatures,
              <br /> and executable structure in one place.
            </p>
            <div className="check-types">
              <span>
                01 <b>SHA-256 reputation</b>
              </span>
              <span>
                02 <b>YARA-X signatures</b>
              </span>
              <span>
                03 <b>PE analysis</b>
              </span>
            </div>
            <p className="note">
              Try the harmless fixtures in <code>samples/files</code>.
            </p>
          </section>
        )}
        {mode === "custom" && report && (
          <>
            <div className="results-heading">
              <div>
                <span className="eyebrow">02 / SCAN REPORT</span>
                <h2>Analysis results</h2>
                <p className="mono">{report.target.display}</p>
              </div>
              <button disabled={busy} onClick={exportReport}>
                Export JSON ↗
              </button>
            </div>
            <section className="summary-grid" aria-label="Scan summary">
              <div className="panel">
                <span className="eyebrow">ASSESSMENT</span>
                <Badge verdict={report.verdict} />
                <span className="subtext">Evidence-based engine verdict</span>
              </div>
              <div className="panel">
                <span className="eyebrow">COMPLETENESS</span>
                <strong
                  className={report.status !== "complete" ? "warning-text" : ""}
                >
                  {readable(report.status)}
                </strong>
                <span className="subtext">
                  {incomplete} files with incomplete checks
                </span>
              </div>
              <div className="panel">
                <span className="eyebrow">FILES HASHED</span>
                <strong>
                  {report.summary.hashed}
                  <small> / {report.files.length} entries</small>
                </strong>
                <span className="subtext">
                  {report.summary.skipped} skipped · {report.summary.failed}{" "}
                  failed
                </span>
              </div>
              <div className="panel">
                <span className="eyebrow">DETECTION EVIDENCE</span>
                <strong>
                  {report.summary.signature_matches +
                    report.summary.hash_matches}
                  <small> matches</small>
                </strong>
                <span className="subtext">
                  {report.summary.signature_matches} YARA ·{" "}
                  {report.summary.hash_matches} hash
                </span>
              </div>
            </section>
            <p className="assessment-note">
              {report.status !== "complete"
                ? "Some checks did not complete. Positive findings remain visible; review scan issues and per-file details."
                : report.files.length === 0
                  ? "This scan found no regular files to inspect."
                  : "No detections is limited to the checks and local sources used. It does not establish that a file is safe."}
            </p>
            <div className="results-layout">
              <section className="panel results" aria-label="File results">
                <div className="results-tools">
                  <h2>
                    Files <span>{rows.length}</span>
                  </h2>
                  <input
                    aria-label="Search file paths"
                    placeholder="Search files…"
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                  />
                  <select
                    aria-label="Filter results"
                    value={filter}
                    onChange={(e) => setFilter(e.target.value)}
                  >
                    <option value="all">All results</option>
                    {Object.entries(verdictLabels).map(([value, label]) => (
                      <option key={value} value={value}>
                        {label}
                      </option>
                    ))}
                    <option value="incomplete">Incomplete checks</option>
                  </select>
                </div>
                <div className="file-list">
                  <table>
                    <thead>
                      <tr>
                        <th>File</th>
                        <th>Assessment</th>
                        <th>Checks</th>
                        <th>Size</th>
                      </tr>
                    </thead>
                    <tbody>
                      {rows.map(({ file, index }) => (
                        <tr
                          key={index}
                          className={index === selected ? "selected" : ""}
                        >
                          <td>
                            <button
                              className="file-button"
                              aria-pressed={index === selected}
                              onClick={() => setSelected(index)}
                              title={file.path.display}
                            >
                              <strong>{filename(file.path.display)}</strong>
                              <span className="mono">{file.path.display}</span>
                            </button>
                          </td>
                          <td>
                            <Badge verdict={file.verdict} />
                          </td>
                          <td>
                            <span
                              className={
                                checksComplete(file) ? "muted" : "warning-text"
                              }
                            >
                              {checksComplete(file) ? "Complete" : "Incomplete"}
                            </span>
                          </td>
                          <td className="size">
                            {file.metadata
                              ? bytes(file.metadata.size_bytes)
                              : "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {rows.length === 0 && (
                    <p className="no-rows">
                      {report.files.length
                        ? "No files match this filter."
                        : "No file entries. Review scan issues below."}
                    </p>
                  )}
                </div>
              </section>
              {selectedFile ? (
                <Details key={selected} file={selectedFile} />
              ) : (
                <aside className="panel detail-placeholder">
                  <p>Select a file to inspect its evidence.</p>
                </aside>
              )}
            </div>
            <section className="panel scan-issues">
              <details
                open={
                  report.issues.length > 0 ||
                  report.rules.status === "failed" ||
                  report.hash_database.status === "failed"
                }
              >
                <summary>
                  Scan issues & detection sources{" "}
                  <span>Report schema {report.schema_version}</span>
                </summary>
                <div className="sources">
                  {report.issues.map((issue, i) => (
                    <p className="issue" key={i}>
                      <b>{issue.error.operation}: </b>
                      {issue.error.message}
                      <br />
                      <code>{issue.path.display}</code>
                    </p>
                  ))}
                  {report.rules.status === "failed" ? (
                    <p className="issue">
                      YARA setup: {report.rules.error.message}
                    </p>
                  ) : (
                    <div>
                      <h3>YARA-X · {report.rules.info.rule_count} rules</h3>
                      <p>
                        {report.rules.info.origin} · Engine{" "}
                        {report.rules.info.engine_version}
                      </p>
                      <code className="hash">{report.rules.info.sha256}</code>
                      <details>
                        <summary>Rule source fingerprints</summary>
                        {report.rules.info.sources.map((source, i) => (
                          <p key={i}>
                            <code>{source.path.display}</code>
                            <br />
                            <code className="hash">{source.sha256}</code>
                          </p>
                        ))}
                      </details>
                    </div>
                  )}
                  {report.hash_database.status === "failed" ? (
                    <p className="issue">
                      Hash database setup: {report.hash_database.error.message}
                    </p>
                  ) : (
                    <div>
                      <h3>
                        Hash reputation ·{" "}
                        {report.hash_database.info.entry_count} indicators
                      </h3>
                      <p>{report.hash_database.info.source}</p>
                      <p>
                        {report.hash_database.info.version} ·{" "}
                        {report.hash_database.info.license} · Retrieved{" "}
                        {report.hash_database.info.retrieved_date}
                      </p>
                      <p className="mono">
                        {report.hash_database.info.source_url}
                      </p>
                      <code className="hash">
                        {report.hash_database.info.sha256}
                      </code>
                    </div>
                  )}
                </div>
              </details>
            </section>
          </>
        )}
      </main>
      <footer>
        <span>Sentinel / Static analysis prototype</span>
        <span>Hash reputation · YARA-X · Windows PE</span>
      </footer>
    </div>
  );
}
