import { useEffect, useRef, useState } from "react";
import { invoke, isTauri } from "@tauri-apps/api/core";
import Details, { Badge } from "./Details";
import {
  bytes,
  filename,
  readable,
  verdictLabels,
  type FileReport,
  type ScanReport,
} from "./report";

type Drive = { id: string; path: string };
type SessionReport = Omit<ScanReport, "target" | "files" | "issues"> & {
  cancelled: boolean;
  roots: {
    path: { display: string };
    status: ScanReport["status"] | null;
    verdict: FileReport["verdict"];
    summary: ScanReport["summary"];
  }[];
  excluded_working_directories: { path: { display: string } }[];
};
export type SystemView = {
  schema_version: number;
  id: number;
  phase: "running" | "finished" | "cancelled" | "failed";
  targets: string[];
  current_path: string;
  files: number;
  detections: number;
  skipped: number;
  failed: number;
  incomplete: number;
  issues: number;
  bytes_read: number;
  elapsed_ms: number;
  error: string | null;
  report: SessionReport | null;
  sources: Pick<ScanReport, "rules" | "hash_database"> | null;
};
type FileRow = Pick<FileReport, "path" | "metadata" | "status" | "verdict"> & {
  id: number;
  complete: boolean;
};
type IssueRow = ScanReport["issues"][number] & { id: number };
type Page<T> = { page: number; total: number; rows: T[] };
const errorMessage = (error: unknown) =>
  error instanceof Error ? error.message : String(error);

export default function FullSystemScan({
  onBusyChange,
}: {
  onBusyChange: (busy: boolean) => void;
}) {
  const [drives, setDrives] = useState<Drive[]>([]);
  const [selectedDrives, setSelectedDrives] = useState<string[]>([]);
  const [view, setView] = useState<SystemView | null>(null);
  const [starting, setStarting] = useState(false);
  const [loading, setLoading] = useState(true);
  const [cancelling, setCancelling] = useState(false);
  const [exporting, setExporting] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");
  const [query, setQuery] = useState("");
  const [filter, setFilter] = useState("detections");
  const [page, setPage] = useState(0);
  const [results, setResults] = useState<Page<FileRow>>({
    page: 0,
    total: 0,
    rows: [],
  });
  const [issues, setIssues] = useState<Page<IssueRow>>({
    page: 0,
    total: 0,
    rows: [],
  });
  const [issuePage, setIssuePage] = useState(0);
  const [detail, setDetail] = useState<{ id: number; file: FileReport } | null>(
    null,
  );
  const detailRequest = useRef(0);
  const startLock = useRef(false);
  const running = starting || view?.phase === "running";
  const desktop = isTauri();

  useEffect(() => {
    let disposed = false;
    if (!desktop) {
      setLoading(false);
      return;
    }
    onBusyChange(true);
    void Promise.all([
      invoke<Drive[]>("list_scan_drives"),
      invoke<SystemView | null>("system_scan_status", { sessionId: null }),
    ])
      .then(([drives, previous]) => {
        if (disposed) return;
        setDrives(drives);
        setSelectedDrives(drives.map((drive) => drive.id));
        setView(previous);
        onBusyChange(previous?.phase === "running");
      })
      .catch((error) => {
        if (!disposed) {
          setError(errorMessage(error));
          onBusyChange(false);
        }
      })
      .finally(() => {
        if (!disposed) setLoading(false);
      });
    return () => {
      disposed = true;
    };
  }, [desktop, onBusyChange]);

  // Poll serially: a slow IPC call never creates a queue of overlapping requests.
  useEffect(() => {
    if (!view || view.phase !== "running") return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function poll() {
      try {
        const next = await invoke<SystemView>("system_scan_status", {
          sessionId: view!.id,
        });
        if (disposed) return;
        setView(next);
        onBusyChange(next.phase === "running");
        if (next.phase === "running") timer = setTimeout(poll, 500);
        else setCancelling(false);
      } catch (error) {
        if (!disposed) {
          setError(errorMessage(error));
          timer = setTimeout(poll, 1500);
        }
      }
    }
    void poll();
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [view?.id, view?.phase, onBusyChange]);

  // Filtering/paging happens in Rust/SQLite. Only 100 compact rows cross IPC.
  useEffect(() => {
    if (!view) return;
    let disposed = false;
    let timer: ReturnType<typeof setTimeout>;
    async function refresh() {
      try {
        const [files, scanIssues] = await Promise.all([
          invoke<Page<FileRow>>("system_scan_page", {
            sessionId: view!.id,
            query,
            filter,
            page,
            issues: false,
          }),
          invoke<Page<IssueRow>>("system_scan_page", {
            sessionId: view!.id,
            query: "",
            filter: "all",
            page: issuePage,
            issues: true,
          }),
        ]);
        if (disposed) return;
        setResults(files);
        setIssues(scanIssues);
      } catch (error) {
        if (!disposed) setError(errorMessage(error));
      }
      if (!disposed && view!.phase === "running")
        timer = setTimeout(refresh, 2000);
    }
    timer = setTimeout(refresh, 250);
    return () => {
      disposed = true;
      clearTimeout(timer);
    };
  }, [view?.id, view?.phase, query, filter, page, issuePage]);

  async function start() {
    if (startLock.current) return;
    startLock.current = true;
    setStarting(true);
    setView(null);
    onBusyChange(true);
    setError("");
    setNotice("");
    setCancelling(false);
    setDetail(null);
    detailRequest.current++;
    setPage(0);
    setIssuePage(0);
    setResults({ page: 0, total: 0, rows: [] });
    setIssues({ page: 0, total: 0, rows: [] });
    try {
      const next = await invoke<SystemView>("start_system_scan", {
        driveIds: selectedDrives,
      });
      setView(next);
      onBusyChange(next.phase === "running");
    } catch (error) {
      setError(errorMessage(error));
      onBusyChange(false);
    } finally {
      setStarting(false);
      startLock.current = false;
    }
  }
  async function cancel() {
    if (!view || cancelling) return;
    setCancelling(true);
    try {
      await invoke("cancel_system_scan", { sessionId: view.id });
    } catch (error) {
      setError(errorMessage(error));
      setCancelling(false);
    }
  }
  async function inspect(id: number) {
    if (!view) return;
    const request = ++detailRequest.current;
    setDetail(null);
    try {
      const file = await invoke<FileReport>("system_scan_detail", {
        sessionId: view.id,
        id,
      });
      if (request === detailRequest.current) setDetail({ id, file });
    } catch (error) {
      if (request === detailRequest.current) setError(errorMessage(error));
    }
  }
  async function exportReport() {
    if (!view || exporting) return;
    setExporting(true);
    onBusyChange(true);
    setError("");
    try {
      const path = await invoke<string | null>("export_system_scan", {
        sessionId: view.id,
      });
      if (path) setNotice(`Report exported to ${path}`);
    } catch (error) {
      setError(errorMessage(error));
    } finally {
      setExporting(false);
      onBusyChange(false);
    }
  }
  const sources = view?.sources ?? view?.report;

  return (
    <section aria-label="Full-system scan">
      <div className="panel system-controls">
        <div>
          <h2>Full-system scan</h2>
          <p>
            Inspect accessible files on the selected local fixed drives. Locked
            files and analysis limits remain visible as coverage gaps.
          </p>
        </div>
        <fieldset disabled={running || exporting || loading}>
          <legend>Drives to scan</legend>
          <div className="drive-options">
            {drives.map((drive) => (
              <label key={drive.id}>
                <input
                  type="checkbox"
                  checked={selectedDrives.includes(drive.id)}
                  onChange={(event) =>
                    setSelectedDrives((current) =>
                      event.target.checked
                        ? [...current, drive.id]
                        : current.filter((id) => id !== drive.id),
                    )
                  }
                />
                {drive.path}
              </label>
            ))}
            {!drives.length && (
              <span className="note">
                {loading
                  ? "Discovering local drives…"
                  : "No local fixed drives are available."}
              </span>
            )}
          </div>
        </fieldset>
        <button
          className="primary"
          disabled={
            !desktop ||
            loading ||
            running ||
            exporting ||
            selectedDrives.length === 0
          }
          onClick={() => void start()}
        >
          {starting ? "Preparing scan…" : "Start full-system scan"}
        </button>
        <p className="note">
          Sequential, read-only scanning. No percentage is shown because the
          total file count is unknown during discovery. PE/YARA/hash limits are
          unchanged.
        </p>
      </div>
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
      {view && (
        <>
          <div className="results-heading">
            <div>
              <span className="eyebrow">FULL-SYSTEM / SESSION {view.id}</span>
              <h2>
                {view.phase === "running"
                  ? "Scanning your selected drives"
                  : view.phase === "cancelled"
                    ? "Scan cancelled"
                    : view.phase === "failed"
                      ? "Scan interrupted by an error"
                      : "Scan finished"}
              </h2>
              <p className="mono">{view.targets.join(" · ")}</p>
            </div>
            {view.phase === "running" ? (
              <button disabled={cancelling} onClick={() => void cancel()}>
                {cancelling ? "Stopping…" : "Cancel scan"}
              </button>
            ) : (
              <button disabled={exporting} onClick={() => void exportReport()}>
                {exporting ? "Exporting…" : "Export system JSON"}
              </button>
            )}
          </div>
          <div className="system-activity" role="status">
            {view.phase === "running" && <span className="spinner" />}
            <div>
              <p>
                {Math.floor(view.elapsed_ms / 1000)}s elapsed ·{" "}
                {bytes(view.bytes_read)} read · {view.skipped} skipped ·{" "}
                {view.failed} failed · {view.issues} scan issues
              </p>
              {view.phase === "running" && (
                <code>
                  {view.current_path || "Preparing local detection sources…"}
                </code>
              )}
            </div>
          </div>
          <div className="summary-grid system-summary">
            <div className="panel">
              <span className="eyebrow">FILE ENTRIES PROCESSED</span>
              <strong>{view.files.toLocaleString()}</strong>
            </div>
            <div className="panel">
              <span className="eyebrow">FILES WITH DETECTIONS</span>
              <strong>{view.detections.toLocaleString()}</strong>
              <span className="subtext">
                Suspicious or known malicious indicators
              </span>
            </div>
            <div className="panel">
              <span className="eyebrow">INCOMPLETE FILE CHECKS</span>
              <strong className={view.incomplete ? "warning-text" : ""}>
                {view.incomplete.toLocaleString()}
              </strong>
            </div>
            <div className="panel">
              <span className="eyebrow">ASSESSMENT / COVERAGE</span>
              {view.report ? (
                <>
                  <Badge verdict={view.report.verdict} />
                  <span className="subtext">
                    Coverage: {view.report.status}
                  </span>
                </>
              ) : (
                <span className="note">
                  {view.phase === "failed"
                    ? "Incomplete: worker/storage error"
                    : "Assessment pending"}
                </span>
              )}
            </div>
          </div>
          {view.error && (
            <div className="alert" role="alert">
              {view.error} Retained results describe only the work completed
              before the error.
            </div>
          )}
          <p className="assessment-note">
            {view.phase === "cancelled"
              ? "Cancellation preserved collected results. Unvisited files and unfinished checks were not assessed."
              : "No detections does not establish safety. Protected paths, links, and oversized analysis inputs may leave coverage gaps."}
            {cancelling &&
              " Waiting for the current OS operation or analysis call to return."}
          </p>
          {sources && (
            <div className="system-source-status">
              {sources.rules.status === "failed" ? (
                <div className="alert" role="alert">
                  YARA source error: {sources.rules.error.message}
                </div>
              ) : (
                <span>
                  YARA-X · {sources.rules.info.rule_count} rules ·{" "}
                  {sources.rules.info.origin}
                </span>
              )}
              {sources.hash_database.status === "failed" ? (
                <div className="alert" role="alert">
                  Hash database error: {sources.hash_database.error.message}
                </div>
              ) : (
                <span>
                  Hash reputation · {sources.hash_database.info.entry_count}{" "}
                  indicators · {sources.hash_database.info.version}
                </span>
              )}
              <details>
                <summary>Detection source versions & fingerprints</summary>
                <pre>{JSON.stringify(sources.rules, null, 2)}</pre>
                <pre>{JSON.stringify(sources.hash_database, null, 2)}</pre>
              </details>
            </div>
          )}
          <div className="results-layout">
            <section className="panel results" aria-label="System file results">
              <div className="results-tools">
                <h2>
                  Files <span>{results.total.toLocaleString()}</span>
                </h2>
                <input
                  aria-label="Search system file paths"
                  placeholder="Search files…"
                  value={query}
                  onChange={(e) => {
                    setQuery(e.target.value);
                    setPage(0);
                    setDetail(null);
                    detailRequest.current++;
                  }}
                />
                <select
                  aria-label="Filter system results"
                  value={filter}
                  onChange={(e) => {
                    setFilter(e.target.value);
                    setPage(0);
                    setDetail(null);
                    detailRequest.current++;
                  }}
                >
                  <option value="detections">Detections only</option>
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
                    {results.rows.map((row) => (
                      <tr
                        key={row.id}
                        className={detail?.id === row.id ? "selected" : ""}
                      >
                        <td>
                          <button
                            className="file-button"
                            aria-pressed={detail?.id === row.id}
                            title={row.path.display}
                            onClick={() => void inspect(row.id)}
                          >
                            <strong>{filename(row.path.display)}</strong>
                            <span className="mono">{row.path.display}</span>
                          </button>
                        </td>
                        <td>
                          <Badge verdict={row.verdict} />
                        </td>
                        <td className={row.complete ? "muted" : "warning-text"}>
                          {row.complete ? "Complete" : "Incomplete"}
                        </td>
                        <td className="size">
                          {row.metadata ? bytes(row.metadata.size_bytes) : "—"}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {results.rows.length === 0 && (
                  <p className="no-rows">
                    {filter === "detections" && view.phase === "running"
                      ? "No detections recorded so far. Choose All results to inspect other files."
                      : "No files match this filter."}
                  </p>
                )}
              </div>
              <div className="pagination">
                <button disabled={page === 0} onClick={() => setPage(page - 1)}>
                  Previous files
                </button>
                <span>Page {page + 1} · Up to 100 files per page</span>
                <button
                  disabled={(page + 1) * 100 >= results.total}
                  onClick={() => setPage(page + 1)}
                >
                  Next files
                </button>
              </div>
            </section>
            {detail ? (
              <Details key={`${view.id}:${detail.id}`} file={detail.file} />
            ) : (
              <aside className="panel detail-placeholder">
                <p>Select a file to inspect its evidence.</p>
              </aside>
            )}
          </div>
          <section className="panel scan-issues">
            <h2>
              Scan issues <span className="muted">({issues.total})</span>
            </h2>
            {issues.rows.length ? (
              issues.rows.map((issue) => (
                <p className="issue" key={issue.id}>
                  <b>{readable(issue.error.operation)}: </b>
                  {issue.error.message}
                  <br />
                  <code>{issue.path.display}</code>
                </p>
              ))
            ) : (
              <p className="note">No traversal or path issues recorded.</p>
            )}
            <div className="pagination">
              <button
                disabled={issuePage === 0}
                onClick={() => setIssuePage(issuePage - 1)}
              >
                Previous issues
              </button>
              <span>Page {issuePage + 1}</span>
              <button
                disabled={(issuePage + 1) * 100 >= issues.total}
                onClick={() => setIssuePage(issuePage + 1)}
              >
                Next issues
              </button>
            </div>
          </section>
          {view.report && (
            <section className="panel scan-issues">
              <h2>Coverage by drive</h2>
              {view.report.roots.map((root, i) => (
                <p key={i}>
                  <code>{root.path.display}</code> ·{" "}
                  {root.status ?? "Not visited"} · {root.summary.hashed} hashed
                  · {root.summary.issues} issues
                </p>
              ))}
              {view.report.excluded_working_directories.length > 0 && (
                <details>
                  <summary>Excluded scanner working directories</summary>
                  {view.report.excluded_working_directories.map(
                    (directory, i) => (
                      <p className="mono" key={i}>
                        {directory.path.display}
                      </p>
                    ),
                  )}
                  <p className="note">
                    Sentinel excludes its own temporary result storage to avoid
                    scanning files it is actively writing.
                  </p>
                </details>
              )}
            </section>
          )}
        </>
      )}
    </section>
  );
}
