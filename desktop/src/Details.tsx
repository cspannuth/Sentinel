import { useState } from "react";
import {
  bytes,
  fileIssues,
  filename,
  readable,
  verdictLabels,
  type FileReport,
} from "./report";

export function Badge({ verdict }: { verdict: FileReport["verdict"] }) {
  return <span className={`badge ${verdict}`}>{verdictLabels[verdict]}</span>;
}

export default function Details({ file }: { file: FileReport }) {
  const [tab, setTab] = useState("Overview");
  const matches =
    file.signatures?.status === "complete" ? file.signatures.matches : [];
  const hash =
    file.hash_reputation?.status === "complete"
      ? file.hash_reputation.matched
      : null;
  const issues = fileIssues(file);
  return (
    <aside className="panel detail" aria-label="File details">
      <div className="detail-heading">
        <span className="eyebrow">FILE INSPECTOR</span>
        <h2>{filename(file.path.display)}</h2>
        <Badge verdict={file.verdict} />
      </div>
      <div className="tabs" role="tablist" aria-label="File detail views">
        {["Overview", "Detections", "PE analysis", "Issues"].map((name) => (
          <button
            key={name}
            role="tab"
            aria-selected={tab === name}
            onClick={() => setTab(name)}
          >
            {name}
            {name === "Issues" && issues.length > 0
              ? ` (${issues.length})`
              : ""}
          </button>
        ))}
      </div>
      <div className="detail-content" role="tabpanel" aria-label={tab}>
        {tab === "Overview" && (
          <>
            <dl>
              <dt>Full path</dt>
              <dd className="mono">{file.path.display}</dd>
              {file.path.native && (
                <>
                  <dt>Path display</dt>
                  <dd>
                    Contains non-Unicode characters. Native units are preserved
                    in JSON export.
                  </dd>
                </>
              )}
              <dt>File read</dt>
              <dd>{readable(file.status)}</dd>
              <dt>Size</dt>
              <dd>
                {file.metadata
                  ? bytes(file.metadata.size_bytes)
                  : "Unavailable"}
              </dd>
              <dt>Modified</dt>
              <dd>
                {file.metadata?.modified_unix_ms != null
                  ? new Date(file.metadata.modified_unix_ms).toLocaleString()
                  : "Unavailable"}
              </dd>
              <dt>SHA-256</dt>
              <dd className="mono hash">
                {file.status === "hashed"
                  ? file.sha256
                  : "Not available: file was not consistently hashed."}
              </dd>
              <dt>PE analysis</dt>
              <dd>{file.pe ? readable(file.pe.status) : "Not performed"}</dd>
              <dt>YARA</dt>
              <dd>
                {file.signatures
                  ? readable(file.signatures.status)
                  : "Not performed"}
              </dd>
              <dt>Hash reputation</dt>
              <dd>
                {file.hash_reputation
                  ? readable(file.hash_reputation.status)
                  : "Not performed"}
              </dd>
            </dl>
            <p className="note">
              A hash identifies file content. No detections means the completed
              checks found no matching indicators; it does not establish safety.
            </p>
          </>
        )}
        {tab === "Detections" && (
          <>
            {hash && (
              <article className="evidence">
                <span className="eyebrow">
                  SHA-256 INDICATOR · {readable(hash.category)}
                </span>
                <h3>{hash.description}</h3>
                <dl>
                  <dt>Source</dt>
                  <dd>{hash.source}</dd>
                  <dt>Database</dt>
                  <dd>{hash.database_version}</dd>
                  <dt>Reference</dt>
                  <dd className="mono">{hash.source_url}</dd>
                  <dt>Digest</dt>
                  <dd className="mono hash">{hash.sha256}</dd>
                </dl>
              </article>
            )}
            {matches.map((match) => (
              <article
                key={`${match.namespace}:${match.rule_id}`}
                className="evidence"
              >
                <span className="eyebrow">
                  YARA · {readable(match.category)}
                </span>
                <h3>{match.rule_id}</h3>
                <p>{match.description}</p>
                <dl>
                  <dt>Author</dt>
                  <dd>{match.author}</dd>
                  <dt>License / version</dt>
                  <dd>
                    {match.license} / {match.version}
                  </dd>
                  <dt>Namespace</dt>
                  <dd>{match.namespace}</dd>
                </dl>
                {match.locations.length > 0 && (
                  <>
                    <h4>Sampled pattern locations</h4>
                    <ul className="locations">
                      {match.locations.map((location, index) => (
                        <li key={index}>
                          <code>{location.pattern_id}</code> · offset{" "}
                          {location.offset} · {location.length} bytes
                        </li>
                      ))}
                    </ul>
                  </>
                )}
              </article>
            ))}
            {!hash && matches.length === 0 && (
              <p className="note">
                No detection evidence was returned. Check the Issues tab for
                incomplete analysis.
              </p>
            )}
            <p className="note">
              Signature and hash matches identify known patterns or indicators.
              Synthetic test files can deliberately match these patterns.
            </p>
          </>
        )}
        {tab === "PE analysis" &&
          (file.pe?.status === "analyzed" ? (
            <>
              <dl>
                <dt>Architecture</dt>
                <dd>
                  {file.pe.report.architecture} · {file.pe.report.format}{" "}
                  {file.pe.report.is_dll && "· DLL"}
                </dd>
                <dt>Entry point RVA</dt>
                <dd className="mono">
                  0x{file.pe.report.entry_point_rva.toString(16)}
                </dd>
                <dt>Image base</dt>
                <dd className="mono">
                  {Number.isSafeInteger(file.pe.report.image_base)
                    ? `0x${file.pe.report.image_base.toString(16)}`
                    : "Exceeds UI integer precision; see original JSON export."}
                </dd>
                <dt>Image size</dt>
                <dd>{bytes(file.pe.report.size_of_image)}</dd>
              </dl>
              <h3>Sections ({file.pe.report.sections.length})</h3>
              <div className="table-scroll">
                <table>
                  <thead>
                    <tr>
                      <th>Name</th>
                      <th>Raw size</th>
                      <th>Flags</th>
                      <th>Entropy</th>
                    </tr>
                  </thead>
                  <tbody>
                    {file.pe.report.sections.map((section, i) => (
                      <tr key={i}>
                        <td className="mono">{section.name}</td>
                        <td>{bytes(section.raw_size)}</td>
                        <td className="mono">
                          {section.readable ? "R" : "–"}
                          {section.writable ? "W" : "–"}
                          {section.executable ? "X" : "–"}
                        </td>
                        <td>{section.entropy.toFixed(3)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <h3>Imports ({file.pe.report.imports.length} libraries)</h3>
              {file.pe.report.imports.map((library, i) => (
                <details key={i} className="import">
                  <summary>
                    {library.dll} <span>{library.symbols.length} symbols</span>
                  </summary>
                  <ul className="locations">
                    {library.symbols.map((symbol, j) => (
                      <li className="mono" key={j}>
                        {symbol.kind === "name"
                          ? symbol.name
                          : `Ordinal ${symbol.ordinal}`}
                      </li>
                    ))}
                  </ul>
                </details>
              ))}
              <details>
                <summary>All PE header fields</summary>
                <pre>
                  {JSON.stringify(
                    {
                      ...file.pe.report,
                      image_base: Number.isSafeInteger(
                        file.pe.report.image_base,
                      )
                        ? file.pe.report.image_base
                        : "Exceeds UI integer precision; see original JSON export.",
                      sections: undefined,
                      imports: undefined,
                    },
                    null,
                    2,
                  )}
                </pre>
              </details>
            </>
          ) : (
            <p className="note">
              {file.pe?.status === "not_pe"
                ? "This file was not identified as a Windows PE executable."
                : "PE analysis is unavailable. See Issues for details."}
            </p>
          ))}
        {tab === "Issues" &&
          (issues.length ? (
            <ul className="issue-list">
              {issues.map((issue, i) => (
                <li key={i}>{issue}</li>
              ))}
            </ul>
          ) : (
            <p className="note">
              All applicable checks completed. No analysis issues were reported
              for this file.
            </p>
          ))}
      </div>
    </aside>
  );
}
