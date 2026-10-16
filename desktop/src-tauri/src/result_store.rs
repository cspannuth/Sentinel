//! Temporary disk-backed results. No scan history is retained across sessions.
use rusqlite::{Connection, params};
use sentinel::{FileReport, ScanIssue, Verdict};
use serde::Serialize;
use serde_json::Value;
use std::{
    io::{self, Write},
    path::Path,
};

pub struct ResultStore {
    connection: Connection,
    pending: usize,
}

#[derive(Serialize)]
pub struct ResultPage {
    pub total: i64,
    pub page: u32,
    pub rows: Vec<Value>,
}

fn storage_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::other(format!("Result storage: {error}"))
}

impl ResultStore {
    pub fn create(path: &Path) -> io::Result<Self> {
        let connection = Connection::open(path).map_err(storage_error)?;
        connection.execute_batch("PRAGMA page_size=4096; PRAGMA max_page_count=524288;
            PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;
            PRAGMA cache_size=-4096; PRAGMA mmap_size=0; PRAGMA temp_store=FILE;
            PRAGMA wal_autocheckpoint=256;
            CREATE TABLE files(id INTEGER PRIMARY KEY, path TEXT NOT NULL, verdict TEXT NOT NULL,
                complete INTEGER NOT NULL, rank INTEGER NOT NULL, row_json TEXT NOT NULL, json TEXT NOT NULL);
            CREATE INDEX findings ON files(rank, id);
            CREATE INDEX verdicts ON files(verdict, id);
            CREATE TABLE issues(id INTEGER PRIMARY KEY, json TEXT NOT NULL);
            BEGIN;").map_err(storage_error)?;
        Ok(Self {
            connection,
            pending: 0,
        })
    }
    fn inserted(&mut self) -> io::Result<()> {
        self.pending += 1;
        if self.pending >= 128 {
            self.flush()?;
        }
        Ok(())
    }
    pub fn flush(&mut self) -> io::Result<()> {
        self.connection
            .execute_batch("COMMIT; BEGIN;")
            .map_err(storage_error)?;
        self.pending = 0;
        Ok(())
    }
    pub fn file(&mut self, file: &FileReport) -> io::Result<()> {
        let data = serde_json::to_value(file).map_err(storage_error)?;
        let raw = serde_json::to_string(&data).map_err(storage_error)?;
        let row = serde_json::json!({"path": data["path"], "metadata": data["metadata"],
            "status": data["status"], "verdict": data["verdict"], "complete": file.is_complete()});
        let verdict = data["verdict"]
            .as_str()
            .ok_or_else(|| storage_error("Missing verdict"))?;
        let rank = match file.verdict {
            Verdict::KnownMaliciousMatch => 0,
            Verdict::Suspicious => 1,
            Verdict::TestMatch => 2,
            Verdict::Error => 3,
            Verdict::Inconclusive => 4,
            Verdict::NoDetections => 5,
        };
        self.connection.execute("INSERT INTO files(path, verdict, complete, rank, row_json, json) VALUES (?1,?2,?3,?4,?5,?6)",
            params![file.path.to_string_lossy(), verdict, file.is_complete(), rank, row.to_string(), raw]).map_err(storage_error)?;
        self.inserted()
    }
    pub fn issue(&mut self, issue: &ScanIssue) -> io::Result<()> {
        self.connection
            .execute(
                "INSERT INTO issues(json) VALUES (?1)",
                [serde_json::to_string(issue).map_err(storage_error)?],
            )
            .map_err(storage_error)?;
        self.inserted()
    }
    /// Values are bound parameters, including search text; SQL predicates are fixed.
    pub fn page(
        &self,
        query: &str,
        filter: &str,
        page: u32,
        issues: bool,
    ) -> io::Result<ResultPage> {
        if query.len() > 2048 {
            return Err(storage_error("Search text is too long"));
        }
        if issues {
            let total = self
                .connection
                .query_row("SELECT count(*) FROM issues", [], |r| r.get(0))
                .map_err(storage_error)?;
            let mut statement = self
                .connection
                .prepare("SELECT id,json FROM issues ORDER BY id LIMIT 100 OFFSET ?1")
                .map_err(storage_error)?;
            let entries = statement
                .query_map([i64::from(page) * 100], |r| {
                    Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
                })
                .map_err(storage_error)?;
            return Ok(ResultPage {
                total,
                page,
                rows: parse_rows(entries)?,
            });
        }
        let predicate = match filter {
            "all" => "1=1",
            "detections" => "rank IN (0,1)",
            "incomplete" => "complete=0",
            "known_malicious_match"
            | "suspicious"
            | "test_match"
            | "no_detections"
            | "inconclusive"
            | "error" => "verdict=?2",
            _ => return Err(storage_error("Invalid result filter")),
        };
        // Always bind all parameters, even when a predicate does not reference ?2.
        let condition = format!(
            "({predicate}) AND (?2 IS NOT NULL) AND (?1='' OR instr(lower(path),lower(?1))>0)"
        );
        let total = self
            .connection
            .query_row(
                &format!("SELECT count(*) FROM files WHERE {condition}"),
                params![query, filter],
                |r| r.get(0),
            )
            .map_err(storage_error)?;
        let mut statement = self.connection.prepare(&format!("SELECT id,row_json FROM files WHERE {condition} ORDER BY rank,id LIMIT 100 OFFSET ?3")).map_err(storage_error)?;
        let entries = statement
            .query_map(params![query, filter, i64::from(page) * 100], |r| {
                Ok((r.get::<_, i64>(0)?, r.get::<_, String>(1)?))
            })
            .map_err(storage_error)?;
        Ok(ResultPage {
            total,
            page,
            rows: parse_rows(entries)?,
        })
    }
    pub fn detail(&self, id: i64) -> io::Result<Value> {
        let raw: String = self
            .connection
            .query_row("SELECT json FROM files WHERE id=?1", [id], |row| row.get(0))
            .map_err(storage_error)?;
        serde_json::from_str(&raw).map_err(storage_error)
    }
    /// Stream original Rust JSON, retaining exact integers and native path units.
    pub fn export(&self, writer: &mut impl Write, metadata: &Value) -> io::Result<()> {
        writer.write_all(b"{\"session\":")?;
        serde_json::to_writer(&mut *writer, metadata).map_err(storage_error)?;
        for table in ["files", "issues"] {
            write!(writer, ",\"{table}\":[")?;
            let mut statement = self
                .connection
                .prepare(&format!("SELECT json FROM {table} ORDER BY id"))
                .map_err(storage_error)?;
            let mut rows = statement.query([]).map_err(storage_error)?;
            let mut first = true;
            while let Some(row) = rows.next().map_err(storage_error)? {
                if !first {
                    writer.write_all(b",")?;
                }
                first = false;
                let raw: String = row.get(0).map_err(storage_error)?;
                writer.write_all(raw.as_bytes())?;
            }
            writer.write_all(b"]")?;
        }
        writer.write_all(b"}\n")?;
        writer.flush()
    }
}

fn parse_rows(
    entries: impl Iterator<Item = rusqlite::Result<(i64, String)>>,
) -> io::Result<Vec<Value>> {
    entries
        .map(|entry| {
            let (id, raw) = entry.map_err(storage_error)?;
            let mut value: Value = serde_json::from_str(&raw).map_err(storage_error)?;
            value["id"] = id.into();
            Ok(value)
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn pages_filters_literal_search_and_exact_export_are_disk_backed() {
        let temp = tempfile::tempdir().unwrap();
        let input = temp.path().join("marker.txt");
        std::fs::write(&input, b"SENTINEL_TEST_SIGNATURE").unwrap();
        let mut file = sentinel::scan(&input).files.remove(0);
        // Exercise integers that JavaScript cannot preserve exactly.
        file.metadata.as_mut().unwrap().modified_unix_ms = Some(9_007_199_254_740_993);
        let mut store = ResultStore::create(&temp.path().join("results.sqlite")).unwrap();
        for index in 0..235 {
            file.path = temp.path().join(format!("file {index}.txt"));
            store.file(&file).unwrap();
        }
        store.flush().unwrap();
        let first = store.page("", "all", 0, false).unwrap();
        let second = store.page("", "all", 1, false).unwrap();
        let last = store.page("", "all", 2, false).unwrap();
        assert_eq!(first.total, 235);
        assert_eq!(first.rows.len(), 100);
        assert_eq!(second.rows.len(), 100);
        assert_eq!(last.rows.len(), 35);
        assert_ne!(first.rows[0]["id"], second.rows[0]["id"]);
        assert_eq!(
            store
                .page("file 234", "test_match", 0, false)
                .unwrap()
                .rows
                .len(),
            1
        );
        assert_eq!(store.page("%", "all", 0, false).unwrap().total, 0);
        assert_eq!(store.page("' OR 1=1 --", "all", 0, false).unwrap().total, 0);
        assert_eq!(store.page("", "detections", 0, false).unwrap().total, 0);
        assert!(store.page("", "invalid", 0, false).is_err());
        let id = first.rows[0]["id"].as_i64().unwrap();
        assert_eq!(
            store.detail(id).unwrap()["metadata"]["modified_unix_ms"],
            9_007_199_254_740_993_u64
        );
        let mut export = Vec::new();
        store
            .export(&mut export, &serde_json::json!({"phase":"finished"}))
            .unwrap();
        let saved: Value = serde_json::from_slice(&export).unwrap();
        assert_eq!(saved["files"].as_array().unwrap().len(), 235);
        assert_eq!(
            saved["files"][0]["metadata"]["modified_unix_ms"],
            9_007_199_254_740_993_u64
        );
        assert_eq!(saved["session"]["phase"], "finished");
    }

    #[test]
    fn storage_errors_and_issue_pages_are_explicit() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = ResultStore::create(&temp.path().join("results.sqlite")).unwrap();
        let report = sentinel::scan(temp.path().join("missing"));
        store.issue(&report.issues[0]).unwrap();
        assert_eq!(store.page("", "all", 0, true).unwrap().total, 1);
        assert!(store.detail(999).is_err());
        store
            .connection
            .execute_batch("PRAGMA query_only=ON;")
            .unwrap();
        assert!(store.issue(&report.issues[0]).is_err());
    }
}
