//! The committed database fixtures, read back through the store.
//!
//! `tests/fixtures/turso-0.7` holds databases written by the turso 0.7
//! engine, each with an `expected.json` recording what that engine read from
//! it at the time: every row the store's public read API returned (`public`)
//! and a digest of every row of every table (`raw`). These tests open a copy
//! of each database with the store as it is now and require the same answers.
//! While the store runs on turso that proves the record is right; once it
//! runs on another engine the same tests, unchanged, prove the hand-over.
//!
//! Only the public `Store` API is used here, on purpose.

mod fixture_support;

use std::fmt::Write as _;
use std::path::Path;
use std::process::Command;

use fixture_support::{
    AS_WRITTEN, FIXTURES, MAIN_ONLY, copy_database, file_inventory, first_difference, fixture_dir,
    load_expected, public_dump, row_digest,
};
use pam_store::Store;
use serde_json::Value;

/// Set to `1` (or to the path of a `sqlite3` binary) to also read every
/// fixture with the SQLite command-line shell and compare it with the record.
const SQLITE3_ENV: &str = "PAM_STORE_FIXTURES_SQLITE3";

/// Stack for the thread a fixture is read on. The reads are the store's own
/// statements, but a debug build of the engine the fixtures were written
/// with needs more than half of a test thread's 2 MiB for them; what is
/// tested here is the data, so the stack is simply made roomy.
const STACK_BYTES: usize = 32 * 1024 * 1024;

/// Runs the future `work` builds to completion on its own thread and
/// runtime, and hands back its result or its panic.
fn on_roomy_thread<F, Fut, T>(work: F) -> T
where
    F: FnOnce() -> Fut + Send + 'static,
    Fut: Future<Output = T>,
    T: Send + 'static,
{
    let worker = std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(work())
        })
        .unwrap();
    match worker.join() {
        Ok(value) => value,
        Err(panic) => std::panic::resume_unwind(panic),
    }
}

fn read_back(name: &'static str) {
    on_roomy_thread(move || reads_back_as_recorded(name));
}

/// Opens a private copy of `name`'s database in each recorded variant and
/// requires the store's public reads to equal the record.
async fn reads_back_as_recorded(name: &str) {
    let expected = load_expected(name);
    assert_eq!(
        file_inventory(&fixture_dir(name)),
        expected["files"],
        "{name}: the committed database files are not the ones expected.json was recorded from"
    );
    let variants = expected["variants"].as_object().unwrap();
    assert!(
        variants.contains_key(AS_WRITTEN),
        "{name}: no recorded read"
    );
    for (variant, recorded) in variants {
        let dir = tempfile::tempdir().unwrap();
        let path = copy_database(&fixture_dir(name), dir.path(), variant != MAIN_ONLY);
        let store = Store::open(&path).await.unwrap();
        store.check_integrity().await.unwrap();
        // Opening migrates: a later binary may be past the recorded version,
        // never behind it.
        let written_at = recorded["raw"]["user_version"].as_i64().unwrap();
        assert!(store.schema_version().await.unwrap() >= written_at);
        let dump = Box::pin(public_dump(&store, &expected["probes"])).await;
        if let Some(difference) = first_difference(&dump, &recorded["public"], "") {
            panic!("{name} ({variant}): {difference}");
        }
        drop(store);

        // A second open of the same files finds the same requests.
        let store = Store::open(&path).await.unwrap();
        let listed = store
            .list_requests_filtered(
                Some(pam_store::MAX_LIST_LIMIT),
                None,
                None,
                None,
                None,
                false,
            )
            .await
            .unwrap();
        assert_eq!(
            Value::from(listed.len()),
            recorded["public"]["request"]["count"],
            "{name} ({variant}): reopening changed the request count"
        );
    }
}

#[test]
fn latest_schema_fixture_reads_back_as_recorded() {
    read_back("v13-full");
}

#[test]
fn fixture_with_commits_only_in_its_wal_reads_back_as_recorded() {
    read_back("v13-wal");
}

#[test]
fn released_schema_11_fixture_migrates_and_reads_back_as_recorded() {
    read_back("v11");
}

/// The write-ahead log of a fixture that has one carries rows the main file
/// lacks: without it the store opens an older, consistent database.
#[test]
fn a_fixture_without_its_wal_is_an_older_database() {
    for name in ["v13-wal", "v11"] {
        let expected = load_expected(name);
        let requests = |variant: &str| {
            expected["variants"][variant]["public"]["request"]["count"]
                .as_u64()
                .unwrap()
        };
        assert_eq!(
            requests(AS_WRITTEN),
            requests(MAIN_ONLY) + 6,
            "{name}: the log should hold six requests the main file does not"
        );
    }
}

/// The record covers every table of the schema, so no table can be added
/// to a fixture without its rows being pinned.
#[test]
fn every_table_of_every_fixture_has_a_recorded_digest() {
    for name in FIXTURES {
        let expected = load_expected(name);
        for (variant, recorded) in expected["variants"].as_object().unwrap() {
            let tables = recorded["raw"]["tables"].as_object().unwrap();
            assert_eq!(tables.len(), 17, "{name} ({variant})");
            for (table, record) in tables {
                assert_eq!(
                    record["count"].as_u64().unwrap(),
                    u64::try_from(record["row_digests"].as_array().unwrap().len()).unwrap(),
                    "{name} ({variant}): {table}"
                );
            }
        }
    }
}

fn sqlite3_binary() -> Option<String> {
    match std::env::var(SQLITE3_ENV) {
        Ok(value) if value == "1" => Some("sqlite3".to_owned()),
        Ok(value) if !value.is_empty() && value != "0" => Some(value),
        _ => None,
    }
}

/// Runs `sql` in the SQLite shell against `database`: whether it succeeded,
/// its output lines, and what it wrote to standard error.
fn sqlite3(binary: &str, database: &Path, sql: &str) -> (bool, Vec<String>, String) {
    let output = Command::new(binary)
        .args(["-batch", "-noheader", "-list"])
        .arg(database)
        .arg(sql)
        .output()
        .unwrap_or_else(|error| panic!("cannot run {binary}: {error}"));
    let lines = String::from_utf8(output.stdout)
        .unwrap()
        .lines()
        .map(str::to_owned)
        .collect();
    let complaint = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    (output.status.success(), lines, complaint)
}

/// [`sqlite3`] for statements that must succeed, with the output split on
/// the `##name` marker lines the statements print.
fn sqlite3_sections(binary: &str, database: &Path, sql: &str) -> Vec<(String, Vec<String>)> {
    let (succeeded, lines, complaint) = sqlite3(binary, database, sql);
    assert!(succeeded, "{binary} failed: {complaint}");
    let mut sections: Vec<(String, Vec<String>)> = Vec::new();
    for line in lines {
        if let Some(name) = line.strip_prefix("##") {
            sections.push((name.to_owned(), Vec::new()));
        } else if let Some((_, lines)) = sections.last_mut() {
            lines.push(line);
        }
    }
    sections
}

/// The file-level checks every comparison starts with.
const SQLITE3_CHECKS: &str = "SELECT '##version'; SELECT sqlite_version(); \
     SELECT '##journal_mode'; PRAGMA journal_mode; \
     SELECT '##page_count'; PRAGMA page_count; \
     SELECT '##freelist_count'; PRAGMA freelist_count; \
     SELECT '##integrity_check'; PRAGMA integrity_check; \
     SELECT '##foreign_key_check'; PRAGMA foreign_key_check; \
     SELECT '##user_version'; PRAGMA user_version; \
     SELECT '##schema_objects'; SELECT type || ':' || name FROM sqlite_master ORDER BY 1; ";

/// Numbers the revocations of `"grant"` the way migration 12 does, as a
/// query, so an engine's own arithmetic can be compared with stored values.
const REVOCATION_RANKS: &str = "SELECT id || ':' || (SELECT COUNT(*) FROM \"grant\" earlier \
     WHERE earlier.revoked_ts IS NOT NULL AND earlier.revoked_ts <= g.revoked_ts) \
     FROM \"grant\" g WHERE g.revoked_ts IS NOT NULL ORDER BY id";

/// Compares what the SQLite shell reads from one copy with the record.
/// Returns the report lines and the disagreements found.
fn sqlite3_compare(binary: &str, database: &Path, raw: &Value) -> (Vec<String>, Vec<String>) {
    let tables = raw["tables"].as_object().unwrap();
    let mut sql = String::from(SQLITE3_CHECKS);
    for (table, record) in tables {
        write!(
            sql,
            "SELECT '##count:{table}'; SELECT count(*) FROM \"{table}\"; \
             SELECT '##rows:{table}'; {}; ",
            record["rows_sql"].as_str().unwrap()
        )
        .unwrap();
    }
    let sections = sqlite3_sections(binary, database, &sql);
    let section = |name: &str| -> &[String] {
        sections
            .iter()
            .find(|(found, _)| found == name)
            .map_or(&[], |(_, lines)| lines.as_slice())
    };
    let mut report = vec![format!(
        "  sqlite3 {}, journal_mode {}",
        section("version").join(" "),
        section("journal_mode").join(" ")
    )];
    let mut disagreements = Vec::new();
    let mut check = |what: String, found: String, wanted: String| {
        let verdict = if found == wanted { "ok" } else { "DISAGREES" };
        report.push(format!(
            "  {what}: sqlite3 {found}, recorded {wanted}: {verdict}"
        ));
        if found != wanted {
            disagreements.push(format!("{what}: sqlite3 {found}, recorded {wanted}"));
        }
    };
    for name in ["page_count", "freelist_count"] {
        // Recorded only where the writing engine answers the pragma.
        if let Some(wanted) = raw[name].as_i64() {
            check(name.to_owned(), section(name).join(" "), wanted.to_string());
        }
    }
    check(
        "integrity_check".to_owned(),
        section("integrity_check").join("; "),
        "ok".to_owned(),
    );
    check(
        "foreign_key_check".to_owned(),
        format!("{} violations", section("foreign_key_check").len()),
        "0 violations".to_owned(),
    );
    check(
        "user_version".to_owned(),
        section("user_version").join(" "),
        raw["user_version"].to_string(),
    );
    let objects: Vec<&str> = raw["schema_objects"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect();
    let found = section("schema_objects");
    check(
        format!("schema objects ({})", objects.len()),
        if found == objects.as_slice() {
            "same names".to_owned()
        } else {
            found.join(",")
        },
        "same names".to_owned(),
    );
    for (table, record) in tables {
        check(
            format!("count({table})"),
            section(&format!("count:{table}")).join(" "),
            record["count"].to_string(),
        );
        let found: Vec<String> = section(&format!("rows:{table}"))
            .iter()
            .map(|line| row_digest(line))
            .collect();
        let wanted: Vec<&str> = record["row_digests"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(Value::as_str)
            .collect();
        let differing = found
            .iter()
            .zip(&wanted)
            .filter(|(found, wanted)| found != wanted)
            .count()
            + found.len().abs_diff(wanted.len());
        check(
            format!("rows({table})"),
            format!("{differing} of {} differ", wanted.len()),
            format!("0 of {} differ", wanted.len()),
        );
    }
    (report, disagreements)
}

/// Opens `database` with the store, which migrates it, closes it again, and
/// has the SQLite shell check what the store left: a sound file at the
/// store's schema version with every row still there, and, for a database
/// written before revocations were numbered, the numbers migration 12 gave
/// them equal to `ranks`, the shell's own count over the untouched file.
fn sqlite3_after_open(
    binary: &str,
    database: &Path,
    raw: &Value,
    ranks: &[String],
) -> (Vec<String>, Vec<String>) {
    let opened = database.to_path_buf();
    let version = on_roomy_thread(move || async move {
        let store = Store::open(&opened).await.unwrap();
        store.schema_version().await.unwrap()
    });
    let tables = raw["tables"].as_object().unwrap();
    let mut sql = String::from(SQLITE3_CHECKS);
    for table in tables.keys() {
        write!(
            sql,
            "SELECT '##count:{table}'; SELECT count(*) FROM \"{table}\"; "
        )
        .unwrap();
    }
    sql.push_str(
        "SELECT '##revocations'; SELECT id || ':' || revoked_seq FROM \"grant\" \
         WHERE revoked_ts IS NOT NULL ORDER BY id;",
    );
    let sections = sqlite3_sections(binary, database, &sql);
    let section = |name: &str| -> &[String] {
        sections
            .iter()
            .find(|(found, _)| found == name)
            .map_or(&[], |(_, lines)| lines.as_slice())
    };
    let counts_before: Vec<String> = tables
        .values()
        .map(|record| record["count"].to_string())
        .collect();
    let counts_after: Vec<String> = tables
        .keys()
        .map(|table| section(&format!("count:{table}")).join(" "))
        .collect();
    let mut checks = vec![
        (
            "integrity_check",
            section("integrity_check").join("; "),
            "ok".to_owned(),
        ),
        (
            "foreign_key_check",
            format!("{} violations", section("foreign_key_check").len()),
            "0 violations".to_owned(),
        ),
        (
            "user_version",
            section("user_version").join(" "),
            version.to_string(),
        ),
        (
            "row counts",
            counts_after.join(","),
            counts_before.join(","),
        ),
    ];
    if raw["user_version"].as_i64().unwrap() < 12 {
        checks.push((
            "revocation numbers (id:seq)",
            section("revocations").join(","),
            ranks.join(","),
        ));
    }
    let mut report = Vec::new();
    let mut disagreements = Vec::new();
    for (what, found, wanted) in checks {
        let verdict = if found == wanted { "ok" } else { "DISAGREES" };
        report.push(format!(
            "  after the store opened it, {what}: sqlite3 {found}, expected {wanted}: {verdict}"
        ));
        if found != wanted {
            disagreements.push(format!(
                "after the store opened it, {what}: sqlite3 {found}, expected {wanted}"
            ));
        }
    }
    (report, disagreements)
}

/// The two triggers of schema 12, as the SQLite shell enforces them on a
/// fixture: each forbidden update must fail with the trigger's own text.
fn sqlite3_triggers(binary: &str, database: &Path) -> (Vec<String>, Vec<String>) {
    let mut report = Vec::new();
    let mut disagreements = Vec::new();
    for (update, refusal) in [
        (
            "UPDATE audit SET detail = 'tampered'",
            "audit rows are append-only",
        ),
        (
            "UPDATE evidence_view SET view_sha256 = 'tampered'",
            "evidence views are immutable",
        ),
    ] {
        let (succeeded, _, complaint) = sqlite3(binary, database, update);
        let refused = !succeeded && complaint.contains(refusal);
        let verdict = if refused { "ok" } else { "DISAGREES" };
        report.push(format!(
            "  `{update}` refused with \"{refusal}\": {verdict}"
        ));
        if !refused {
            disagreements.push(format!("`{update}` was not refused: {complaint}"));
        }
    }
    (report, disagreements)
}

/// Opt-in: the SQLite shell reads a copy of every fixture and must find a
/// sound file holding exactly the rows the writing engine recorded, value for
/// value and type for type; then the same for a copy the store has opened
/// and migrated. Skipped unless `PAM_STORE_FIXTURES_SQLITE3` is set; run with
/// `--nocapture` for the per-table report.
#[test]
fn sqlite3_shell_reads_the_same_rows_as_recorded() {
    let Some(binary) = sqlite3_binary() else {
        eprintln!("skipped: set {SQLITE3_ENV}=1 to compare the fixtures with the sqlite3 shell");
        return;
    };
    let mut disagreements = Vec::new();
    for name in FIXTURES {
        let expected = load_expected(name);
        for (variant, recorded) in expected["variants"].as_object().unwrap() {
            let raw = &recorded["raw"];
            let with_wal = variant != MAIN_ONLY;
            let untouched = tempfile::tempdir().unwrap();
            let database = copy_database(&fixture_dir(name), untouched.path(), with_wal);
            let (mut report, mut found) = sqlite3_compare(&binary, &database, raw);
            let ranks = sqlite3_sections(
                &binary,
                &database,
                &format!("SELECT '##ranks'; {REVOCATION_RANKS};"),
            )
            .pop()
            .map(|(_, lines)| lines)
            .unwrap_or_default();
            let has_triggers = raw["schema_objects"]
                .as_array()
                .unwrap()
                .iter()
                .any(|object| {
                    object
                        .as_str()
                        .is_some_and(|name| name.starts_with("trigger:"))
                });
            if has_triggers {
                let (lines, failures) = sqlite3_triggers(&binary, &database);
                report.extend(lines);
                found.extend(failures);
            }
            let opened = tempfile::tempdir().unwrap();
            let database = copy_database(&fixture_dir(name), opened.path(), with_wal);
            let (lines, failures) = sqlite3_after_open(&binary, &database, raw, &ranks);
            report.extend(lines);
            found.extend(failures);

            println!("{name} ({variant})");
            for line in report {
                println!("{line}");
            }
            disagreements.extend(
                found
                    .into_iter()
                    .map(|d| format!("{name} ({variant}): {d}")),
            );
        }
    }
    assert!(
        disagreements.is_empty(),
        "sqlite3 and the recorded reads disagree:\n{}",
        disagreements.join("\n")
    );
}
