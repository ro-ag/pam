//! What a killed process leaves behind.
//!
//! The test binary re-executes itself as a child that opens a store on a
//! real file and writes without pause, announcing each write on standard
//! output only after the store call has returned. The parent kills it
//! (`Child::kill`: `SIGKILL` on unix, `TerminateProcess` on Windows) and
//! opens the files it left: the database must be sound, every announced
//! write must be there, and no transaction may be visible in part.
//!
//! A kill proves what survives the *process* dying; the operating system
//! still has every byte the process wrote. Surviving a power cut is a
//! property of the sync settings and cannot be tested from user space.
//!
//! Public `Store` API only.

use std::io::{BufRead, BufReader, Write};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::mpsc;
use std::time::Duration;

use pam_store::{Actor, AuditEntry, Decision, RequestState, Store};

/// Set, for the child, to the path of the database it writes.
const DATABASE_ENV: &str = "PAM_STORE_DURABILITY_DATABASE";
/// What the child does: `write:<prefix>` or `prune:<count>`.
const WORK_ENV: &str = "PAM_STORE_DURABILITY_WORK";

/// How long the parent waits for the child's next line before giving up.
const CHILD_SILENCE: Duration = Duration::from_secs(120);

/// The settings pair every write transaction of the child rewrites
/// together: both halves always carry the same value.
const PAIR: [&str; 2] = ["pair_a", "pair_b"];

fn entry() -> AuditEntry<'static> {
    AuditEntry {
        action: "execute",
        decision: Decision::Allow,
        actor: Actor::System,
        detail: None,
    }
}

fn runtime() -> tokio::runtime::Runtime {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
}

fn say(line: &str) {
    let mut out = std::io::stdout().lock();
    writeln!(out, "{line}").unwrap();
    out.flush().unwrap();
}

/// The child. A test like any other to the harness; it does nothing unless
/// the parent's variables are set.
#[test]
fn durability_child() {
    let (Some(database), Ok(work)) = (std::env::var_os(DATABASE_ENV), std::env::var(WORK_ENV))
    else {
        return;
    };
    let database = Path::new(&database).to_owned();
    runtime().block_on(async move {
        let store = Store::open(&database).await.unwrap();
        match work.split_once(':').unwrap() {
            ("write", prefix) => write_until_killed(&store, prefix).await,
            ("prune", count) => prune_until_killed(&store, count.parse().unwrap()).await,
            other => panic!("unknown work {other:?}"),
        }
    });
}

/// One request per round: inserted, finished with its audit row in one
/// transaction, then the settings pair in another. Each is announced after
/// its call returned.
async fn write_until_killed(store: &Store, prefix: &str) {
    say("ready");
    for index in 0u64.. {
        let id = format!("{prefix}_{index:06}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        assert!(
            store
                .finish_request(&id, RequestState::Done, Some("ok"), entry())
                .await
                .unwrap()
        );
        say(&format!("finished {index}"));
        let value = format!("{prefix}:{index}");
        store
            .set_settings(&[(PAIR[0], &value), (PAIR[1], &value)])
            .await
            .unwrap();
        say(&format!("paired {index}"));
    }
}

/// Seeds `count` finished requests, each with evidence, then removes them
/// all, announcing when the removal starts.
async fn prune_until_killed(store: &Store, count: u64) {
    for index in 0..count {
        let id = format!("old_{index:06}");
        store
            .insert_request(&id, "echo", "/repo", "agent", "{}", None)
            .await
            .unwrap();
        store
            .insert_evidence(
                &format!("ev_{index:06}"),
                &id,
                "log.source",
                &[7u8; 2048],
                None,
            )
            .await
            .unwrap();
        store
            .finish_request(&id, RequestState::Done, Some("ok"), entry())
            .await
            .unwrap();
    }
    say("pruning");
    let removed = store.prune_requests_before(i64::MAX).await.unwrap();
    say(&format!("pruned {}", removed.requests));
    // Stay alive until killed, so the parent's kill is the only way out.
    loop {
        tokio::time::sleep(Duration::from_secs(1)).await;
    }
}

/// A running child and the lines it prints.
struct Writer {
    child: Child,
    lines: mpsc::Receiver<String>,
}

impl Writer {
    fn spawn(database: &Path, work: &str) -> Self {
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "durability_child", "--nocapture"])
            .env(DATABASE_ENV, database)
            .env(WORK_ENV, work)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()
            .unwrap();
        let stdout = child.stdout.take().unwrap();
        let (sender, lines) = mpsc::channel();
        std::thread::spawn(move || {
            for line in BufReader::new(stdout).lines() {
                let Ok(line) = line else { break };
                if sender.send(line).is_err() {
                    break;
                }
            }
        });
        Self { child, lines }
    }

    /// The child's next line; panics if it has gone quiet or died.
    fn next(&self) -> String {
        self.lines
            .recv_timeout(CHILD_SILENCE)
            .expect("the child stopped talking before it was killed")
    }

    /// Reads until the child prints `wanted`. The test harness may have put
    /// its own words on the same line first.
    fn wait_for(&self, wanted: &str) {
        while !self.next().trim().ends_with(wanted) {}
    }

    /// Kills the child and returns every line it had printed and the parent
    /// had not read yet.
    fn kill(mut self) -> Vec<String> {
        self.child.kill().unwrap();
        self.child.wait().unwrap();
        // The reader thread ends at end of file; the channel then closes.
        self.lines.iter().collect()
    }
}

impl Drop for Writer {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

/// The highest `<word> <n>` among `lines`.
fn highest(lines: &[String], word: &str) -> Option<u64> {
    lines
        .iter()
        .filter_map(|line| line.trim().strip_prefix(word)?.trim().parse().ok())
        .max()
}

#[test]
fn a_killed_writer_loses_nothing_it_acknowledged_and_shows_nothing_in_part() {
    let dir = tempfile::tempdir().unwrap();
    let database = dir.path().join("state.sqlite3");

    // Three lives of the same database, each ended by a kill at a different
    // depth, each starting from what the last one left.
    for (round, kill_after) in [(0u32, 40u64), (1, 150), (2, 15)] {
        let prefix = format!("life{round}");
        let writer = Writer::spawn(&database, &format!("write:{prefix}"));
        writer.wait_for("ready");
        let mut seen = Vec::new();
        loop {
            let line = writer.next();
            let enough =
                highest(std::slice::from_ref(&line), "paired").is_some_and(|n| n >= kill_after);
            seen.push(line);
            if enough {
                break;
            }
        }
        // Mid-stride: the child is inside one of its next store calls when
        // this lands, a different one each round.
        std::thread::sleep(Duration::from_micros(u64::from(round) * 1700));
        seen.extend(writer.kill());
        let finished = highest(&seen, "finished").unwrap();
        let paired = highest(&seen, "paired").unwrap();
        assert!(paired >= kill_after, "round {round}");

        runtime().block_on(async {
            let store = Store::open(&database).await.unwrap();
            store.check_integrity().await.unwrap();

            // Everything acknowledged is there, whole.
            for index in 0..=finished {
                let id = format!("{prefix}_{index:06}");
                let row = store
                    .get_request(&id)
                    .await
                    .unwrap()
                    .unwrap_or_else(|| panic!("round {round}: acknowledged {id} is missing"));
                assert_eq!(row.state, RequestState::Done, "round {round}: {id}");
                assert_eq!(row.outcome.as_deref(), Some("ok"), "round {round}: {id}");
                assert_eq!(
                    store.audit_for_request(&id).await.unwrap().len(),
                    1,
                    "round {round}: {id}"
                );
            }
            // Past the last acknowledgement a request may exist or not, but
            // never in part: finished with its audit row, or queued without.
            for index in finished + 1..finished + 4 {
                let id = format!("{prefix}_{index:06}");
                let audit = store.audit_for_request(&id).await.unwrap().len();
                match store.get_request(&id).await.unwrap() {
                    None => assert_eq!(audit, 0, "round {round}: audit without {id}"),
                    Some(row) if row.state == RequestState::Done => {
                        assert_eq!(
                            audit, 1,
                            "round {round}: {id} finished without its audit row"
                        );
                    }
                    Some(row) => {
                        assert_eq!(row.state, RequestState::Queued, "round {round}: {id}");
                        assert_eq!(audit, 0, "round {round}: audit row for unfinished {id}");
                    }
                }
            }
            // The pair was only ever written together, and is at least as
            // new as its last acknowledgement.
            let a = store.get_setting(PAIR[0]).await.unwrap().unwrap();
            let b = store.get_setting(PAIR[1]).await.unwrap().unwrap();
            assert_eq!(a, b, "round {round}: half a transaction is visible");
            let (life, index) = a.split_once(':').unwrap();
            assert_eq!(life, prefix, "round {round}");
            assert!(
                index.parse::<u64>().unwrap() >= paired,
                "round {round}: {a}"
            );
            // Earlier lives are intact too.
            for earlier in 0..round {
                let id = format!("life{earlier}_000000");
                assert!(store.get_request(&id).await.unwrap().is_some(), "{id}");
            }
            // Dropped, not closed: the next life starts from a log again.
            drop(store);
        });
    }
}

#[test]
fn a_writer_killed_while_pruning_leaves_whole_records_only() {
    const SEEDED: u64 = 700;
    // Kills at several depths into the removal: before its first batch has
    // committed, part-way through, and (on a fast disk) after it finished.
    for delay_ms in [1u64, 5, 9] {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("state.sqlite3");
        let writer = Writer::spawn(&database, &format!("prune:{SEEDED}"));
        writer.wait_for("pruning");
        std::thread::sleep(Duration::from_millis(delay_ms));
        let rest = writer.kill();
        let completed = highest(&rest, "pruned");

        runtime().block_on(async {
            let store = Store::open(&database).await.unwrap();
            store.check_integrity().await.unwrap();
            let mut remaining = 0u64;
            for index in 0..SEEDED {
                let id = format!("old_{index:06}");
                let audit = store.audit_for_request(&id).await.unwrap().len();
                let evidence = store.list_evidence(&id).await.unwrap().len();
                let blob = store.get_evidence(&format!("ev_{index:06}")).await.unwrap();
                if store.get_request(&id).await.unwrap().is_some() {
                    // Untouched: every part of the record is still there.
                    assert_eq!((audit, evidence), (1, 1), "{id} lost a part");
                    assert_eq!(blob.unwrap().content.len(), 2048, "{id}");
                    remaining += 1;
                } else {
                    // Removed: every part of the record is gone.
                    assert_eq!((audit, evidence), (0, 0), "{id} left a part behind");
                    assert!(blob.is_none(), "{id} left its evidence behind");
                }
            }
            if let Some(removed) = completed {
                // The prune had returned before the kill: all of it is
                // durable.
                assert_eq!(removed, SEEDED);
                assert_eq!(remaining, 0);
            }
            // What is left can still be removed, in good order.
            let removed = store.prune_requests_before(i64::MAX).await.unwrap();
            assert_eq!(removed.requests, remaining);
            store.close().await.unwrap();
        });
    }
}
