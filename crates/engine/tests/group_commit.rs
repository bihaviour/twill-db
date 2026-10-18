//! Group commit (spec 02/09; issue #6 / #29). These pin the correctness and
//! durability of coalescing concurrent transactions' WAL into one durable append
//! — the W1 lever — and prove the batching actually engages. They run *here* (no
//! network, no real object store) because correctness, isolation, and durability
//! are universal; the latency/throughput *numbers* (the Exp-1 ceiling vs the
//! Exp-2 plateau) are measured against a real object store by `twill-bench`.
//!
//! What must hold under concurrent writers, even when their commits batch:
//!
//! * **Every acked commit is durable.** Group commit never acks before the batch
//!   is on disk (spec 10 — "never acknowledge a commit before its WAL record is
//!   durably stored, even under group commit"). Reopening the database must show
//!   every committed row.
//! * **Snapshot isolation holds.** Independent-row writers all commit with
//!   distinct, gap-free LSNs; same-row writers are serialized by
//!   first-toucher-wins and never lose an update (see also `tests/hot_row.rs`,
//!   which now exercises the same contended path through the coordinator);
//!   concurrent same-key inserts never produce a duplicate.
//! * **Batching engages.** With many concurrent writers, commits coalesce — the
//!   number of durable appends is strictly less than the number of commits.

use engine::{Connection, Database, EngineStatus, Value};
use std::fs;
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Barrier;
use std::thread;

fn db_path(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("twill-gc-{tag}-{}-{n}.db", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn url_for(p: &std::path::Path) -> String {
    format!("file://{}", p.display())
}

fn scalar_i64(conn: &mut Connection, sql: &str) -> i64 {
    let rs = conn.query(sql).unwrap();
    match &rs.rows[0][0] {
        Value::Int(n) => *n,
        other => panic!("expected integer scalar, got {other:?}"),
    }
}

/// Run `sql`, retrying the (retryable) first-committer/first-toucher conflict
/// that contended writers provoke under snapshot isolation.
fn exec_retrying(conn: &mut Connection, sql: &str) {
    loop {
        match conn.exec(sql) {
            Ok(()) => return,
            Err(e) if e.status == EngineStatus::ErrConflict => continue,
            Err(e) => panic!("unexpected error: {e:?}"),
        }
    }
}

#[test]
fn independent_writers_coalesce_and_are_durable() {
    // Many connections each insert their own disjoint rows in autocommit (the
    // Experiment-2 shape: independent rows, no contention). Every commit must be
    // durable, all rows must survive a reopen, and the commits must coalesce into
    // fewer durable appends than there were commits.
    const WRITERS: usize = 8;
    const PER_WRITER: usize = 100;
    const TOTAL: usize = WRITERS * PER_WRITER;

    let p = db_path("independent");
    let url = url_for(&p);

    // Hold a Database handle so we can read the group-commit counters; it shares
    // the same instance the connections use (process-global registry).
    let db = Database::open(&url).unwrap();
    {
        let mut setup = Connection::open(&url).unwrap();
        setup
            .exec("CREATE TABLE t (id INTEGER PRIMARY KEY, w INTEGER)")
            .unwrap();
    }

    let barrier = Barrier::new(WRITERS);
    thread::scope(|s| {
        for w in 0..WRITERS {
            let url = &url;
            let barrier = &barrier;
            s.spawn(move || {
                let mut c = Connection::open(url).unwrap();
                barrier.wait(); // maximize commit overlap so batches form
                for i in 0..PER_WRITER {
                    let id = w * PER_WRITER + i;
                    exec_retrying(&mut c, &format!("INSERT INTO t (id, w) VALUES ({id}, {w})"));
                }
            });
        }
    });

    let mut check = Connection::open(&url).unwrap();
    assert_eq!(
        scalar_i64(&mut check, "SELECT COUNT(*) FROM t"),
        TOTAL as i64,
        "every inserted row must be present"
    );

    let (appends, commits) = db.group_commit_stats();
    assert!(
        commits >= TOTAL as u64,
        "expected at least {TOTAL} commits, saw {commits}"
    );
    assert!(
        appends < commits,
        "group commit must coalesce: {appends} durable appends for {commits} commits"
    );

    // Durability: drop every handle, reopen from disk, and confirm all rows
    // recovered (replay of the batched WAL).
    drop(check);
    drop(db);
    let mut reopened = Connection::open(&url).unwrap();
    assert_eq!(
        scalar_i64(&mut reopened, "SELECT COUNT(*) FROM t"),
        TOTAL as i64,
        "all acked commits must survive a restart"
    );

    let _ = fs::remove_file(&p);
}

#[test]
fn database_stats_fold_engine_and_storage_counters() {
    // `Database::stats()` is the engine tier of the #53 observability surface: it
    // folds the group-commit counters and the committed-LSN gauge together with
    // the backend's StorageStats, pulled through the seam — so one pull on a
    // handle yields both. Asserts the snapshot moves with real work and that the
    // embedded storage counters are populated (the engine reaches the backend's
    // counters without the backend leaking internals across the seam).
    let p = db_path("stats");
    let url = url_for(&p);

    let db = Database::open(&url).unwrap();
    let before = db.stats();

    let mut c = Connection::open(&url).unwrap();
    c.exec("CREATE TABLE t (id INTEGER PRIMARY KEY, v INTEGER)")
        .unwrap();
    for i in 0..25 {
        c.exec(&format!("INSERT INTO t (id, v) VALUES ({i}, {})", i * 2))
            .unwrap();
    }
    // A read, so a SELECT round-trip is part of the observed window.
    assert_eq!(scalar_i64(&mut c, "SELECT COUNT(*) FROM t"), 25);

    let after = db.stats();
    assert!(
        after.commits > before.commits,
        "commits advanced: {} -> {}",
        before.commits,
        after.commits
    );
    assert!(
        after.committed_lsn > before.committed_lsn,
        "committed LSN gauge advanced"
    );
    // group_commit_stats() and stats() agree on the same underlying counters.
    let (appends, commits) = db.group_commit_stats();
    assert_eq!(after.commits, commits);
    assert_eq!(after.durable_appends, appends);
    // Storage counters reached through the seam reflect the durable appends.
    assert!(
        after.storage.wal_appends >= after.durable_appends,
        "storage saw at least one WAL append per durable batch"
    );
    assert!(
        after.storage.fsyncs > 0,
        "durable commits fsync the backend"
    );

    drop(c);
    drop(db);
    let _ = fs::remove_file(&p);
}

#[test]
fn write_lane_handoffs_are_observable_under_contention() {
    // EX-4 / spec 10: the per-DB serialized-handoff count + wait time must be
    // observable through `Database::stats()` so the hot-row routing decision is
    // falsifiable. A single uncontended writer records acquisitions but zero
    // handoffs (nothing to wait behind); many writers hammering ONE hot row
    // force serialized handoffs through the single write lane.
    let p = db_path("handoff");
    let url = url_for(&p);

    let db = Database::open(&url).unwrap();
    {
        let mut setup = Connection::open(&url).unwrap();
        setup
            .exec("CREATE TABLE t (id INTEGER PRIMARY KEY, n INTEGER)")
            .unwrap();
        setup.exec("INSERT INTO t (id, n) VALUES (1, 0)").unwrap();
    }

    // Uncontended baseline: a single writer never waits behind another, so the
    // handoff counter stays put even as acquisitions climb.
    let base = db.stats();
    {
        let mut solo = Connection::open(&url).unwrap();
        for _ in 0..20 {
            exec_retrying(&mut solo, "UPDATE t SET n = n + 1 WHERE id = 1");
        }
    }
    let solo = db.stats();
    assert!(
        solo.write_acquires > base.write_acquires,
        "a lone writer still acquires the lane per write"
    );
    assert_eq!(
        solo.write_handoffs, base.write_handoffs,
        "a lone writer never hands off (no contention): {} -> {}",
        base.write_handoffs, solo.write_handoffs
    );

    // Contended: many writers on the same hot row serialize through the lane.
    const WRITERS: usize = 8;
    const PER_WRITER: usize = 40;
    let barrier = Barrier::new(WRITERS);
    thread::scope(|s| {
        for _ in 0..WRITERS {
            let url = &url;
            let barrier = &barrier;
            s.spawn(move || {
                let mut c = Connection::open(url).unwrap();
                barrier.wait(); // maximize overlap so writers collide on the lane
                for _ in 0..PER_WRITER {
                    exec_retrying(&mut c, "UPDATE t SET n = n + 1 WHERE id = 1");
                }
            });
        }
    });

    let after = db.stats();
    assert!(
        after.write_handoffs > solo.write_handoffs,
        "contended writers must record serialized handoffs: {} -> {}",
        solo.write_handoffs,
        after.write_handoffs
    );
    assert!(
        after.write_wait_us_total >= solo.write_wait_us_total,
        "handoff wait time is cumulative and non-decreasing"
    );
    // The hot row was incremented exactly once per successful UPDATE.
    let mut check = Connection::open(&url).unwrap();
    assert_eq!(
        scalar_i64(&mut check, "SELECT n FROM t WHERE id = 1"),
        (20 + WRITERS * PER_WRITER) as i64,
        "single-writer serialization loses no update even while we measure it"
    );

    drop(check);
    drop(db);
    let _ = fs::remove_file(&p);
}

#[test]
fn commit_lsns_are_unique_across_concurrent_writers() {
    // Each autocommit insert publishes at its own commit LSN; across concurrent
    // writers those LSNs must be distinct and positive (the batched append
    // assigns a contiguous, gap-free LSN range, one Commit marker per member).
    const WRITERS: usize = 6;
    const PER_WRITER: usize = 60;

    let p = db_path("lsn");
    let url = url_for(&p);
    {
        let mut setup = Connection::open(&url).unwrap();
        setup.exec("CREATE TABLE t (id INTEGER)").unwrap();
    }

    let barrier = Barrier::new(WRITERS);
    let lsns: std::sync::Mutex<Vec<i64>> = std::sync::Mutex::new(Vec::new());
    thread::scope(|s| {
        for w in 0..WRITERS {
            let url = &url;
            let barrier = &barrier;
            let lsns = &lsns;
            s.spawn(move || {
                let mut c = Connection::open(url).unwrap();
                let mut mine = Vec::new();
                barrier.wait();
                for i in 0..PER_WRITER {
                    let id = w * PER_WRITER + i;
                    exec_retrying(&mut c, &format!("INSERT INTO t (id) VALUES ({id})"));
                    mine.push(c.last_lsn);
                }
                lsns.lock().unwrap().extend(mine);
            });
        }
    });

    let mut all = lsns.into_inner().unwrap();
    let n = all.len();
    all.sort_unstable();
    all.dedup();
    assert_eq!(all.len(), n, "commit LSNs must be unique across writers");
    assert!(all.iter().all(|&l| l > 0), "commit LSNs must be positive");

    let _ = fs::remove_file(&p);
}

#[test]
fn concurrent_same_row_increments_never_lose_an_update() {
    // The single-writer-serialization / first-toucher-wins guarantee must hold
    // even though commits batch: a contended read-modify-write retried on
    // conflict yields an exact total (no lost update is reachable).
    const WRITERS: usize = 8;
    const PER_WRITER: usize = 40;

    let p = db_path("samerow");
    let url = url_for(&p);
    {
        let mut setup = Connection::open(&url).unwrap();
        setup
            .exec("CREATE TABLE c (id INTEGER, n INTEGER)")
            .unwrap();
        setup.exec("INSERT INTO c (id, n) VALUES (1, 0)").unwrap();
    }

    let barrier = Barrier::new(WRITERS);
    thread::scope(|s| {
        for _ in 0..WRITERS {
            let url = &url;
            let barrier = &barrier;
            s.spawn(move || {
                let mut c = Connection::open(url).unwrap();
                barrier.wait();
                for _ in 0..PER_WRITER {
                    exec_retrying(&mut c, "UPDATE c SET n = n + 1 WHERE id = 1");
                }
            });
        }
    });

    let mut check = Connection::open(&url).unwrap();
    assert_eq!(
        scalar_i64(&mut check, "SELECT n FROM c WHERE id = 1"),
        (WRITERS * PER_WRITER) as i64,
        "no update may be lost under group commit"
    );

    let _ = fs::remove_file(&p);
}

#[test]
fn concurrent_same_key_inserts_never_duplicate() {
    // Two writers race to insert the same primary key many times. Exactly one of
    // each pair may win; the loser sees a UNIQUE/conflict error. The committed
    // state must never contain a duplicate key. Since the primary key is enforced
    // and both writers attempt every key, COUNT(*) == KEYS proves each of the
    // KEYS distinct keys is present exactly once.
    const KEYS: usize = 200;

    let p = db_path("samekey");
    let url = url_for(&p);
    {
        let mut setup = Connection::open(&url).unwrap();
        setup
            .exec("CREATE TABLE u (id INTEGER PRIMARY KEY, who INTEGER)")
            .unwrap();
    }

    let barrier = Barrier::new(2);
    thread::scope(|s| {
        for who in 0..2 {
            let url = &url;
            let barrier = &barrier;
            s.spawn(move || {
                let mut c = Connection::open(url).unwrap();
                barrier.wait();
                for id in 0..KEYS {
                    // One of the two racers wins each key; tolerate the loss
                    // (constraint or conflict), never retry into a duplicate.
                    match c.exec(&format!("INSERT INTO u (id, who) VALUES ({id}, {who})")) {
                        Ok(()) => {}
                        Err(e)
                            if matches!(
                                e.status,
                                EngineStatus::ErrConstraint | EngineStatus::ErrConflict
                            ) => {}
                        Err(e) => panic!("unexpected error: {e:?}"),
                    }
                }
            });
        }
    });

    let mut check = Connection::open(&url).unwrap();
    assert_eq!(
        scalar_i64(&mut check, "SELECT COUNT(*) FROM u"),
        KEYS as i64,
        "exactly one row per key — no duplicate may commit"
    );

    let _ = fs::remove_file(&p);
}

/// Concurrent *cold* opens of one database (a burst of pgwire connections, or a
/// pooler filling its backend set) must converge on a single storage handle.
/// Two live `LocalFileStorage` handles over one file each keep a private append
/// offset, and opening one heals a "torn" tail that may be the other's
/// in-flight write — truncating it, so the surviving writer's acked commits
/// land past a gap that the next cold open's recovery stops at (and discards).
/// Every commit acked through the concurrently-opened handles must survive a
/// cold reopen.
#[test]
fn concurrent_cold_opens_lose_no_acked_commit() {
    const OPENERS: usize = 8;
    const ROWS_PER_OPENER: usize = 10;
    for round in 0..100 {
        let p = db_path("cold-open");
        let url = url_for(&p);
        {
            let mut c = Connection::open(&url).unwrap();
            c.exec("CREATE TABLE t (id INTEGER PRIMARY KEY)").unwrap();
        } // the last handle drops: the database is cold again

        let opened = Barrier::new(OPENERS);
        let start = Barrier::new(OPENERS);
        thread::scope(|s| {
            for w in 0..OPENERS {
                let (url, opened, start) = (&url, &opened, &start);
                s.spawn(move || {
                    opened.wait(); // every handle cold-opens at once
                    let mut c = Connection::open(url).unwrap();
                    start.wait(); // all held open together, then write
                    for i in 0..ROWS_PER_OPENER {
                        let id = w * ROWS_PER_OPENER + i;
                        exec_retrying(&mut c, &format!("INSERT INTO t VALUES ({id})"));
                    }
                });
            }
        });

        // Every handle has dropped: this replays from the file.
        let mut c = Connection::open(&url).unwrap();
        assert_eq!(
            scalar_i64(&mut c, "SELECT COUNT(*) FROM t"),
            (OPENERS * ROWS_PER_OPENER) as i64,
            "round {round}: an acked commit was lost across concurrent cold opens"
        );
        drop(c);
        let _ = fs::remove_file(&p);
    }
}
