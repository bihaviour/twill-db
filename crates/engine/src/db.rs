//! Shared per-database state: the storage backend, the single-writer fence
//! token, the MVCC store, and the write lane that serializes writers.
//!
//! Multiple connections (engine handles) to the *same* URL share one
//! `Database` via a process-global registry, so a writer on one handle and a
//! reader on another see consistent MVCC snapshots within the process. On open
//! the engine acquires the single-writer fence and replays the durable WAL to
//! rebuild in-memory state (spec 02 — "on restart, WAL replay determines
//! outcome").

use crate::error::{EngineError, EngineStatus, Result};
use crate::group_commit::GroupCommit;
use crate::store::Store;
use crate::wal::WalOp;
use std::collections::HashMap;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock, PoisonError, RwLock, Weak};
use twill_storage::{
    block_on, open_branch as storage_open_branch, open_storage, BranchId, FenceToken, Lsn, PageId,
    Storage, WriterId, PAGE_SIZE,
};

/// A simple counting write lane: at most one writer holds it at a time. Held
/// across the statements of a write transaction; released on commit/rollback.
/// Not tied to a guard lifetime, so a connection can hold it across FFI calls.
///
/// The lane is the one point every write to a database serializes through
/// (single-writer-per-DB). It carries read-only contention counters so the
/// spec-10 hot-row routing decision is *observable* (EX-4 / #103): how many
/// writers had to wait behind another, and for how long. The counters never
/// change the lane's behaviour — they only surface what already happens.
pub struct WriteLane {
    locked: Mutex<bool>,
    cv: Condvar,
    /// Write-lane acquisitions (≈ write transactions) — the denominator of the
    /// serialized-handoff rate.
    acquires: AtomicU64,
    /// Acquisitions that had to wait because another writer already held the
    /// lane: the per-DB **serialized-handoff** count (spec 10). Because every
    /// write funnels through this one lane, a rising handoff share is the
    /// hot-row contention signal the per-tool placement decision keys on.
    handoffs: AtomicU64,
    /// Cumulative microseconds writers spent blocked waiting for the lane.
    wait_us_total: AtomicU64,
}

impl WriteLane {
    fn new() -> WriteLane {
        WriteLane {
            locked: Mutex::new(false),
            cv: Condvar::new(),
            acquires: AtomicU64::new(0),
            handoffs: AtomicU64::new(0),
            wait_us_total: AtomicU64::new(0),
        }
    }
    pub fn acquire(&self) {
        self.acquires.fetch_add(1, Ordering::Relaxed);
        let mut g = self.locked.lock().unwrap();
        if *g {
            // Contended: another writer holds the lane. This wait *is* a
            // serialized handoff — count it and time how long we block.
            self.handoffs.fetch_add(1, Ordering::Relaxed);
            let start = std::time::Instant::now();
            while *g {
                g = self.cv.wait(g).unwrap();
            }
            let us = start.elapsed().as_micros() as u64;
            self.wait_us_total.fetch_add(us, Ordering::Relaxed);
        }
        *g = true;
    }
    pub fn release(&self) {
        let mut g = self.locked.lock().unwrap();
        *g = false;
        self.cv.notify_one();
    }

    /// `(acquires, handoffs, wait_us_total)`: total lane acquisitions, the
    /// contended subset (serialized handoffs), and cumulative wait microseconds.
    /// Read-only observation for the spec-10 hot-row decision (EX-4).
    pub(crate) fn stats(&self) -> (u64, u64, u64) {
        (
            self.acquires.load(Ordering::Relaxed),
            self.handoffs.load(Ordering::Relaxed),
            self.wait_us_total.load(Ordering::Relaxed),
        )
    }
}

/// Read-only engine + storage observability snapshot (#53 / spec 15). Pulled by
/// Twill Bench and a future OTLP exporter at scenario boundaries; cumulative, so
/// a consumer takes the delta between two pulls.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EngineStats {
    /// Transactions committed durably (the group-commit `commits` counter).
    pub commits: u64,
    /// Durable WAL appends (group-commit batches). `commits > durable_appends`
    /// proves coalescing engaged — the W1 lever (spec 09 Experiment 2).
    pub durable_appends: u64,
    /// Highest committed (visible) LSN — a gauge, not a counter.
    pub committed_lsn: u64,
    /// Write-lane acquisitions (≈ write transactions) — the denominator of the
    /// serialized-handoff rate (EX-4 / spec 10 hot-row contention).
    pub write_acquires: u64,
    /// Acquisitions that had to wait for another writer: the per-DB
    /// **serialized-handoff** count. Single-writer-per-DB funnels every write
    /// through one lane, so `write_handoffs / write_acquires` is the hot-row
    /// contention rate the per-tool routing decision keys on (spec 10).
    pub write_handoffs: u64,
    /// Cumulative microseconds writers spent blocked on the write lane — the
    /// wait-time signal paired with the handoff count.
    pub write_wait_us_total: u64,
    /// The backend's counters, pulled through the seam (`Storage::stats`).
    pub storage: twill_storage::StorageStats,
}

pub struct Database {
    pub(crate) storage: Box<dyn Storage>,
    pub(crate) token: FenceToken,
    pub(crate) store: RwLock<Store>,
    pub(crate) lane: WriteLane,
    /// Coalesces concurrent commits into one durable append (spec 02/09 — the W1
    /// lever). See [`crate::group_commit`].
    pub(crate) group_commit: GroupCommit,
    key: String,
    /// The URL this database was opened from (the base URL for a branch).
    url: String,
    /// `Some(id)` if this handle is a copy-on-write branch view, else the root.
    branch: Option<BranchId>,
    /// Set once a lease renewal observes that a newer writer fenced us; commits
    /// then fail fast (the storage append would reject them anyway).
    fenced: AtomicBool,
    /// VH-1 observability: vector indexes warmed from a page checkpoint (rather
    /// than rebuilt from the rows) on this database's cold open. Purely a counter
    /// for tests / stats; the warm result is identical either way.
    index_pages_loaded: AtomicU64,
}

fn registry() -> &'static Mutex<HashMap<String, Weak<Database>>> {
    static REG: OnceLock<Mutex<HashMap<String, Weak<Database>>>> = OnceLock::new();
    REG.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Per-key build locks: at most one `Database` is built for a key at a time.
/// Building opens a fresh storage handle and acquires the fence, and two live
/// handles over one `file://` log each keep a private append offset — worse,
/// opening one heals a "torn" tail that may be the other's in-flight frame,
/// truncating it so the surviving writer's acked commits land past a gap the
/// next recovery stops at. Serializing builds per key (not globally, so cold
/// opens of different databases still warm in parallel) means concurrent
/// openers wait for the first build and then share it.
fn build_locks() -> &'static Mutex<HashMap<String, Arc<Mutex<()>>>> {
    static LOCKS: OnceLock<Mutex<HashMap<String, Arc<Mutex<()>>>>> = OnceLock::new();
    LOCKS.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Return the live shared `Database` for `key`, or build one with `build`
/// under the key's build lock and register it.
fn shared_or_build(key: &str, build: impl FnOnce() -> Result<Database>) -> Result<Arc<Database>> {
    let live = |key: &str| registry().lock().unwrap().get(key).and_then(Weak::upgrade);
    if let Some(existing) = live(key) {
        return Ok(existing);
    }
    // Clones of a build lock are only taken under the map lock, so a lock
    // whose only reference is the map's can be dropped from it safely.
    let lock = Arc::clone(
        build_locks()
            .lock()
            .unwrap()
            .entry(key.to_string())
            .or_default(),
    );
    let result = {
        let _guard = lock.lock().unwrap_or_else(PoisonError::into_inner);
        // Re-check under the build lock: a concurrent opener may have just
        // built it (every registry insert for this key happens under this lock).
        // (`live` drops its registry guard before `build` runs and re-locks it.)
        match live(key) {
            Some(existing) => Ok(existing),
            None => build().map(|db| {
                let db = Arc::new(db);
                registry()
                    .lock()
                    .unwrap()
                    .insert(key.to_string(), Arc::downgrade(&db));
                db
            }),
        }
    };
    let mut locks = build_locks().lock().unwrap();
    drop(lock);
    if locks.get(key).is_some_and(|l| Arc::strong_count(l) == 1) {
        locks.remove(key);
    }
    result
}

/// Allocate a fresh in-flight-writer id, unique among concurrently committing
/// transactions (it tags their pending store versions through group commit).
/// `0` is reserved for "fully committed", so ids start at `1`.
pub(crate) fn next_owner() -> u64 {
    static OWNER: AtomicU64 = AtomicU64::new(1);
    let id = OWNER.fetch_add(1, Ordering::Relaxed);
    if id == 0 {
        // Astronomically unlikely wrap; skip the reserved sentinel.
        OWNER.fetch_add(1, Ordering::Relaxed)
    } else {
        id
    }
}

fn next_writer_id() -> WriterId {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let pid = std::process::id() as u128;
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    let c = COUNTER.fetch_add(1, Ordering::Relaxed) as u128;
    WriterId((pid << 96) ^ (nanos << 16) ^ c)
}

/// Registry key: canonical absolute path for `file://` URLs; the URL otherwise.
fn registry_key(url: &str) -> String {
    if let Some(rest) = url.strip_prefix("file://") {
        let path = rest.split('?').next().unwrap_or(rest);
        match std::path::absolute(path) {
            Ok(p) => p.to_string_lossy().into_owned(),
            Err(_) => path.to_string(),
        }
    } else {
        url.to_string()
    }
}

impl Database {
    /// Open (or share) the database named by `url`, acquiring the writer fence
    /// and replaying the durable WAL.
    pub fn open(url: &str) -> Result<Arc<Database>> {
        let key = registry_key(url);
        shared_or_build(&key, || {
            let storage = open_storage(url)?;
            let token = block_on(storage.acquire_fence(next_writer_id()))?;

            let mut store = Store::default();
            replay(storage.as_ref(), &mut store)?;
            let committed = block_on(storage.get_commit_lsn())?;
            store.committed_lsn = store.committed_lsn.max(committed.0);
            let loaded = warm_vector_indexes(storage.as_ref(), &mut store);

            Ok(Database {
                storage,
                token,
                store: RwLock::new(store),
                lane: WriteLane::new(),
                group_commit: GroupCommit::new(),
                key: key.clone(),
                url: url.to_string(),
                branch: None,
                fenced: AtomicBool::new(false),
                index_pages_loaded: AtomicU64::new(loaded),
            })
        })
    }

    /// Open (or share) a copy-on-write branch of the database at `url`. The
    /// branch must already exist (created via `storage.create_branch`); its
    /// diverged state lives in a private overlay (see `twill_storage::
    /// open_branch`), so a branch writer never touches the base or siblings.
    pub fn open_branch(url: &str, branch: BranchId) -> Result<Arc<Database>> {
        let key = format!("{}#branch={}", registry_key(url), branch.0);
        shared_or_build(&key, || {
            let storage = storage_open_branch(url, branch)?;
            let token = block_on(storage.acquire_fence(next_writer_id()))?;

            let mut store = Store::default();
            replay(storage.as_ref(), &mut store)?;
            let committed = block_on(storage.get_commit_lsn())?;
            store.committed_lsn = store.committed_lsn.max(committed.0);
            let loaded = warm_vector_indexes(storage.as_ref(), &mut store);

            Ok(Database {
                storage,
                token,
                store: RwLock::new(store),
                lane: WriteLane::new(),
                group_commit: GroupCommit::new(),
                key: key.clone(),
                url: url.to_string(),
                branch: Some(branch),
                fenced: AtomicBool::new(false),
                index_pages_loaded: AtomicU64::new(loaded),
            })
        })
    }

    pub fn committed_lsn(&self) -> u64 {
        self.store.read().unwrap().committed_lsn
    }

    /// VH-1: checkpoint index `name`'s freshly built graph as page images through
    /// `put_page`, stamped with the committed LSN they reflect, so a later cold
    /// open can load the graph in bounded page reads instead of rebuilding it.
    /// Best-effort: any failure (an unpageable graph, a storage error) leaves the
    /// WAL-derived rebuild path as the source of truth.
    pub(crate) fn checkpoint_vector_index(&self, name: &str, reflected_lsn: u64) {
        let frames = self
            .store
            .read()
            .unwrap()
            .index_page_frames(name, reflected_lsn);
        let Some(frames) = frames else {
            return;
        };
        let region = index_page_region(name);
        for (i, frame) in frames.iter().enumerate() {
            if frame.len() > PAGE_SIZE {
                return;
            }
            if block_on(
                self.storage
                    .put_page(&self.token, PageId(region + i as u64), frame),
            )
            .is_err()
            {
                return;
            }
        }
    }

    /// VH-1 observability: vector indexes warmed from a page checkpoint on this
    /// database's cold open (vs. rebuilt from rows). The two warms are equivalent;
    /// this only lets callers/tests confirm the page path engaged.
    pub fn index_pages_loaded(&self) -> u64 {
        self.index_pages_loaded.load(Ordering::Relaxed)
    }

    /// Snapshot of every table's schema, for catalog reflection (spec 07).
    pub fn catalog(&self) -> Vec<crate::catalog::TableSchema> {
        self.store.read().unwrap().table_schemas()
    }

    /// Group-commit counters `(durable_appends, commits)`. Under concurrency
    /// `commits > durable_appends` means transactions coalesced into shared
    /// durable appends (the W1 lever; spec 09 Experiment 2). An observability
    /// hook — the commit/durability contract does not depend on it.
    pub fn group_commit_stats(&self) -> (u64, u64) {
        self.group_commit.metrics()
    }

    /// A read-only [`EngineStats`] snapshot — the engine-tier observability
    /// surface (#53 / spec 15). Folds the group-commit counters, the
    /// committed-LSN gauge, and the write-lane contention counters (the
    /// serialized-handoff count + wait time that make the spec-10 hot-row
    /// decision observable — EX-4 / #103) together with the backend's
    /// [`StorageStats`], pulled through the seam
    /// ([`twill_storage::Storage::stats`]), so a single pull on an engine handle
    /// yields all of them. Pure observation; the commit/durability contract and
    /// single-writer serialization do not depend on it.
    pub fn stats(&self) -> EngineStats {
        let (durable_appends, commits) = self.group_commit.metrics();
        let (write_acquires, write_handoffs, write_wait_us_total) = self.lane.stats();
        EngineStats {
            commits,
            durable_appends,
            committed_lsn: self.committed_lsn(),
            write_acquires,
            write_handoffs,
            write_wait_us_total,
            storage: self.storage.stats(),
        }
    }

    /// The URL this database (or its base, for a branch) was opened from.
    pub fn url(&self) -> &str {
        &self.url
    }

    /// Whether this handle is a branch view (branch-of-branch is rejected).
    pub fn is_branch(&self) -> bool {
        self.branch.is_some()
    }

    /// Durably renew this database's single-writer lease (the lifecycle
    /// controller's heartbeat). On `Fenced` — a newer writer took over — mark
    /// the database fenced so subsequent commits fail fast, and surface the
    /// error so the controller can step the instance down.
    pub fn renew_lease(&self) -> Result<()> {
        match block_on(self.storage.renew_fence(&self.token)) {
            Ok(_) => Ok(()),
            Err(e) => {
                if matches!(e, twill_storage::StorageError::Fenced { .. }) {
                    self.fenced.store(true, Ordering::SeqCst);
                }
                Err(commit_error(e))
            }
        }
    }

    /// True once a lease renewal observed this writer was fenced by a newer one.
    pub fn is_fenced(&self) -> bool {
        self.fenced.load(Ordering::SeqCst)
    }
}

impl Drop for Database {
    fn drop(&mut self) {
        // Best-effort: drop the registry entry and release the fence.
        if let Ok(mut reg) = registry().lock() {
            if let Some(w) = reg.get(&self.key) {
                if w.strong_count() == 0 {
                    reg.remove(&self.key);
                }
            }
        }
        let _ = block_on(self.storage.release_fence(self.token.clone()));
    }
}

/// Rebuild the store by replaying durable WAL records, grouping each
/// transaction's ops up to its `Commit` marker and stamping the produced
/// versions with the marker's commit LSN. A trailing markerless group (an
/// incomplete transaction) is discarded.
fn replay(storage: &dyn Storage, store: &mut Store) -> Result<()> {
    let entries = block_on(storage.scan_wal(Lsn::ZERO))?;
    let mut group: Vec<WalOp> = Vec::new();
    for entry in entries {
        let op = WalOp::decode(&entry.record.bytes)?;
        match op {
            WalOp::Commit => {
                let commit_lsn = entry.lsn.0;
                for op in group.drain(..) {
                    apply_replay(store, op, commit_lsn);
                }
                store.committed_lsn = store.committed_lsn.max(commit_lsn);
            }
            other => group.push(other),
        }
    }
    // `group` non-empty here would be an incomplete trailing txn: discard. The
    // autoincrement counters are rebuilt from the recovered rows; the vector
    // indexes are warmed separately (after `committed_lsn` is finalized) so a page
    // checkpoint can be matched against the exact replayed head — see
    // [`warm_vector_indexes`].
    store.rebuild_autoinc();
    Ok(())
}

/// VH-1 page-id region for an index's checkpoint pages: an FNV-1a hash of the
/// (lowercased) index name placed in a high reserved band so it never overlaps a
/// row page, with the low 23 bits left for the per-index page offset. A hash
/// collision is harmless — the loader re-checks the index name in the page header
/// and falls back to a rebuild on any mismatch.
fn index_page_region(name: &str) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for b in name.to_ascii_lowercase().bytes() {
        h ^= b as u64;
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    (1u64 << 63) | ((h & 0xFF_FFFF_FFFF) << 23)
}

/// Warm every vector index after replay (spec 12 / VH-1): adopt a page-laid-out
/// checkpoint when one exists *and* exactly reflects the replayed head
/// (`reflected_lsn == committed_lsn`), otherwise rebuild the graph from the
/// recovered rows. Returns how many indexes were loaded from pages. The graph is
/// derived-from-WAL either way, so a stale, missing, or branch-private checkpoint
/// simply takes the rebuild path — correctness never depends on the pages.
fn warm_vector_indexes(storage: &dyn Storage, store: &mut Store) -> u64 {
    let committed = store.committed_lsn;
    let mut loaded = 0;
    for name in store.index_names() {
        let Some(def) = store.index_def(&name) else {
            continue;
        };
        match load_index_pages(storage, &def, committed) {
            Some(ix) => {
                store.adopt_index(ix);
                loaded += 1;
            }
            None => store.rebuild_one_index(&name),
        }
    }
    loaded
}

/// Try to reconstruct an index graph from its page checkpoint. `None` (→ rebuild)
/// on a missing/old/foreign/corrupt checkpoint.
fn load_index_pages(
    storage: &dyn Storage,
    def: &crate::vector::IndexDef,
    committed: u64,
) -> Option<crate::vector::VectorIndex> {
    let region = index_page_region(&def.name);
    let header = block_on(storage.get_page(PageId(region), Lsn(u64::MAX))).ok()?;
    let hdr = crate::vector::parse_page_header(&header.bytes[..])?;
    // Guard against a page-id-region collision and a stale checkpoint.
    if !hdr.name.eq_ignore_ascii_case(&def.name) || hdr.reflected_lsn != committed {
        return None;
    }
    let mut frames: Vec<Vec<u8>> = Vec::with_capacity(hdr.num_body_pages + 1);
    frames.push(header.bytes[..].to_vec());
    for i in 0..hdr.num_body_pages as u64 {
        let p = block_on(storage.get_page(PageId(region + 1 + i), Lsn(u64::MAX))).ok()?;
        frames.push(p.bytes[..].to_vec());
    }
    crate::vector::VectorIndex::from_page_frames(def.clone(), &frames)
}

fn apply_replay(store: &mut Store, op: WalOp, commit_lsn: u64) {
    match op {
        WalOp::CreateTable { schema } => store.replay_create(schema),
        WalOp::DropTable { name } => store.replay_drop(&name),
        WalOp::Insert { table, vid, values } => {
            store.replay_insert(&table, vid, values, commit_lsn)
        }
        WalOp::Delete { table, vid } => store.replay_delete(&table, vid, commit_lsn),
        // Index definitions are registered empty here; the graph is populated by
        // `rebuild_indexes` once all rows are present (order-independent).
        WalOp::CreateIndex { def } => store.register_index(def),
        WalOp::DropIndex { name } => {
            store.drop_index(&name);
        }
        // Schema-evolution ops reshape the catalog and rows (stage 6D).
        op @ (WalOp::AlterAddColumn { .. }
        | WalOp::AlterDropColumn { .. }
        | WalOp::AlterRenameColumn { .. }
        | WalOp::AlterRenameTable { .. }) => apply_alter(store, &op),
        // A view is reconstructed by re-parsing its stored statement text (it
        // parsed cleanly at CREATE time, so a malformed record is ignored rather
        // than aborting recovery).
        WalOp::CreateView { name, sql } => {
            if let Ok((crate::sql::Stmt::CreateView { query, .. }, _)) = crate::sql::parse(&sql) {
                store.replay_create_view(name, *query);
            }
        }
        WalOp::DropView { name } => store.replay_drop_view(&name),
        // Row-level-security catalog facts (Phase 7): additive, replayed like
        // views/constraints so policies branch / scale-to-zero / PITR-restore.
        WalOp::CreatePolicy { table, policy } => store.add_policy(&table, policy),
        WalOp::DropPolicy { table, name } => {
            store.drop_policy(&table, &name);
        }
        WalOp::SetRls { table, enabled } => store.set_rls(&table, enabled),
        WalOp::Commit => {}
    }
}

/// Apply an `ALTER TABLE` WAL op to the in-memory store — shared by the live DDL
/// path and replay (stage 6D). A newly added column backfills existing rows with
/// its `DEFAULT` (evaluated as a constant) or NULL.
pub(crate) fn apply_alter(store: &mut Store, op: &WalOp) {
    match op {
        WalOp::AlterAddColumn { table, column } => {
            let fill = column
                .default_sql
                .as_deref()
                .and_then(|s| crate::exec::eval_const_sql(s).ok())
                .unwrap_or(crate::value::Value::Null);
            store.add_column(table, column.clone(), fill);
        }
        WalOp::AlterDropColumn { table, column } => store.drop_column(table, column),
        WalOp::AlterRenameColumn { table, from, to } => store.rename_column(table, from, to),
        WalOp::AlterRenameTable { table, to } => store.rename_table(table, to),
        WalOp::SetRls { table, enabled } => store.set_rls(table, *enabled),
        _ => {}
    }
}

/// Map a storage error during commit to the engine's conflict/storage codes.
pub fn commit_error(e: twill_storage::StorageError) -> EngineError {
    use twill_storage::StorageError::*;
    let status = match &e {
        Fenced { .. } | Contended => EngineStatus::ErrConflict,
        _ => EngineStatus::ErrStorage,
    };
    EngineError::new(status, e.to_string())
}
