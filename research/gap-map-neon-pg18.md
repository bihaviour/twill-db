# Twill DB gap map: Neon `release-9129` and PostgreSQL 18.6

_Compiled 2026-10-18 against twill-db `2af9fc1` (workspace 0.5.1). Updated after [#128](https://github.com/bihaviour/twill-db/pull/128) and [#129](https://github.com/bihaviour/twill-db/pull/129) merged (`e6d02f3`); resolved items are marked **RESOLVED**._

| Reference | Pinned at | Why this pin |
|---|---|---|
| PostgreSQL | `REL_18_6` (`724edf9`) | Latest stable tag; 19 is still at `REL_19_BETA3` |
| Neon | `release-9129` (`5340423`) | Head of Neon's `release` branch, its latest stable storage release |
| Twill DB | `2af9fc1` | `main` as of this worktree |

**Method.** The comparison was made by reading the source of all three trees. Each row below cites code or tests in both the reference and Twill. Rows marked ✔︎ were re-checked by hand at the cited line. We did not use REA, the reverse-engineering MCP. It analyses binaries and Electron/JS bundles and cannot diff source repos. It is also only registered for the `bunda-iam` project.

**Legend.** HAS = equivalent behaviour. PARTIAL = some of the behaviour. MISSING = no equivalent. BY DESIGN = left out on purpose; the Twill spec states the decision. Rank says how much the gap matters for Twill's own stated goals.

---

## 1. Headline findings

These are things the code does that the docs and specs do not say.

1. ✔︎ **`s3://`, `r2://` and `gs://` are a local directory.** `ObjectStorage::open` serves all three from `FsObjectStore` under `$TWILL_OBJECT_ROOT`, which defaults to a temp dir (`crates/storage/src/object/mod.rs:198`). The storage crate has no HTTP or S3 client dependency. The "disaggregated" backend has never talked to a real bucket.
2. ✔︎ **All rows live in RAM, and every open replays the WAL from LSN 0** (`crates/engine/src/db.rs:397`). Nothing calls `set_retention_floor`, so compaction and GC never run and the log never shrinks. As a result:
   - cold-start time grows with the total write history;
   - database size is bounded by RAM;
   - dead MVCC row versions are never pruned (`store.rs` calls `retain` only on rollback).
3. ✔︎ **Scale-to-zero is not wired into anything you can deploy.** Only `crates/bench` depends on `twill-controller`. `engine-server` and `twilldb serve` do not use it.
4. **RESOLVED in #129.** ~~The real PostgREST path drops the RLS identity.~~ The original finding: PostgREST sends `SELECT set_config('role', …), set_config('request.jwt.claims', …)`. The server answers it with canned empty rows (`crates/server/src/introspect.rs:382`), so requests run as `anon`. This contradicts the spec 17 MUST. Only explicit `SET` statements are tested (`tests/wire.rs`).
5. **Any pgwire client can bypass RLS.** The server uses trust auth, and `SET twill.rls.bypass = on` or `SET ROLE <anything>` needs no privilege (`conn.rs:220`).
6. **RESOLVED in #129.** ~~Errors come back with the wrong SQLSTATE.~~ The original finding: Unique, NOT NULL, CHECK and RLS violations all return `42601` (syntax error) (`crates/server/src/session.rs:1214`). ORMs that branch on `23505`, `23502`, `23514` or `42501` misbehave.
7. ✔︎ **`SERIALIZABLE` silently runs as snapshot isolation**, so write skew is possible. **`BEGIN READ ONLY` still allows writes.** Both are parsed and then ignored (`crates/engine/src/sql.rs:1065`).
8. **Latent GC/branch bug.** `set_retention_floor` (`object/mod.rs:960`) does not clamp the floor to live branch fork points. `get_page` refuses reads below the floor (`:669`). Spec 04 requires that GC never drop a layer a retained branch still references. Nothing calls it today, so the bug is latent.

**Found and fixed during follow-up work**

- **Non-ASCII string literals were garbled by the lexer.** Fixed in [#128](https://github.com/bihaviour/twill-db/pull/128).
- **Concurrent cold opens could lose acked commits on disk.** This was a durability bug on `main`, surfaced by CI on #129. Fixed in [#129](https://github.com/bihaviour/twill-db/pull/129), commit `552b2e5`.

---

## 2. Twill vs Neon (architecture and serverless)

| Area | Neon | Twill | Class | Rank |
|---|---|---|---|---|
| WAL durability | Safekeeper Paxos quorum (`safekeeper/src/safekeeper.rs`); S3 offload (`wal_backup.rs`) | One fsync (file) or put-if-absent CAS segment (object); group commit | BY DESIGN (spec 04: no Raft/Paxos) | — |
| Real object-store client | `libs/remote_storage` (S3/Azure/GCS) | ✔︎ Local `FsObjectStore` only; R2-binding adapter for WASM | MISSING | **High** |
| Bounded recovery / checkpoint | basebackup at an LSN; `remove_wal.rs` trims offloaded WAL | ✔︎ Full replay from genesis; log never truncated | MISSING | **High** |
| Page reconstruction | `walredo.rs`, `timeline.rs::get_vectored` | Row store not paged; size bounded by RAM | PARTIAL (walredo itself is BY DESIGN) | Med |
| Layers / compaction / GC | Delta and image layers with B-tree index; L0→L1 compaction; deletion queue | Flat CRC'd layers; `compact()`/`gc()` exist but are never scheduled; no manifest (discovery by LIST) | PARTIAL | Med |
| GC vs branches | `gc_info.insert_child` keeps ancestor LSNs | Retention floor ignores branch fork points (finding 8) | PARTIAL (bug) | Med |
| Branching | Any LSN, any ancestry, `detach_ancestor`, offload | O(1) copy-on-write overlay. The seam accepts any `base_lsn`, but the API forks only at the committed LSN; no branch-of-branch | PARTIAL | Med |
| PITR / time travel | `pitr_interval`, `find_lsn_for_timestamp`, LSN leases | `pitr_floor` exists but nothing calls it; no timestamp→LSN index; no AS-OF reads | PARTIAL | **High** |
| Read replicas / hot standby | Hot standby, `compute_promote.rs` | None (spec 05 out of scope) | MISSING | Med |
| HA / failover | SK quorum, storage-controller heartbeats, secondary locations | Fence take-over by epoch bump; no failure detector or standby | PARTIAL | Med |
| Sharding | `ShardIdentity`, shard split | Many small DBs instead (spec 14) | BY DESIGN | Low |
| Multi-tenancy | Throttle, eviction, per-tenant config | One `--db` per server process; `database` startup param ignored | PARTIAL | Med |
| Tenant relocation / heatmaps | Live migrate with prewarm | Stop, then cold-start elsewhere | PARTIAL | Low |
| Proxy and auth | SNI routing, SCRAM, JWT/JWKS, SQL-over-HTTP, websockets, pooling, cancellation | Cleartext, trust auth, no CancelRequest, no HTTP/WS endpoint (spec 07 says SHOULD) | MISSING (JWT verification is composed, BY DESIGN) | **High** |
| Compute lifecycle | `compute_ctl`, LFC prewarm, basebackup cache | ✔︎ State machine and herd admission exist, but only bench uses them; cold start = full replay | PARTIAL | **High** |
| Local file cache | `pgxn/neon/file_cache.c` | Spec 05 marks it MUST; not built | MISSING | Med (High once paged) |
| Autoscaling | `vm_monitor` | Host process sizes itself (spec 11) | BY DESIGN | Low |
| Scrubber / integrity | `storage_scrubber` (find garbage, scan metadata, physical GC) | CRCs only; no offline verifier | MISSING | Med |
| Observability | Rich metrics, consumption metrics, tenant size | Prometheus `/metrics`, `Storage::stats`, `EngineStats` | PARTIAL | Low |
| Storage control plane | `storage_controller`, `storage_broker` | Controller owns no durable state; bucket LIST acts as the catalog | BY DESIGN | Low |
| Testing | 150+ pytest regress files, deterministic simulation (`libs/desim`) | C1–C8 conformance, seeded crash gate, branching battery; nothing against a real store | PARTIAL | Med |

---

## 3. Twill vs PostgreSQL 18.6 (SQL, protocol, compatibility)

PG 18.6 has 112 built-in types, 3,397 functions, about 124 statement productions and 7 access methods. Twill has about 27 statement kinds, 5 storage classes plus `vector(N)`, and about 70 functions.

### 3a. SQL surface

| Capability | Twill | Rank |
|---|---|---|
| CRUD, RETURNING, ON CONFLICT, INSERT…SELECT, UPDATE FROM, DELETE USING | HAS | — |
| Joins (inner/left/right/full/cross), non-recursive CTEs, set ops, DISTINCT, GROUP BY/HAVING, views | HAS (nested-loop only) | — |
| Correlated subqueries | PARTIAL: one level deep, not under aggregation | Med |
| ✔︎ Transactional DDL | MISSING: DDL is autocommit only (`conn.rs:730`) | **High** |
| ✔︎ `CREATE [UNIQUE] INDEX` (btree) | MISSING: only `USING hnsw` (`sql.rs:1407`) | **High** |
| Schema-qualified names (`"public"."t"`), `CREATE SCHEMA` | MISSING (only PostgREST's datapath strips `public`) | **High** |
| `ALTER TABLE` | PARTIAL: add/drop/rename column, rename table, RLS on/off. No ADD CONSTRAINT, ALTER TYPE, or SET/DROP NOT NULL / DEFAULT | **High** |
| `GENERATED … AS IDENTITY`; STORED and PG18 VIRTUAL generated columns | MISSING | **High** / Med |
| FK enforcement, CASCADE | MISSING: metadata only | **High** |
| Sequences (`nextval`), TRUNCATE, COMMENT ON | MISSING | Med |
| `SELECT … FOR UPDATE/SKIP LOCKED`, LOCK TABLE, advisory locks | MISSING | **High** |
| Window functions, recursive CTEs, LATERAL, GROUPING SETS | BY DESIGN (spec 16: compose DuckDB) | Med |
| Functions, procedures, triggers, PL/pgSQL, extensions, MERGE, domains/enums | BY DESIGN | Med |
| PG18: `uuidv7()`, OLD/NEW in RETURNING, `WITHOUT OVERLAPS`, `NOT ENFORCED` | MISSING (`NOT ENFORCED` already matches how Twill FKs behave) | Low–Med |

### 3b. Types and functions

| Capability | Twill | Rank |
|---|---|---|
| int2/4/8 | PARTIAL: all i64, and INTEGER is reported on the wire as int8 (node-postgres then returns strings) | Med–High |
| numeric/decimal | PARTIAL: stored as f64 | **High** |
| date/time/timestamptz/interval | PARTIAL: stored as text or epoch, sent with a text OID, no INTERVAL | **High** |
| bool, uuid, json/jsonb | PARTIAL: stored as 0/1 or text; no native OIDs | Med |
| Arrays (`= ANY($1)`, `text[]`) | BY DESIGN | **High** for ORMs |
| JSON operators `@>`, `#>`, `?`, `jsonb_set`, jsonpath | MISSING (has `->`, `->>`, `json_build_*`) | Med |
| Aggregates `array_agg`, `bool_and/or`, stddev | MISSING | Med |
| Set-returning `generate_series`, `unnest`, `json_each` | MISSING | Med |
| `IS DISTINCT FROM`, `= ANY/ALL` | MISSING | Med |
| Regex, full-text search | BY DESIGN | Med |
| `vector(N)` + HNSW | HAS (pgvector-equivalent) | — |

### 3c. Transactions, wire protocol, security

| Capability | Twill | Rank |
|---|---|---|
| REPEATABLE READ (= SI) | HAS | — |
| ✔︎ SERIALIZABLE (SSI) | PARTIAL: silently runs as SI | **High** |
| READ COMMITTED | PARTIAL: runs as SI and raises 40001 where Postgres would block and continue | **High** |
| ✔︎ READ ONLY transactions | PARTIAL: ignored, writes allowed | Med |
| Simple and extended query, text and binary formats | HAS | — |
| SQLSTATE fidelity | **RESOLVED in #129**: constraint and RLS violations now return proper codes | — |
| pg_catalog / information_schema | PARTIAL: canned PostgREST/psql answers; anything else returns 0A000 (breaks Prisma/Drizzle introspection and psql `\d`) | **High** |
| TLS, SCRAM/MD5, PG18 OAuth | MISSING: cleartext, trust only | **High** |
| CancelRequest | MISSING: dropped | Med |
| COPY | MISSING | Med |
| LISTEN/NOTIFY | PARTIAL: LISTEN is acked but nothing is ever delivered (silent) | Med |
| Protocol 3.2 (PG18) | MISSING: 3.0 only | Low |
| RLS USING/WITH CHECK, default-deny | HAS | — |
| RLS RESTRICTIVE, FORCE, ALTER POLICY | MISSING | Med |
| Roles, GRANT/REVOKE | BY DESIGN | Med |
| Planner, statistics, EXPLAIN ANALYZE | MISSING: fixed EXPLAIN string, no cost model | Med |
| VACUUM | MISSING: no-op, no version GC | Med |
| Replication (physical/logical), partitioning, TOAST, collations | BY DESIGN or N/A | Low |

---

## 4. Recommended order

Each group unblocks the one after it.

**A. Make the serverless claim true (Neon axis)**

1. Real S3/R2 `ObjectStore` using `If-None-Match` / `If-Match` conditional writes, behind the existing client seam. Add a MinIO CI job and run the crash gate against it.
2. Row-store checkpoint (image pages at an LSN). Replay only from the checkpoint, then let GC drop old log segments. This bounds cold start and storage.
3. Clamp the retention floor to live branch fork points and add a branching-battery test (finding 8).
4. Wire `twill-controller` into `engine-server` / `twilldb serve`.
5. PITR: a commit-timestamp→LSN index, branch-at-LSN/timestamp in the CLI and ABI, and a retention window.

**B. Make it safe to expose (both axes)**

6. TLS + SCRAM-SHA-256 and CancelRequest in `engine-server`. Gate the RLS bypass and `SET ROLE` behind an authenticated privilege.
7. ~~Forward PostgREST's `set_config('role' / 'request.jwt.claims')` to the engine session (finding 4).~~ Done in #129.

**C. Postgres-client compatibility (PG axis, cheapest first)**

8. ~~Map SQLSTATEs: 23505, 23502, 23514, 23503, 42501.~~ Done in #129.
9. Reject or honour `SERIALIZABLE` and `READ ONLY` instead of silently ignoring them.
10. Accept `public.`-qualified names and plain `CREATE [UNIQUE] INDEX`, and map `GENERATED AS IDENTITY` to AUTOINCREMENT.
11. Transactional DDL. This is the largest blocker for migration tools.
12. Real `pg_catalog` reflection for ORM introspection.
13. Advisory locks and `FOR UPDATE`.
14. Native temporal and decimal types with correct OIDs.
15. FK enforcement.

---

## 5. Places where the docs and the code disagree

- `CLAUDE.md` and spec 16 say `STORAGE_TRAIT_VERSION` is 2; the code has 3 (`crates/storage/src/lib.rs:59`).
- `CLAUDE.md` describes `s3://` as running on object storage; it runs on a local directory (finding 1).
- The Phase-2 roadmap marks the local cache as MUST; it is not implemented.
- Spec 16 is stale in three places:
  - GROUP BY is listed as missing; it shipped in 6B.
  - The LIKE/ILIKE case split is listed as deferred; it shipped.
  - The CREATE INDEX wording does not match the code.
- The `crates/server/src/datapath.rs:11` header says the engine lacks CTEs and subqueries; it has them.
- ~~The docs present RLS as working with unmodified PostgREST; the identity preamble is stubbed (finding 4).~~ Fixed in #129.
