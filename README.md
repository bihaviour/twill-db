# Twill DB

> DB Management System with separated process and storage layer. Built on Rust, and compatible with PostgreSQL.

**Status: design / specification stage.** This repository currently holds the development specifications; the Rust engine implementation follows the roadmap below.

## What this is

**Twill DB** is an OLTP database engine that is, at the same time:

- **Embeddable** — links in-process as a library, at function-call latency (SQLite-style), and
- **Storage-disaggregated** — durable state lives on object storage (S3 / Cloudflare R2 / MinIO), so compute is stateless.

These usually pull in opposite directions. The resolution is to keep the engine a **library** and make its **storage backend pluggable**, pointing the seam at the network instead of a local file — rather than putting a server at the boundary. The *same* engine then runs embedded (via FFI) **or** as a **PostgreSQL wire-compatible server**; the storage choice is configuration, not a rebuild.

Headline properties: **scale-to-zero**, **true embeddability**, and **instant branching** (copy-on-write over LSN-versioned immutable layers).

## Architecture at a glance

- **Engine (Rust library)** — SQL parser → planner → executor, MVCC (snapshot isolation via LSN-stamped versions), WAL generation, and a local page cache. Ships as `cdylib` + `staticlib` with a stable C ABI (`engine.h`), plus an `engine-server` binary.
- **Pluggable `Storage` trait** — the central seam. Two backends: `LocalFileStorage` (pure embedded, zero network) and `ObjectStorage` (disaggregated).
- **Object-storage backend** — an LSM page store (versioned by LSN) plus an ordered commit log whose durability bottoms out on **S3 conditional writes (compare-and-swap)** — atomic ordered appends and single-writer fencing without a separate consensus cluster.
- **Interfaces** — embedded via `bun:ffi` / NAPI; server via the **Postgres wire protocol**, so existing tooling (PostgREST, `Bun.sql`, standard `psql`/pg drivers) connects unchanged.

## Specifications

The full development spec is a self-contained HTML site under [`specs/`](specs/). Open [`specs/index.html`](specs/index.html) in a browser, or serve the folder locally:

```bash
cd specs && python3 -m http.server
# then visit http://localhost:8000
```

Selected documents:

| Spec | |
|---|---|
| [Architecture Overview](specs/01-architecture-overview.html) | The three slots and inter-layer protocols |
| [Engine Core](specs/02-engine-core.html) | C ABI, MVCC, WAL, execution pipeline |
| [Storage Interface](specs/03-storage-interface.html) | The pluggable `Storage` trait (the seam) |
| [Object-Storage Backend](specs/04-object-storage-backend.html) | LSM page store + S3-CAS commit log |
| [Benchmark & Validation Plan](specs/09-benchmark-plan.html) | Latency/throughput/crash-safety experiments |
| [Roadmap & Build Sequence](specs/13-roadmap.html) | Phased delivery plan |

## Roadmap

1. **Embedded library first** — `bun:ffi` + `LocalFileStorage`. Fastest path to a working demo, zero infra.
2. **Add `ObjectStorage`** — LSM-on-S3 page store + S3-CAS commit log → disaggregated + scale-to-zero, still embedded.
3. **Add `engine-server` + Postgres wire protocol** — remote/server mode for multi-client and tools that expect Postgres.
4. **Add the controller** — idle stop + branch-on-LSN → scale-to-zero and instant clones.

See the [full roadmap](specs/13-roadmap.html) for milestones, dependencies, and exit criteria.

## License

Licensed under the **GNU Affero General Public License v3.0** (AGPL-3.0). See [`LICENSE`](LICENSE).

If you run a modified version of this software as a network service, the AGPL requires you to make your modified source available to its users.
