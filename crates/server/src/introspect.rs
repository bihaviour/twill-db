//! Canned answers for the connect-time introspection queries real clients issue
//! (spec 07 — "MUST answer the small set of introspection queries that Bun.sql
//! and PostgREST issue … failing this is the most common reason a wire-compatible
//! engine fails to connect").
//!
//! These are *not* engine features; they are protocol-handshake glue. Anything
//! not matched here falls through to the engine ([`Canned::Pass`]).

use engine::{CatalogTable, ColumnType, Value};

/// The server version string advertised in `ParameterStatus` and `version()`.
/// Clients parse the leading `MAJOR.MINOR`; we report a modern Postgres major.
pub const SERVER_VERSION: &str = "15.0";

/// The numeric form of [`SERVER_VERSION`] (`MAJOR*10000 + MINOR`), which
/// `server_version_num` / `current_setting('server_version_num')` report. This
/// is the first thing PostgREST probes on connect; failing it aborts startup.
pub const SERVER_VERSION_NUM: &str = "150000";

/// The outcome of inspecting a statement before it reaches the engine.
pub enum Canned {
    /// A canned result set (column names + rows) and a CommandComplete tag.
    /// `oids` is either empty (infer per-column from the values) or one explicit
    /// Postgres type OID per column (needed when a column carries pre-encoded
    /// binary, e.g. the schema-cache arrays).
    Rows {
        columns: Vec<String>,
        oids: Vec<i32>,
        rows: Vec<Vec<Value>>,
        tag: String,
    },
    /// A canned CommandComplete tag with no rows (e.g. `SET`).
    Tag(String),
    /// A schema-cache query the session must answer by reflecting the live
    /// catalog (the pure classifier here has no catalog access).
    Reflect(ReflectKind),
    /// The `twill.stats` observability surface (#53 / spec 15): the session must
    /// answer it by pulling the live [`engine::EngineStats`] snapshot (the pure
    /// classifier here has no engine access, exactly like `Reflect`).
    Stats,
    /// The `twill.catalog` / `twill.relationships` reflection surface (spec 19
    /// Milestone 3): a plain-text view of the live catalog the management CLI
    /// consumes over the wire to drive its `tables`/`describe`/`gen types`/
    /// `schema dump` commands. Resolved by the session against the live
    /// [`engine::Connection::catalog`], exactly like `Stats`/`Reflect` (which the
    /// pure classifier cannot reach). Distinct from `Reflect`, whose binary,
    /// PostgREST-query-shaped output is for PostgREST's schema cache, not a
    /// generic client.
    Catalog(CatalogKind),
    /// PostgREST's per-request `SELECT set_config(…), …` preamble, parsed into
    /// its calls. The session resolves any bound `$n` values, forwards the RLS
    /// principal (`role`, `request.jwt.claims`, `request.jwt.claim.*`) to the
    /// engine, and replies with one row echoing each value set.
    SetConfig(Vec<SetConfigCall>),
    /// Not intercepted — hand the statement to the engine.
    Pass,
}

/// One argument of a `set_config` call: a string literal or a bound `$n`.
#[derive(Debug, Clone, PartialEq)]
pub enum ConfigArg {
    Lit(String),
    Param(usize),
}

/// One `set_config(name, value, is_local)` call. `is_local` is not kept: the
/// engine's session principal has no transaction-local scope (an engine `SET
/// LOCAL` likewise lasts until overwritten), and PostgREST re-sends role +
/// claims at the start of every request, so each request replaces the last.
#[derive(Debug, Clone, PartialEq)]
pub struct SetConfigCall {
    pub name: ConfigArg,
    pub value: ConfigArg,
}

/// Which view of the live catalog the `twill.catalog` family reflects.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum CatalogKind {
    /// `twill.catalog` — one row per column: `(tbl, col, typ, notnull, pk)`.
    Columns,
    /// `twill.relationships` — one row per foreign key:
    /// `(tbl, name, cols, ftable, fcols)` (column lists comma-joined).
    Relationships,
}

/// Which PostgREST schema-cache query to reflect from the catalog.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum ReflectKind {
    /// The tables/columns/PK query (`pg_relation_is_updatable`).
    Tables,
    /// The foreign-key relationship query (`pg_constraint`, `contype='f'`),
    /// which PostgREST turns into resource-embedding relationships.
    Relationships,
}

/// The advertised value of a GUC / run-time setting, for `SHOW` and
/// `current_setting`. Unknown settings report empty (rather than erroring) for
/// maximum client compatibility.
fn setting_value(name: &str) -> &'static str {
    match name {
        "server_version" => SERVER_VERSION,
        "server_version_num" => SERVER_VERSION_NUM,
        "transaction isolation level"
        | "default_transaction_isolation"
        | "transaction_isolation" => "read committed",
        "transaction_read_only" => "off",
        "server_encoding" | "client_encoding" => "UTF8",
        "standard_conforming_strings" => "on",
        "search_path" => "\"$user\", public",
        "max_index_keys" => "32",
        "integer_datetimes" => "on",
        "datestyle" => "ISO, MDY",
        "timezone" => "UTC",
        _ => "",
    }
}

fn one_row(col: &str, value: &str) -> Canned {
    Canned::Rows {
        columns: vec![col.to_string()],
        oids: vec![],
        rows: vec![vec![Value::Text(value.to_string())]],
        tag: "SELECT 1".to_string(),
    }
}

/// A zero-row result with the given column names — used to satisfy introspection
/// queries that have no rows to return here (role settings, the schema cache
/// before catalog reflection lands). Empty rows carry no data, so the column
/// count is all the client decodes; no per-column binary encoding is needed.
fn empty_rows(columns: &[&str]) -> Canned {
    Canned::Rows {
        columns: columns.iter().map(|c| c.to_string()).collect(),
        oids: vec![],
        rows: vec![],
        tag: "SELECT 0".to_string(),
    }
}

/// Whether `s` (lowercased/trimmed) is a session statement that sets the RLS
/// principal — `SET [LOCAL|SESSION] ROLE …`, `SET … twill.jwt.claims` /
/// `request.jwt.claims` (PostgREST's GUC), `SET … twill.rls.bypass`, or the
/// matching `RESET`. These must reach the engine (identity composed at the
/// boundary, enforced in-core), unlike the other fire-and-forget `SET`s. Matched
/// precisely so an unrelated `SET` (which the engine's lexer may reject) is still
/// a no-op.
pub fn is_rls_session_stmt(s: &str) -> bool {
    let body = match s.strip_prefix("set ").or_else(|| s.strip_prefix("reset ")) {
        Some(b) => b.trim_start(),
        None => return false,
    };
    let body = body
        .strip_prefix("local ")
        .or_else(|| body.strip_prefix("session "))
        .map(str::trim_start)
        .unwrap_or(body);
    // The GUC name may be double-quoted (`"request.jwt.claims"`).
    let body = body.trim_start_matches('"');
    for name in [
        "role",
        "twill.jwt.claims",
        "request.jwt.claims",
        "twill.rls.bypass",
    ] {
        if let Some(after) = body.strip_prefix(name) {
            if after.is_empty()
                || after.starts_with(['"', ' ', '\t', '='])
                || after.starts_with(';')
            {
                return true;
            }
        }
    }
    false
}

/// The CommandComplete tag for a fire-and-forget session-setup command
/// (`SET` / `DISCARD` / `LISTEN` / `UNLISTEN`), or `None` if `s` is not one.
/// Drivers issue these on connect and ignore the reply; the engine has no GUCs
/// or pub/sub, so they are accepted as no-ops. Split out of `intercept` to keep
/// that classifier within the project's lizard complexity gate.
fn session_noop_tag(s: &str) -> Option<&'static str> {
    if s.starts_with("set ") || s == "begin read only" {
        Some("SET")
    } else if s.starts_with("discard ") {
        Some("DISCARD ALL")
    } else if s.starts_with("listen ") {
        Some("LISTEN")
    } else if s.starts_with("unlisten ") {
        Some("UNLISTEN")
    } else {
        None
    }
}

/// Whether `s` (already lowercased/trimmed) is one of the accepted spellings of
/// the `twill.stats` observability surface (#53). Split out of `intercept` to
/// keep that classifier's cyclomatic complexity within the project's lizard gate.
fn is_twill_stats_query(s: &str) -> bool {
    matches!(
        s,
        "show twill.stats"
            | "show twill_stats"
            | "select * from twill.stats"
            | "select * from twill_stats"
            | "table twill.stats"
            | "table twill_stats"
    )
}

/// Whether `s` (already lowercased/trimmed) is one of the accepted spellings of
/// the `twill.catalog` / `twill.relationships` reflection surface (spec 19
/// Milestone 3), and if so which view. Accepts `SHOW`, a `SELECT *`, or a bare
/// `TABLE`, with either the dotted or underscored name — the same vocabulary as
/// `twill.stats`. Kept separate from `intercept` so that classifier's cyclomatic
/// complexity stays within the project's lizard gate.
fn twill_catalog_query(s: &str) -> Option<CatalogKind> {
    let one = |name: &str| {
        matches!(s.strip_prefix("show ").map(str::trim), Some(n) if n == name)
            || matches!(s.strip_prefix("table ").map(str::trim), Some(n) if n == name)
            || matches!(
                s.strip_prefix("select * from ").map(str::trim),
                Some(n) if n == name
            )
    };
    if one("twill.catalog") || one("twill_catalog") {
        Some(CatalogKind::Columns)
    } else if one("twill.relationships") || one("twill_relationships") {
        Some(CatalogKind::Relationships)
    } else {
        None
    }
}

/// Format a live [`engine::EngineStats`] snapshot into the `twill.stats` result
/// set: `(metric TEXT, value BIGINT)`, one row per signal under the settled #53
/// vocabulary (spec 15). Pure formatting from a passed-in value — this module
/// never reaches the engine; the session pulls the snapshot and calls this. The
/// server reports the engine + storage families it can source from one process;
/// the compute/scheduler family joins it over a controller-driven deployment.
pub fn stats_rows(stats: &engine::EngineStats) -> Canned {
    let st = &stats.storage;
    let metrics: &[(&str, u64)] = &[
        // commit family
        ("twill_commit_total", stats.commits),
        ("twill_durable_append_total", stats.durable_appends),
        ("twill_committed_lsn", stats.committed_lsn),
        // write-contention family (EX-4 / spec 10 hot-row): per-DB serialized
        // handoffs + wait time, the signal the per-tool routing decision keys on.
        ("twill_write_lane_acquire_total", stats.write_acquires),
        ("twill_write_handoff_total", stats.write_handoffs),
        ("twill_write_wait_us_total", stats.write_wait_us_total),
        // storage family (pulled through the seam)
        ("twill_storage_wal_appends_total", st.wal_appends),
        ("twill_storage_wal_bytes_total", st.wal_bytes),
        ("twill_storage_page_reads_total", st.page_reads),
        ("twill_storage_page_read_bytes_total", st.page_read_bytes),
        ("twill_storage_cache_hits_total", st.cache_hits),
        ("twill_storage_cache_misses_total", st.cache_misses),
        (
            "twill_storage_fetch_latency_us_total",
            st.fetch_latency_us_total,
        ),
        ("twill_storage_fsync_total", st.fsyncs),
    ];
    let rows = metrics
        .iter()
        .map(|(name, v)| vec![Value::Text(name.to_string()), Value::Int(*v as i64)])
        .collect::<Vec<_>>();
    let n = rows.len();
    Canned::Rows {
        columns: vec!["metric".to_string(), "value".to_string()],
        oids: vec![],
        rows,
        tag: format!("SELECT {n}"),
    }
}

/// The lowercase SQL type keyword for an engine storage class — the spelling the
/// management CLI re-parses when it rebuilds the catalog from the wire (the
/// inverse of the parser's type mapping). Mirrors `render`/`schema` in the CLI so
/// a wire `schema dump` matches an embedded one.
fn sql_type_name(ty: ColumnType) -> String {
    match ty {
        ColumnType::Integer => "integer".to_string(),
        ColumnType::Real => "real".to_string(),
        ColumnType::Text => "text".to_string(),
        ColumnType::Blob => "blob".to_string(),
        ColumnType::Vector(n) => format!("vector({n})"),
    }
}

/// Resolve a `twill.catalog` / `twill.relationships` query against the live
/// catalog (the session calls this, exactly like [`stats_rows`]).
pub fn catalog_reflect(kind: CatalogKind, catalog: &[CatalogTable]) -> Canned {
    match kind {
        CatalogKind::Columns => catalog_columns_rows(catalog),
        CatalogKind::Relationships => catalog_relationships_rows(catalog),
    }
}

/// `twill.catalog`: one row per column, `(tbl, col, typ, notnull, pk, uniq,
/// dflt)`, in table then ordinal order. `notnull` / `pk` / `uniq` are `0`/`1`
/// integers; `dflt` is the column's `DEFAULT` SQL text (empty when none). The
/// trailing `uniq` / `dflt` are additive — older readers ignore them.
fn catalog_columns_rows(catalog: &[CatalogTable]) -> Canned {
    let mut rows = Vec::new();
    for t in catalog {
        for c in &t.columns {
            rows.push(vec![
                Value::Text(t.name.clone()),
                Value::Text(c.name.clone()),
                Value::Text(sql_type_name(c.ty)),
                Value::Int(c.not_null as i64),
                Value::Int(c.primary_key as i64),
                Value::Int(c.unique as i64),
                Value::Text(c.default_sql.clone().unwrap_or_default()),
            ]);
        }
    }
    let n = rows.len();
    Canned::Rows {
        columns: ["tbl", "col", "typ", "notnull", "pk", "uniq", "dflt"]
            .iter()
            .map(|c| c.to_string())
            .collect(),
        oids: vec![],
        rows,
        tag: format!("SELECT {n}"),
    }
}

/// `twill.relationships`: one row per foreign key, `(tbl, name, cols, ftable,
/// fcols)`, with the local/foreign column lists comma-joined.
fn catalog_relationships_rows(catalog: &[CatalogTable]) -> Canned {
    let mut rows = Vec::new();
    for t in catalog {
        for fk in &t.foreign_keys {
            rows.push(vec![
                Value::Text(t.name.clone()),
                Value::Text(fk.name.clone()),
                Value::Text(fk.columns.join(",")),
                Value::Text(fk.foreign_table.clone()),
                Value::Text(fk.foreign_columns.join(",")),
            ]);
        }
    }
    let n = rows.len();
    Canned::Rows {
        columns: ["tbl", "name", "cols", "ftable", "fcols"]
            .iter()
            .map(|c| c.to_string())
            .collect(),
        oids: vec![],
        rows,
        tag: format!("SELECT {n}"),
    }
}

/// Parse `SELECT set_config(<arg>, <arg>, <bool>)[, …]` where each `<arg>` is a
/// `'string'` literal or a `$n` parameter (optionally `::type`-cast). Returns
/// `None` for anything else, so an unexpected shape falls back rather than
/// guessing.
fn parse_set_config_list(sql: &str) -> Option<Vec<SetConfigCall>> {
    let mut p = ArgScanner {
        b: sql.trim().trim_end_matches(';').as_bytes(),
        i: 0,
    };
    p.keyword("select")?;
    let mut calls = Vec::new();
    loop {
        p.keyword("set_config")?;
        p.punct(b'(')?;
        let name = p.arg()?;
        p.punct(b',')?;
        let value = p.arg()?;
        p.punct(b',')?;
        // is_local: a bare `true`/`false` (or a bound parameter); not kept.
        p.ws();
        while p.i < p.b.len() && (p.b[p.i].is_ascii_alphanumeric() || p.b[p.i] == b'$') {
            p.i += 1;
        }
        p.punct(b')')?;
        calls.push(SetConfigCall { name, value });
        p.ws();
        if p.i == p.b.len() {
            return Some(calls);
        }
        p.punct(b',')?;
    }
}

/// A byte cursor for [`parse_set_config_list`]. Every delimiter it stops on is
/// ASCII, so slicing between them is always on a UTF-8 boundary.
struct ArgScanner<'a> {
    b: &'a [u8],
    i: usize,
}

impl ArgScanner<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn keyword(&mut self, kw: &str) -> Option<()> {
        self.ws();
        let end = self.i + kw.len();
        let word = self.b.get(self.i..end)?;
        let boundary =
            !matches!(self.b.get(end), Some(c) if c.is_ascii_alphanumeric() || *c == b'_');
        (word.eq_ignore_ascii_case(kw.as_bytes()) && boundary).then(|| self.i = end)
    }

    fn punct(&mut self, c: u8) -> Option<()> {
        self.ws();
        (self.b.get(self.i) == Some(&c)).then(|| self.i += 1)
    }

    fn arg(&mut self) -> Option<ConfigArg> {
        self.ws();
        let arg = match *self.b.get(self.i)? {
            b'\'' => {
                let mut out = Vec::new();
                self.i += 1;
                loop {
                    match *self.b.get(self.i)? {
                        b'\'' if self.b.get(self.i + 1) == Some(&b'\'') => {
                            out.push(b'\'');
                            self.i += 2;
                        }
                        b'\'' => {
                            self.i += 1;
                            break;
                        }
                        c => {
                            out.push(c);
                            self.i += 1;
                        }
                    }
                }
                ConfigArg::Lit(String::from_utf8(out).ok()?)
            }
            b'$' => {
                let start = self.i + 1;
                self.i = start;
                while self.b.get(self.i).is_some_and(u8::is_ascii_digit) {
                    self.i += 1;
                }
                let n = std::str::from_utf8(&self.b[start..self.i])
                    .ok()?
                    .parse()
                    .ok()?;
                ConfigArg::Param(n)
            }
            _ => return None,
        };
        // An optional `::type` cast (`$1::text`).
        self.ws();
        if self.b[self.i..].starts_with(b"::") {
            self.i += 2;
            self.ws();
            while self
                .b
                .get(self.i)
                .is_some_and(|c| c.is_ascii_alphanumeric() || *c == b'_')
            {
                self.i += 1;
            }
        }
        Some(arg)
    }
}

/// Inspect a statement; return a canned answer or [`Canned::Pass`].
pub fn intercept(sql: &str, user: &str, database: &str) -> Canned {
    let s = sql.trim().trim_end_matches(';').trim().to_ascii_lowercase();

    // RLS principal statements (`SET ROLE` / `SET … {twill,request}.jwt.claims` /
    // `SET … twill.rls.bypass` and their `RESET`) must reach the engine so the
    // executor can enforce policies against the session principal (Phase 7).
    // Checked before the fire-and-forget `SET` no-op below.
    if is_rls_session_stmt(&s) {
        return Canned::Pass;
    }

    // Session-setup commands drivers fire and forget (SET / DISCARD / LISTEN /
    // UNLISTEN) — grouped into a helper to keep this classifier within the
    // project's lizard complexity gate.
    if let Some(tag) = session_noop_tag(&s) {
        return Canned::Tag(tag.to_string());
    }

    // `twill.stats` — the read-only observability surface (#53 / spec 15),
    // pulled in-band over pgwire. Recognized as a `SHOW`, a view select, or a
    // bare `TABLE`. Matched before the generic `SHOW <name>` so it is not
    // mistaken for a GUC. The session resolves it against the live engine.
    if is_twill_stats_query(&s) {
        return Canned::Stats;
    }

    // `twill.catalog` / `twill.relationships` — the catalog reflection surface
    // the management CLI consumes over the wire (spec 19 Milestone 3). Matched
    // before the generic `SHOW <name>` so the dotted name is not taken for a GUC.
    if let Some(kind) = twill_catalog_query(&s) {
        return Canned::Catalog(kind);
    }

    // SHOW <name> — one row named after the setting.
    if let Some(rest) = s.strip_prefix("show ") {
        let name = rest.trim();
        return one_row(name, setting_value(name));
    }

    // PostgREST's per-request preamble: `SELECT set_config('search_path', $1,
    // true), set_config('role', $2, true), set_config('request.jwt.claims', $3,
    // true), …`. Parsed from the original (case-preserving) text so the session
    // can forward the role + claims to the engine — this is the *only* way
    // PostgREST conveys the request principal, so RLS depends on it (spec 17).
    // A shape the parser does not recognize keeps the old answer: one row of
    // empty strings, one per call (PostgREST ignores the values).
    if s.starts_with("select set_config(") {
        if let Some(calls) = parse_set_config_list(sql) {
            return Canned::SetConfig(calls);
        }
        let n = s.matches("set_config(").count().max(1);
        return Canned::Rows {
            columns: vec!["set_config".to_string(); n],
            oids: vec![],
            rows: vec![vec![Value::Text(String::new()); n]],
            tag: "SELECT 1".to_string(),
        };
    }

    // PostgREST's schema-cache introspection (a recursive pg_catalog query the
    // engine cannot execute). Reflected from the real catalog elsewhere; for now
    // a placeholder empty result with the exact 9-column shape PostgREST decodes.
    if s.contains("pg_relation_is_updatable") {
        return Canned::Reflect(ReflectKind::Tables);
    }

    // PostgREST loads the timezone list (for the `Prefer: timezone=` header).
    // The engine has no tz catalog → empty list.
    if s.contains("pg_timezone_names") {
        return empty_rows(&["name"]);
    }

    // PostgREST's cast introspection (pg_cast — domain ⇄ json/text coercions).
    // No domains/casts here → empty result.
    if s.contains("pg_cast") || s.contains("castsource") {
        return empty_rows(&["castsource", "casttarget", "castfunc"]);
    }

    // PostgREST's computed-relationships query (set-returning functions that act
    // as relationships). No functions here → empty result.
    if s.contains("computed_rels") || s.contains("all_relations") {
        return empty_rows(&[
            "name",
            "rel_table_schema",
            "rel_table_name",
            "rel_ftable_schema",
            "rel_ftable_name",
            "single_row",
            "is_self",
        ]);
    }

    // PostgREST's functions/RPC introspection (pg_proc). No user functions here
    // → empty result (the /rpc surface is simply empty).
    if s.contains("rettype_is_setof") || s.contains("proargmodes") {
        return empty_rows(&[
            "proc_schema",
            "proc_name",
            "proc_description",
            "args",
            "schema",
            "name",
            "rettype_is_setof",
            "rettype_is_composite",
            "rettype_is_composite_alias",
            "provolatile",
            "hasvariadic",
            "transaction_isolation_level",
            "kvs",
        ]);
    }

    // PostgREST's foreign-key relationship query (pg_constraint, contype='f').
    // Reflected from the engine catalog's foreign keys by the session, which
    // turns each into an embeddable relationship.
    if s.contains("pks_uniques_cols") {
        return Canned::Reflect(ReflectKind::Relationships);
    }

    // PostgREST's view-relationship dependency query (recursive, parses view
    // definitions from pg_rewrite). No views here → empty result.
    if s.contains("pks_fks") || s.contains("column_dependencies") {
        return empty_rows(&[
            "table_schema",
            "table_name",
            "view_schema",
            "view_name",
            "constraint_name",
            "constraint_type",
            "column_dependencies",
        ]);
    }

    // PostgREST's per-role config-settings query reads `pg_db_role_setting`
    // (custom GUCs set via ALTER ROLE). The engine has no such catalog and no
    // role settings, so the correct answer is zero rows — and PostgREST blocks
    // (retries) until this query succeeds, so it must not fall through and fail.
    if s.contains("pg_db_role_setting") {
        return empty_rows(&["key", "value"]);
    }
    // PostgREST's other role-settings query (per-role GUCs via ALTER ROLE,
    // joined against pg_settings). No roles carry settings here → zero rows.
    if s.contains("pg_auth_members") {
        return empty_rows(&["rolname", "iso_lvl", "role_settings"]);
    }

    // PostgREST 14.x's exact startup probe (captured from the real client): one
    // SELECT pulling the numeric version, the version string, and version() in a
    // single row. Answer it as a 3-column row so the schema-cache step proceeds.
    let compact: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    if compact.starts_with(
        "selectcurrent_setting('server_version_num')::integer,\
         current_setting('server_version'),version()",
    ) {
        return Canned::Rows {
            columns: vec![
                "server_version_num".to_string(),
                "server_version".to_string(),
                "version".to_string(),
            ],
            oids: vec![],
            rows: vec![vec![
                Value::Int(SERVER_VERSION_NUM.parse().unwrap_or(150000)),
                Value::Text(SERVER_VERSION.to_string()),
                Value::Text(format!(
                    "PostgreSQL {SERVER_VERSION} (twill-db engine-server)"
                )),
            ]],
            tag: "SELECT 1".to_string(),
        };
    }

    // `current_setting('<name>'[, missing_ok])[::type]` — the GUC accessor
    // PostgREST and Bun.sql probe on connect (notably `server_version_num`).
    // Match whitespace-insensitively and stop at the setting name, so any cast
    // suffix, second argument, or alias is tolerated.
    if let Some(rest) = compact.strip_prefix("selectcurrent_setting('") {
        if let Some(end) = rest.find('\'') {
            return one_row("current_setting", setting_value(&rest[..end]));
        }
    }

    // Scalar introspection functions clients probe on connect.
    match s.as_str() {
        "select version()" => {
            return one_row(
                "version",
                &format!("PostgreSQL {SERVER_VERSION} (twill-db engine-server)"),
            )
        }
        "select current_schema()" | "select current_schema" => {
            return one_row("current_schema", "public")
        }
        "select current_database()" | "select current_database" => {
            return one_row("current_database", database)
        }
        "select current_user" | "select user" | "select current_user()" => {
            return one_row("current_user", user)
        }
        "select pg_backend_pid()" => {
            return Canned::Rows {
                columns: vec!["pg_backend_pid".to_string()],
                oids: vec![],
                rows: vec![vec![Value::Int(std::process::id() as i64)]],
                tag: "SELECT 1".to_string(),
            }
        }
        _ => {}
    }

    Canned::Pass
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scalar(sql: &str) -> Option<String> {
        match intercept(sql, "postgres", "srv") {
            Canned::Rows { rows, .. } => match &rows[0][0] {
                Value::Text(s) => Some(s.clone()),
                Value::Int(i) => Some(i.to_string()),
                _ => None,
            },
            _ => None,
        }
    }

    #[test]
    fn version_probe_is_canned() {
        // The exact PostgREST/Bun.sql startup probe, with the cast + whitespace.
        assert_eq!(
            scalar("SELECT current_setting('server_version_num')::integer").as_deref(),
            Some(SERVER_VERSION_NUM)
        );
        assert_eq!(
            scalar("select  current_setting( 'server_version_num' , true )").as_deref(),
            Some(SERVER_VERSION_NUM)
        );
        assert_eq!(
            scalar("SHOW server_version_num").as_deref(),
            Some(SERVER_VERSION_NUM)
        );
    }

    #[test]
    fn common_settings_resolve() {
        assert_eq!(
            scalar("select current_setting('standard_conforming_strings')").as_deref(),
            Some("on")
        );
        assert_eq!(scalar("SHOW client_encoding").as_deref(), Some("UTF8"));
        // Unknown settings report empty rather than erroring (Pass would 500).
        assert_eq!(
            scalar("select current_setting('nonesuch')").as_deref(),
            Some("")
        );
    }

    #[test]
    fn twill_stats_is_intercepted_and_formatted() {
        // All accepted spellings classify as the stats surface, not a GUC.
        for q in [
            "SHOW twill.stats",
            "show twill_stats",
            "SELECT * FROM twill_stats",
            "TABLE twill.stats",
        ] {
            assert!(
                matches!(intercept(q, "u", "d"), Canned::Stats),
                "{q} should intercept to Stats"
            );
        }
        // A normal SHOW is unaffected (still a one-row GUC answer).
        assert_eq!(scalar("SHOW client_encoding").as_deref(), Some("UTF8"));

        // The formatter renders the (metric, value) rows under the settled names.
        let stats = engine::EngineStats {
            commits: 7,
            durable_appends: 3,
            committed_lsn: 42,
            write_acquires: 9,
            write_handoffs: 2,
            write_wait_us_total: 1234,
            storage: engine::StorageStats {
                wal_appends: 3,
                fsyncs: 4,
                ..Default::default()
            },
        };
        match stats_rows(&stats) {
            Canned::Rows { columns, rows, .. } => {
                assert_eq!(columns, vec!["metric".to_string(), "value".to_string()]);
                let kv: std::collections::HashMap<String, i64> = rows
                    .iter()
                    .map(|r| match (&r[0], &r[1]) {
                        (Value::Text(k), Value::Int(v)) => (k.clone(), *v),
                        other => panic!("unexpected cell {other:?}"),
                    })
                    .collect();
                assert_eq!(kv["twill_commit_total"], 7);
                assert_eq!(kv["twill_durable_append_total"], 3);
                assert_eq!(kv["twill_committed_lsn"], 42);
                assert_eq!(kv["twill_storage_wal_appends_total"], 3);
                assert_eq!(kv["twill_storage_fsync_total"], 4);
                // write-contention family (EX-4 / spec 10 hot-row).
                assert_eq!(kv["twill_write_lane_acquire_total"], 9);
                assert_eq!(kv["twill_write_handoff_total"], 2);
                assert_eq!(kv["twill_write_wait_us_total"], 1234);
            }
            _ => panic!("expected rows from stats_rows"),
        }
    }

    #[test]
    fn data_queries_still_pass_through() {
        assert!(matches!(
            intercept("SELECT * FROM books", "postgres", "srv"),
            Canned::Pass
        ));
        // A column literally named current_setting must not be intercepted.
        assert!(matches!(
            intercept("SELECT current_setting FROM t", "postgres", "srv"),
            Canned::Pass
        ));
    }

    #[test]
    fn postgrest_startup_probes_are_canned() {
        // The combined 3-column version probe PostgREST 14.x issues on connect.
        match intercept(
            "SELECT current_setting('server_version_num')::integer, \
             current_setting('server_version'), version()",
            "postgres",
            "srv",
        ) {
            Canned::Rows { columns, rows, .. } => {
                assert_eq!(columns.len(), 3);
                assert_eq!(rows[0].len(), 3);
                assert!(matches!(rows[0][0], Value::Int(150000)));
            }
            _ => panic!("version probe must be canned"),
        }

        // LISTEN / UNLISTEN are accepted no-ops (no engine pub/sub).
        assert!(matches!(
            intercept("LISTEN \"pgrst\"", "postgres", "srv"),
            Canned::Tag(t) if t == "LISTEN"
        ));

        // Both role-settings queries resolve to an empty result so PostgREST
        // stops retrying and proceeds to load the schema cache.
        for q in [
            "WITH role_setting AS (SELECT 1 FROM pg_catalog.pg_db_role_setting) SELECT 1",
            "with role_setting as (select 1 from pg_auth_members) select 1",
        ] {
            assert!(matches!(
                intercept(q, "postgres", "srv"),
                Canned::Rows { rows, .. } if rows.is_empty()
            ));
        }
    }

    #[test]
    fn set_config_preamble_is_parsed() {
        use ConfigArg::{Lit, Param};
        let call = |name, value| SetConfigCall { name, value };
        match intercept(
            "select set_config('search_path', $1, true), set_config('role', $2::text, true), \
             set_config($3, 'it''s', false)",
            "u",
            "d",
        ) {
            Canned::SetConfig(calls) => assert_eq!(
                calls,
                vec![
                    call(Lit("search_path".into()), Param(1)),
                    call(Lit("role".into()), Param(2)),
                    call(Param(3), Lit("it's".into())),
                ]
            ),
            _ => panic!("preamble must parse into set_config calls"),
        }
        // An unrecognized shape keeps the canned one-row answer.
        assert!(matches!(
            intercept("SELECT set_config('a', lower('B'), true)", "u", "d"),
            Canned::Rows { rows, .. } if rows.len() == 1
        ));
    }

    #[test]
    fn schema_cache_queries_are_intercepted_empty() {
        // Each PostgREST schema-cache query (matched by a marker token) must be
        // intercepted with an empty, correctly-shaped result so the engine never
        // sees the un-runnable pg_catalog SQL and the cache loads. Column counts
        // match what PostgREST decodes.
        // The tables query is reflected from the live catalog by the session,
        // so the pure classifier returns the Reflect marker.
        assert!(matches!(
            intercept(
                "...pg_relation_is_updatable(c.oid::regclass, TRUE) & 8...",
                "postgres",
                "srv"
            ),
            Canned::Reflect(ReflectKind::Tables)
        ));

        // The FK relationship query is likewise reflected from the live catalog.
        assert!(matches!(
            intercept(
                "...JOIN pks_uniques_cols ... contype = 'f'...",
                "postgres",
                "srv"
            ),
            Canned::Reflect(ReflectKind::Relationships)
        ));

        // The remaining schema-cache queries are answered with an empty,
        // correctly-shaped result (no catalog needed).
        let cases = [
            ("...with recursive pks_fks as ... column_dependencies...", 7),
            ("...rettype_is_setof ... proargmodes::text[]...", 13),
            ("...all_relations as ( ... computed_rels", 7),
            ("...from pg_cast c ... castsource...", 3),
            ("SELECT name FROM pg_timezone_names", 1),
        ];
        for (sql, ncols) in cases {
            match intercept(sql, "postgres", "srv") {
                Canned::Rows { columns, rows, .. } => {
                    assert_eq!(columns.len(), ncols, "wrong column count for {sql:?}");
                    assert!(rows.is_empty(), "expected empty rows for {sql:?}");
                }
                _ => panic!("schema-cache query not intercepted: {sql:?}"),
            }
        }
    }
}
