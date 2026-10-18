//! The frozen pgwire-subset boundary (EX-3 / #102, spec 07 addendum).
//!
//! The wire surface this server answers used to live implicitly in the protocol
//! enum and the `introspect` classifier. This module makes it **explicit and
//! reviewable**: a capability matrix — every protocol message and every
//! connect-time catalog/introspection query the real clients (`Bun.sql`,
//! PostgREST 14.x, `pgbench`) issue, each tagged answered / reflected / stubbed /
//! errored — plus the one classifier that turns an *un*-answered system-catalog
//! query into a clear `feature_not_supported` error instead of a confusing
//! syntax error from the engine.
//!
//! It is wire-surface only (spec 07 non-goal: no engine-core or storage change).
//! The matrix is enumerated **empirically** — from SQL captured by running the
//! clients against the listener (`TWILL_LOG_SQL`), not from reading the spec —
//! and frozen by [`crate::tests`]-adjacent conformance tests
//! (`crates/server/tests/pgwire_subset.rs`).

/// How the subset treats a given message / query.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Support {
    /// Fully handled end-to-end (the engine runs it, or the server answers it
    /// with a real value derived from live state).
    Answered,
    /// Answered by reflecting the live engine catalog into the client's expected
    /// shape (PostgREST schema-cache: tables, FK relationships).
    Reflected,
    /// Accepted with a canned/empty but correctly-shaped reply: the client needs
    /// the query to *succeed*, but the engine has no such concept (GUCs, tz list,
    /// pg_cast, role settings). A no-op, not a failure.
    Stubbed,
    /// Deliberately rejected with a clear, typed error (a system-catalog query
    /// outside the subset; an unimplemented protocol message).
    Errored,
}

/// One protocol message in the frozen subset.
#[derive(Debug, Clone, Copy)]
pub struct MessageCap {
    /// Wire type byte (`'\0'` for the type-less startup packet).
    pub tag: char,
    pub name: &'static str,
    pub support: Support,
    pub note: &'static str,
}

/// The protocol-message capability matrix (spec 07 §"Supported protocol subset").
/// Startup/auth + simple + the full extended query protocol are Answered; SCRAM,
/// in-process TLS, and out-of-band cancel are Errored/declined non-goals.
pub const PROTOCOL_MESSAGES: &[MessageCap] = &[
    MessageCap {
        tag: '\0',
        name: "StartupMessage",
        support: Support::Answered,
        note: "protocol 3.0; trust auth, cleartext",
    },
    MessageCap {
        tag: '\0',
        name: "SSLRequest",
        support: Support::Stubbed,
        note: "declined with 'N'; client proceeds cleartext",
    },
    MessageCap {
        tag: '\0',
        name: "GSSENCRequest",
        support: Support::Stubbed,
        note: "declined with 'N'",
    },
    MessageCap {
        tag: '\0',
        name: "CancelRequest",
        support: Support::Stubbed,
        note: "accepted and ignored (no out-of-band cancel)",
    },
    MessageCap {
        tag: 'Q',
        name: "Query (simple)",
        support: Support::Answered,
        note: "multi-statement, intercepts + engine",
    },
    MessageCap {
        tag: 'P',
        name: "Parse",
        support: Support::Answered,
        note: "$n placeholders rewritten to engine '?'",
    },
    MessageCap {
        tag: 'B',
        name: "Bind",
        support: Support::Answered,
        note: "text + binary parameter formats",
    },
    MessageCap {
        tag: 'D',
        name: "Describe",
        support: Support::Answered,
        note: "statement + portal; ParameterDescription/RowDescription",
    },
    MessageCap {
        tag: 'E',
        name: "Execute",
        support: Support::Answered,
        note: "text + binary result formats",
    },
    MessageCap {
        tag: 'C',
        name: "Close",
        support: Support::Answered,
        note: "statement + portal",
    },
    MessageCap {
        tag: 'S',
        name: "Sync",
        support: Support::Answered,
        note: "ReadyForQuery; ends skip-until-Sync",
    },
    MessageCap {
        tag: 'H',
        name: "Flush",
        support: Support::Answered,
        note: "accepted (buffered writes already flushed)",
    },
    MessageCap {
        tag: 'X',
        name: "Terminate",
        support: Support::Answered,
        note: "closes the connection",
    },
    MessageCap {
        tag: 'p',
        name: "PasswordMessage (SCRAM/MD5)",
        support: Support::Errored,
        note: "non-goal: only trust auth this phase",
    },
    MessageCap {
        tag: 'F',
        name: "FunctionCall",
        support: Support::Errored,
        note: "non-goal: legacy fast-path",
    },
    MessageCap {
        tag: 'd',
        name: "CopyData",
        support: Support::Errored,
        note: "non-goal: COPY protocol",
    },
];

/// One connect-time catalog/introspection query class, keyed by a stable marker
/// token that appears verbatim in the client's SQL.
#[derive(Debug, Clone, Copy)]
pub struct CatalogCap {
    /// A substring that uniquely identifies the query in captured client SQL.
    pub marker: &'static str,
    pub purpose: &'static str,
    pub support: Support,
    /// Which client(s) issue it (documentation only).
    pub clients: &'static str,
}

/// The catalog/introspection capability matrix. Each entry is matched by
/// [`crate::introspect::intercept`] (the `marker` is the same token that
/// classifier keys on) and answered as recorded here. The conformance suite
/// asserts every Answered/Reflected/Stubbed entry resolves and that a query
/// outside this set hits the [`unsupported_catalog_reason`] clear error.
pub const CATALOG_QUERIES: &[CatalogCap] = &[
    CatalogCap {
        marker: "server_version_num",
        purpose: "version probe (numeric) — the make-or-break startup gate",
        support: Support::Answered,
        clients: "PostgREST, Bun.sql",
    },
    CatalogCap {
        marker: "version()",
        purpose: "version string",
        support: Support::Answered,
        clients: "PostgREST, psql, Bun.sql",
    },
    CatalogCap {
        marker: "current_setting",
        purpose: "GUC accessor (server_version_num, encodings, …)",
        support: Support::Answered,
        clients: "PostgREST, Bun.sql",
    },
    CatalogCap {
        marker: "show ",
        purpose: "SHOW <guc>",
        support: Support::Answered,
        clients: "psql, Bun.sql",
    },
    CatalogCap {
        marker: "set ",
        purpose: "session SET (search_path, role, …)",
        support: Support::Stubbed,
        clients: "PostgREST, psql",
    },
    CatalogCap {
        marker: "set_config(",
        purpose: "PostgREST per-request preamble (role + JWT claims set the RLS principal)",
        support: Support::Answered,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "discard ",
        purpose: "DISCARD ALL on pool checkin",
        support: Support::Stubbed,
        clients: "poolers",
    },
    CatalogCap {
        marker: "listen ",
        purpose: "LISTEN/UNLISTEN (no engine pub/sub)",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "current_schema",
        purpose: "current schema()",
        support: Support::Answered,
        clients: "Bun.sql, ORMs",
    },
    CatalogCap {
        marker: "current_database",
        purpose: "current database()",
        support: Support::Answered,
        clients: "Bun.sql, ORMs",
    },
    CatalogCap {
        marker: "current_user",
        purpose: "current_user / user",
        support: Support::Answered,
        clients: "Bun.sql, ORMs",
    },
    CatalogCap {
        marker: "pg_backend_pid()",
        purpose: "backend pid",
        support: Support::Answered,
        clients: "psql, Bun.sql",
    },
    CatalogCap {
        marker: "pg_relation_is_updatable",
        purpose: "schema cache: tables/columns/PKs",
        support: Support::Reflected,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pks_uniques_cols",
        purpose: "schema cache: FK relationships (embedding)",
        support: Support::Reflected,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pg_timezone_names",
        purpose: "timezone list (Prefer: timezone=)",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pg_cast",
        purpose: "cast introspection",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "computed_rels",
        purpose: "computed relationships",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "rettype_is_setof",
        purpose: "functions/RPC introspection",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pks_fks",
        purpose: "view-relationship dependencies",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pg_db_role_setting",
        purpose: "per-role config settings",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "pg_auth_members",
        purpose: "per-role GUCs",
        support: Support::Stubbed,
        clients: "PostgREST",
    },
    CatalogCap {
        marker: "twill.stats",
        purpose: "the in-band observability surface (#53/EX-4)",
        support: Support::Answered,
        clients: "operators",
    },
    CatalogCap {
        marker: "twill.catalog",
        purpose: "catalog reflection (columns) for the management CLI (spec 19 M3)",
        support: Support::Reflected,
        clients: "twilldb",
    },
    CatalogCap {
        marker: "twill.relationships",
        purpose: "catalog reflection (foreign keys) for the management CLI (spec 19 M3)",
        support: Support::Reflected,
        clients: "twilldb",
    },
];

/// Markers that signal a system-catalog / introspection query the subset does
/// **not** answer. If captured client SQL ever starts issuing one of these for
/// real, it graduates into [`CATALOG_QUERIES`] with a decided disposition; until
/// then, hitting one is a clear `feature_not_supported`, never a silent
/// fall-through to a baffling engine syntax error.
const UNSUPPORTED_CATALOG_MARKERS: &[&str] = &[
    "pg_catalog.",
    "information_schema.",
    " from pg_",
    " join pg_",
    "::regclass",
    "::regproc",
    "::regtype",
    "pg_get_",
];

/// If `sql` is a system-catalog/introspection query outside the frozen subset
/// (and not already intercepted), return a clear human-readable reason naming
/// the offending marker; otherwise `None`. The session turns `Some(reason)` into
/// a `0A000 feature_not_supported` error — the spec-07 MUST that an unsupported
/// catalog query "returns a clear error" rather than confusing the client with a
/// generic parser failure.
///
/// Conservative by construction: it keys on table-reference / cast forms
/// (` from pg_`, `pg_catalog.`, `::regclass`, …), never on a bare identifier, so
/// ordinary data queries — including a user column literally named `pg_size` or
/// `version` — pass straight through. Intercepted queries never reach here (the
/// session calls [`crate::introspect::intercept`] first).
pub fn unsupported_catalog_reason(sql: &str) -> Option<String> {
    // Normalize whitespace so multi-line client SQL matches the ` from pg_`-style
    // markers, and lowercase for case-insensitive matching.
    let normalized = normalize(sql);
    let marker = UNSUPPORTED_CATALOG_MARKERS
        .iter()
        .find(|m| normalized.contains(**m))?;
    Some(format!(
        "unsupported catalog query: this engine-server answers only the pgwire \
         introspection subset frozen in the capability matrix (spec 07 addendum); \
         '{}' is not implemented",
        marker.trim()
    ))
}

/// Lowercase `sql` and collapse every run of ASCII whitespace to a single space,
/// so `FROM\n  pg_class` matches the ` from pg_` marker.
fn normalize(sql: &str) -> String {
    let lower = sql.to_ascii_lowercase();
    let mut out = String::with_capacity(lower.len());
    let mut prev_space = false;
    for ch in lower.chars() {
        if ch.is_ascii_whitespace() {
            if !prev_space {
                out.push(' ');
            }
            prev_space = true;
        } else {
            out.push(ch);
            prev_space = false;
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ordinary_data_queries_are_not_flagged() {
        // Plain DML/DDL and even a column named like a catalog token pass through.
        for sql in [
            "SELECT id, name FROM books WHERE id = $1",
            "INSERT INTO t (version, pg_size) VALUES (1, 2)",
            "SELECT version FROM releases",
            "UPDATE accounts SET balance = balance + 1 WHERE id = 1",
            "CREATE TABLE t (id INTEGER PRIMARY KEY)",
        ] {
            assert!(
                unsupported_catalog_reason(sql).is_none(),
                "false positive on data query: {sql:?}"
            );
        }
    }

    #[test]
    fn unhandled_system_catalog_queries_get_a_clear_reason() {
        // Catalog queries the subset does not answer must classify as unsupported
        // (the session turns this into 0A000, not a parser error).
        for sql in [
            "SELECT relname FROM pg_catalog.pg_class",
            "SELECT * FROM information_schema.columns",
            "SELECT oid::regclass FROM t",
            "SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid = c.relnamespace",
            "SELECT pg_get_expr(adbin, adrelid) FROM pg_attrdef",
        ] {
            let reason = unsupported_catalog_reason(sql);
            assert!(reason.is_some(), "should be flagged unsupported: {sql:?}");
            assert!(reason.unwrap().contains("capability matrix"));
        }
    }

    #[test]
    fn matrix_is_internally_consistent() {
        // No empty markers/notes; every catalog marker is distinct so the
        // conformance suite can address each row unambiguously.
        let mut seen = std::collections::HashSet::new();
        for c in CATALOG_QUERIES {
            assert!(!c.marker.is_empty() && !c.purpose.is_empty());
            assert!(
                seen.insert(c.marker),
                "duplicate catalog marker {:?}",
                c.marker
            );
        }
        for m in PROTOCOL_MESSAGES {
            assert!(!m.name.is_empty() && !m.note.is_empty());
        }
        // The subset answers at least the version probe (the startup gate) and
        // reflects the schema cache.
        assert!(CATALOG_QUERIES
            .iter()
            .any(|c| c.marker == "server_version_num" && c.support == Support::Answered));
        assert!(CATALOG_QUERIES
            .iter()
            .any(|c| c.support == Support::Reflected));
    }
}
