//! Postgres-client compatibility over the wire: the SQLSTATE an engine error
//! surfaces as, and PostgREST's per-request `set_config` preamble driving the
//! engine's row-level security principal (spec 17).
//!
//! Both are things an unmodified client keys on: drivers / ORMs branch on
//! `23505` (unique) vs `23502` (NOT NULL) vs `42501` (RLS), and PostgREST sets
//! the request's role + JWT claims *only* through the preamble — never via
//! `SET ROLE` — so RLS is enforced for a PostgREST caller only if the preamble
//! reaches the engine session.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::thread;
use std::time::Duration;

fn unique_db() -> String {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("twill-compat-{}-{n}.db", std::process::id()));
    let _ = std::fs::remove_file(&p);
    format!("file://{}", p.display())
}

fn start_server() -> String {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let db = unique_db();
    thread::spawn(move || {
        let _ = twill_server::serve_listener(listener, &db);
    });
    addr
}

// ---- a tiny pg client ------------------------------------------------------

type Msgs = Vec<(u8, Vec<u8>)>;

struct Client {
    stream: TcpStream,
}

impl Client {
    fn connect(addr: &str) -> Client {
        let stream = TcpStream::connect(addr).unwrap();
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut c = Client { stream };
        let mut body = Vec::new();
        body.extend_from_slice(&196608i32.to_be_bytes());
        for (k, v) in [("user", "authenticator"), ("database", "app")] {
            body.extend_from_slice(k.as_bytes());
            body.push(0);
            body.extend_from_slice(v.as_bytes());
            body.push(0);
        }
        body.push(0);
        let mut msg = ((body.len() + 4) as i32).to_be_bytes().to_vec();
        msg.extend_from_slice(&body);
        c.stream.write_all(&msg).unwrap();
        c.read_until_ready();
        c
    }

    fn send(&mut self, tag: u8, payload: &[u8]) {
        let mut msg = vec![tag];
        msg.extend_from_slice(&((payload.len() + 4) as i32).to_be_bytes());
        msg.extend_from_slice(payload);
        self.stream.write_all(&msg).unwrap();
    }

    fn read_until_ready(&mut self) -> Msgs {
        let mut msgs = Vec::new();
        loop {
            let mut tag = [0u8; 1];
            self.stream.read_exact(&mut tag).unwrap();
            let mut len = [0u8; 4];
            self.stream.read_exact(&mut len).unwrap();
            let mut body = vec![0u8; i32::from_be_bytes(len) as usize - 4];
            self.stream.read_exact(&mut body).unwrap();
            msgs.push((tag[0], body));
            if tag[0] == b'Z' {
                return msgs;
            }
        }
    }

    fn simple(&mut self, sql: &str) -> Msgs {
        let mut p = sql.as_bytes().to_vec();
        p.push(0);
        self.send(b'Q', &p);
        self.read_until_ready()
    }

    /// Parse/Bind/Describe/Execute/Sync an unnamed statement with text params —
    /// the shape PostgREST (hasql) sends every per-request statement in.
    fn extended(&mut self, sql: &str, params: &[&str]) -> Msgs {
        let mut p = vec![0]; // unnamed statement
        p.extend_from_slice(sql.as_bytes());
        p.push(0);
        p.extend_from_slice(&0i16.to_be_bytes()); // no declared param types
        self.send(b'P', &p);

        let mut b = vec![0, 0]; // unnamed portal, unnamed statement
        b.extend_from_slice(&0i16.to_be_bytes()); // all params text
        b.extend_from_slice(&(params.len() as i16).to_be_bytes());
        for v in params {
            b.extend_from_slice(&(v.len() as i32).to_be_bytes());
            b.extend_from_slice(v.as_bytes());
        }
        b.extend_from_slice(&0i16.to_be_bytes()); // text results
        self.send(b'B', &b);

        self.send(b'D', &[b'P', 0]);
        let mut e = vec![0];
        e.extend_from_slice(&0i32.to_be_bytes());
        self.send(b'E', &e);
        self.send(b'S', &[]);
        self.read_until_ready()
    }
}

fn data_rows(msgs: &Msgs) -> Vec<Vec<Option<String>>> {
    let mut out = Vec::new();
    for (tag, body) in msgs {
        if *tag != b'D' {
            continue;
        }
        let ncols = i16::from_be_bytes(body[0..2].try_into().unwrap()) as usize;
        let mut pos = 2;
        let mut row = Vec::with_capacity(ncols);
        for _ in 0..ncols {
            let len = i32::from_be_bytes(body[pos..pos + 4].try_into().unwrap());
            pos += 4;
            if len < 0 {
                row.push(None);
            } else {
                let s = String::from_utf8_lossy(&body[pos..pos + len as usize]).into_owned();
                pos += len as usize;
                row.push(Some(s));
            }
        }
        out.push(row);
    }
    out
}

/// The column count announced by the first RowDescription ('T').
fn row_description_width(msgs: &Msgs) -> Option<usize> {
    msgs.iter()
        .find(|(t, _)| *t == b'T')
        .map(|(_, b)| i16::from_be_bytes(b[0..2].try_into().unwrap()) as usize)
}

/// The SQLSTATE (field 'C') of every ErrorResponse in the stream.
fn error_codes(msgs: &Msgs) -> Vec<String> {
    let mut out = Vec::new();
    for (tag, body) in msgs {
        if *tag != b'E' {
            continue;
        }
        let mut pos = 0;
        while pos < body.len() && body[pos] != 0 {
            let field = body[pos];
            pos += 1;
            let start = pos;
            while pos < body.len() && body[pos] != 0 {
                pos += 1;
            }
            if field == b'C' {
                out.push(String::from_utf8_lossy(&body[start..pos]).into_owned());
            }
            pos += 1;
        }
    }
    out
}

fn ok(msgs: &Msgs) {
    assert!(error_codes(msgs).is_empty(), "unexpected error: {msgs:?}");
}

fn ids(msgs: &Msgs) -> Vec<String> {
    data_rows(msgs)
        .into_iter()
        .map(|r| r[0].clone().unwrap_or_default())
        .collect()
}

// ---- 1. SQLSTATE mapping ---------------------------------------------------

#[test]
fn constraint_violations_carry_their_sqlstate() {
    let addr = start_server();
    let mut c = Client::connect(&addr);
    ok(&c.simple(
        "CREATE TABLE people (id INTEGER PRIMARY KEY, email TEXT UNIQUE, \
         name TEXT NOT NULL, age INTEGER CHECK (age >= 0))",
    ));
    ok(&c.simple("INSERT INTO people VALUES (1, 'a@x', 'ada', 30)"));

    let cases = [
        // unique_violation — primary key and UNIQUE column alike.
        ("INSERT INTO people VALUES (1, 'b@x', 'bel', 20)", "23505"),
        ("INSERT INTO people VALUES (2, 'a@x', 'bel', 20)", "23505"),
        // not_null_violation
        ("INSERT INTO people VALUES (3, 'c@x', NULL, 20)", "23502"),
        // check_violation
        ("INSERT INTO people VALUES (4, 'd@x', 'dan', -1)", "23514"),
        // feature_not_supported — the engine parses but does not implement it.
        (
            "CREATE TABLE g (a INTEGER, b INTEGER GENERATED ALWAYS AS (a) STORED)",
            "0A000",
        ),
        // A genuine syntax error stays a syntax error.
        ("SELEC 1", "42601"),
    ];
    for (sql, want) in cases {
        let r = c.simple(sql);
        assert_eq!(error_codes(&r), vec![want.to_string()], "{sql}: {r:?}");
    }

    // The extended protocol (every ORM's path) maps the same way.
    let r = c.extended(
        "INSERT INTO people (id, email, name, age) VALUES ($1, 'z@x', 'zed', 1)",
        &["1"],
    );
    assert_eq!(error_codes(&r), vec!["23505".to_string()], "{r:?}");
}

#[test]
fn rls_with_check_denial_is_insufficient_privilege() {
    let addr = start_server();
    let mut c = Client::connect(&addr);
    ok(&c.simple("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT)"));
    ok(&c.simple("ALTER TABLE notes ENABLE ROW LEVEL SECURITY"));
    ok(&c.simple(
        "CREATE POLICY p ON notes FOR ALL TO authenticated \
         USING (owner = auth.uid()) WITH CHECK (owner = auth.uid())",
    ));
    ok(&c.simple("SET ROLE authenticated"));
    ok(&c.simple(r#"SET twill.jwt.claims = '{"sub":"42"}'"#));
    ok(&c.simple("INSERT INTO notes VALUES (1, '42')"));

    let r = c.simple("INSERT INTO notes VALUES (2, '99')");
    assert_eq!(error_codes(&r), vec!["42501".to_string()], "{r:?}");
}

// ---- 2. PostgREST's set_config preamble drives RLS -------------------------

/// PostgREST 12–14's per-request preamble (`setPgLocals`): constant GUC names,
/// bound text values, `is_local = true`. Sent in the extended protocol inside
/// the request's transaction, ahead of the data-path statement.
const PGRST_PREAMBLE: &str = "select set_config('search_path', $1, true), \
     set_config('role', $2, true), set_config('request.jwt.claims', $3, true), \
     set_config('request.method', $4, true), set_config('request.path', $5, true), \
     set_config('request.headers', $6, true), set_config('request.cookies', $7, true)";

fn preamble(c: &mut Client, role: &str, claims: &str) -> Msgs {
    c.extended(
        PGRST_PREAMBLE,
        &[
            "\"public\"",
            role,
            claims,
            "GET",
            "/notes",
            r#"{"accept":"*/*"}"#,
            "{}",
        ],
    )
}

#[test]
fn postgrest_preamble_sets_the_rls_principal() {
    let addr = start_server();
    let mut admin = Client::connect(&addr);
    ok(&admin.simple("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT)"));
    ok(&admin.simple("INSERT INTO notes VALUES (1,'alice'),(2,'bob'),(3,'alice')"));
    ok(&admin.simple("ALTER TABLE notes ENABLE ROW LEVEL SECURITY"));
    ok(&admin.simple(
        "CREATE POLICY own ON notes FOR SELECT TO authenticated USING (owner = auth.uid())",
    ));

    // One pooled PostgREST connection serving successive requests.
    let mut pg = Client::connect(&addr);

    // Request 1: alice. The preamble's reply keeps PostgREST's shape — one row,
    // one column per set_config, each the value just set.
    ok(&pg.simple("BEGIN"));
    let r = preamble(
        &mut pg,
        "authenticated",
        r#"{"sub":"alice","role":"authenticated"}"#,
    );
    ok(&r);
    assert_eq!(row_description_width(&r), Some(7), "{r:?}");
    let rows = data_rows(&r);
    assert_eq!(rows.len(), 1, "{r:?}");
    assert_eq!(rows[0][1].as_deref(), Some("authenticated"));
    assert_eq!(
        rows[0][2].as_deref(),
        Some(r#"{"sub":"alice","role":"authenticated"}"#)
    );
    assert_eq!(rows[0][3].as_deref(), Some("GET"));
    let r = pg.extended("SELECT id FROM notes ORDER BY id", &[]);
    assert_eq!(ids(&r), vec!["1", "3"], "alice sees only her rows: {r:?}");
    ok(&pg.simple("COMMIT"));

    // Request 2 on the same connection: bob. The new principal replaces alice's.
    ok(&pg.simple("BEGIN"));
    ok(&preamble(
        &mut pg,
        "authenticated",
        r#"{"sub":"bob","role":"authenticated"}"#,
    ));
    let r = pg.extended("SELECT id FROM notes ORDER BY id", &[]);
    assert_eq!(ids(&r), vec!["2"], "bob sees only his rows: {r:?}");
    ok(&pg.simple("COMMIT"));

    // Request 3: anonymous (PostgREST sends role=anon, claims {"role":"anon"}).
    // The policy is TO authenticated, so anon is default-denied.
    ok(&pg.simple("BEGIN"));
    ok(&preamble(&mut pg, "anon", r#"{"role":"anon"}"#));
    let r = pg.extended("SELECT id FROM notes ORDER BY id", &[]);
    assert!(ids(&r).is_empty(), "anon is denied: {r:?}");
    ok(&pg.simple("COMMIT"));
}

#[test]
fn legacy_per_claim_gucs_and_literal_values_reach_the_engine() {
    // PostgREST < 10 set one `request.jwt.claim.<k>` GUC per claim; a plain
    // client may pass literal values in a simple query. Both must land.
    let addr = start_server();
    let mut c = Client::connect(&addr);
    ok(&c.simple("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT)"));
    ok(&c.simple("INSERT INTO notes VALUES (1,'alice'),(2,'bob')"));
    ok(&c.simple("ALTER TABLE notes ENABLE ROW LEVEL SECURITY"));
    ok(&c.simple(
        "CREATE POLICY own ON notes FOR SELECT TO authenticated USING (owner = auth.uid())",
    ));

    let r = c.simple(
        "SELECT set_config('role', 'authenticated', true), \
         set_config('request.jwt.claim.sub', 'bob', true)",
    );
    ok(&r);
    assert_eq!(
        data_rows(&r),
        vec![vec![Some("authenticated".into()), Some("bob".into())]]
    );
    assert_eq!(ids(&c.simple("SELECT id FROM notes")), vec!["2"]);

    // Dynamic GUC names (PostgREST's role/app settings use `set_config($1, $2, …)`).
    ok(&c.extended(
        "select set_config('role', $1, true), set_config($2, $3, true)",
        &["authenticated", "request.jwt.claim.sub", "alice"],
    ));
    assert_eq!(ids(&c.simple("SELECT id FROM notes")), vec!["1"]);
}

#[test]
fn a_preamble_replaces_the_whole_principal() {
    // PostgREST < 10 sends no claim GUCs at all for an anonymous request. The
    // previous request's claims must not survive into it: a policy open to every
    // role that keys on auth.uid() would otherwise still match the last user.
    let addr = start_server();
    let mut c = Client::connect(&addr);
    ok(&c.simple("CREATE TABLE notes (id INTEGER PRIMARY KEY, owner TEXT)"));
    ok(&c.simple("INSERT INTO notes VALUES (1,'alice'),(2,'bob')"));
    ok(&c.simple("ALTER TABLE notes ENABLE ROW LEVEL SECURITY"));
    ok(&c.simple("CREATE POLICY own ON notes FOR SELECT USING (owner = auth.uid())"));

    ok(&c.simple(
        "SELECT set_config('role', 'authenticated', true), \
         set_config('request.jwt.claim.sub', 'alice', true)",
    ));
    assert_eq!(ids(&c.simple("SELECT id FROM notes")), vec!["1"]);

    // Next request: anonymous, role only.
    ok(&c.simple("SELECT set_config('role', 'anon', true)"));
    assert!(
        ids(&c.simple("SELECT id FROM notes")).is_empty(),
        "alice's claims leaked into the anonymous request"
    );

    // And the converse: claims only, after a role was set, resets the role.
    ok(&c.simple("SELECT set_config('role', 'authenticated', true)"));
    ok(&c.simple("SELECT set_config('request.jwt.claims', '{\"sub\":\"bob\"}', true)"));
    let r = c.simple("SELECT auth.role()");
    assert_eq!(data_rows(&r), vec![vec![Some("anon".into())]], "{r:?}");

    // A preamble touching no principal GUC leaves the principal alone.
    ok(&c.simple("SELECT set_config('search_path', 'public', true)"));
    assert_eq!(ids(&c.simple("SELECT id FROM notes")), vec!["2"]);
}

#[test]
fn preamble_rejects_a_role_it_cannot_forward_safely() {
    // A role name the engine cannot quote is refused rather than spliced into SQL.
    let addr = start_server();
    let mut c = Client::connect(&addr);
    let r = preamble(&mut c, "evil\"; SET twill.rls.bypass = on; --", "{}");
    assert_eq!(error_codes(&r), vec!["22023".to_string()], "{r:?}");
}
