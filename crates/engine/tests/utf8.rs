//! Non-ASCII text survives the SQL lexer: string literals are decoded as UTF-8,
//! not byte-by-byte as Latin-1 (`'José'` must not come back as `'JosÃ©'`). This
//! covers every client path — embedded FFI, pgwire and Bun all hand the engine
//! the same `&str` — including JWT claims read by RLS policies.

use engine::Connection;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

fn db_path(tag: &str) -> PathBuf {
    static N: AtomicU64 = AtomicU64::new(0);
    let n = N.fetch_add(1, Ordering::Relaxed);
    let mut p = std::env::temp_dir();
    p.push(format!("twill-utf8-{tag}-{}-{n}.db", std::process::id()));
    let _ = fs::remove_file(&p);
    p
}

fn open(p: &Path) -> Connection {
    Connection::open(&format!("file://{}", p.display())).unwrap()
}

#[test]
fn non_ascii_string_literals_round_trip() {
    let p = db_path("roundtrip");
    let mut db = open(&p);
    db.exec("CREATE TABLE people (id INTEGER PRIMARY KEY, name TEXT)")
        .unwrap();
    db.exec("INSERT INTO people VALUES (1, 'José'), (2, '日本'), (3, 'it''s 🦀')")
        .unwrap();
    let rs = db.query("SELECT name FROM people ORDER BY id").unwrap();
    let names: Vec<_> = rs.rows.iter().map(|r| r[0].render()).collect();
    assert_eq!(
        names,
        vec![
            Some("José".to_string()),
            Some("日本".to_string()),
            Some("it's 🦀".to_string()),
        ]
    );

    // A non-ASCII literal in a predicate matches the stored value.
    let rs = db
        .query("SELECT id FROM people WHERE name = '日本'")
        .unwrap();
    assert_eq!(rs.rows.len(), 1);
    assert_eq!(rs.rows[0][0].render().as_deref(), Some("2"));

    // And it survives WAL replay on reopen.
    drop(db);
    let mut db = open(&p);
    let rs = db.query("SELECT name FROM people WHERE id = 1").unwrap();
    assert_eq!(rs.rows[0][0].render().as_deref(), Some("José"));
}

#[test]
fn non_ascii_jwt_claims_reach_auth_accessors() {
    let p = db_path("claims");
    let mut db = open(&p);
    db.exec("SET ROLE authenticated").unwrap();
    db.exec(r#"SET twill.jwt.claims = '{"sub":"José","name":"日本"}'"#)
        .unwrap();
    let rs = db.query("SELECT auth.uid(), auth.claim('name')").unwrap();
    assert_eq!(rs.rows[0][0].render().as_deref(), Some("José"));
    assert_eq!(rs.rows[0][1].render().as_deref(), Some("日本"));
}

#[test]
fn unexpected_non_ascii_character_is_reported_intact() {
    let p = db_path("errmsg");
    let mut db = open(&p);
    let err = db.query("SELECT é").unwrap_err();
    assert!(
        err.to_string().contains("'é'"),
        "error should name the character, got: {err}"
    );
}

/// JSON `\u` escapes outside the BMP arrive as UTF-16 surrogate pairs (Python's
/// `json.dumps` writes them by default); the pair must decode to one code point,
/// not two replacement characters.
#[test]
fn json_surrogate_pair_escapes_decode() {
    let p = db_path("surrogates");
    let mut db = open(&p);
    let rs = db
        .query(r#"SELECT '{"a":"\ud83e\udd80"}'::json ->> 'a', '{"b":"Jos\u00e9"}'::json ->> 'b'"#)
        .unwrap();
    assert_eq!(rs.rows[0][0].render().as_deref(), Some("🦀"));
    assert_eq!(rs.rows[0][1].render().as_deref(), Some("José"));

    db.exec("SET ROLE authenticated").unwrap();
    db.exec(r#"SET twill.jwt.claims = '{"sub":"\ud83e\udd80"}'"#)
        .unwrap();
    let rs = db.query("SELECT auth.uid()").unwrap();
    assert_eq!(rs.rows[0][0].render().as_deref(), Some("🦀"));
}
