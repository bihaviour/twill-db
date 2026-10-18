//! A compact JSON value model for the stage-6C JSON accessors. The engine stores
//! JSON as `Text` (spec 16 — no native `json` type), so `->`/`->>`/`json_extract`
//! parse that text, navigate it, and return the sub-value. Hand-rolled to keep
//! dependencies minimal (rust.md).

#[derive(Debug, Clone)]
pub enum Json {
    Null,
    Bool(bool),
    Num(f64),
    Str(String),
    Arr(Vec<Json>),
    Obj(Vec<(String, Json)>),
}

impl Json {
    /// Parse a complete JSON document; `None` on any syntax error or trailing
    /// junk.
    pub fn parse(s: &str) -> Option<Json> {
        let b: Vec<char> = s.chars().collect();
        let mut p = Parser { b: &b, i: 0 };
        p.ws();
        let v = p.value()?;
        p.ws();
        if p.i == p.b.len() {
            Some(v)
        } else {
            None
        }
    }

    /// Object member by key.
    pub fn get_key(&self, key: &str) -> Option<&Json> {
        match self {
            Json::Obj(m) => m.iter().find(|(k, _)| k == key).map(|(_, v)| v),
            _ => None,
        }
    }

    /// Array element by index (negative counts from the end, Postgres-style).
    pub fn get_index(&self, idx: i64) -> Option<&Json> {
        match self {
            Json::Arr(a) => {
                let i = if idx < 0 { a.len() as i64 + idx } else { idx };
                usize::try_from(i).ok().and_then(|i| a.get(i))
            }
            _ => None,
        }
    }

    /// The `->>` / scalar text form: a string yields its raw text, scalars their
    /// rendering, a JSON `null` yields `None` (SQL NULL); arrays/objects
    /// re-serialize.
    pub fn as_text(&self) -> Option<String> {
        match self {
            Json::Null => None,
            Json::Bool(b) => Some(b.to_string()),
            Json::Num(n) => Some(fmt_num(*n)),
            Json::Str(s) => Some(s.clone()),
            Json::Arr(_) | Json::Obj(_) => Some(self.to_json_text()),
        }
    }

    /// Re-serialize to compact JSON text (the `->` form).
    pub fn to_json_text(&self) -> String {
        let mut out = String::new();
        self.write_json(&mut out);
        out
    }

    fn write_json(&self, out: &mut String) {
        match self {
            Json::Null => out.push_str("null"),
            Json::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
            Json::Num(n) => out.push_str(&fmt_num(*n)),
            Json::Str(s) => out.push_str(&quote(s)),
            Json::Arr(a) => {
                out.push('[');
                for (i, v) in a.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    v.write_json(out);
                }
                out.push(']');
            }
            Json::Obj(m) => {
                out.push('{');
                for (i, (k, v)) in m.iter().enumerate() {
                    if i > 0 {
                        out.push(',');
                    }
                    out.push_str(&quote(k));
                    out.push(':');
                    v.write_json(out);
                }
                out.push('}');
            }
        }
    }

    /// Navigate an SQLite-style path (`$`, `$.key`, `$[0]`, `$.a[1].b`).
    pub fn extract_path<'a>(&'a self, path: &str) -> Option<&'a Json> {
        let p = path.strip_prefix('$').unwrap_or(path);
        let mut cur = self;
        let mut chars = p.chars().peekable();
        while let Some(&c) = chars.peek() {
            match c {
                '.' => {
                    chars.next();
                    let mut key = String::new();
                    while let Some(&c) = chars.peek() {
                        if c == '.' || c == '[' {
                            break;
                        }
                        key.push(c);
                        chars.next();
                    }
                    cur = cur.get_key(&key)?;
                }
                '[' => {
                    chars.next();
                    let mut num = String::new();
                    for c in chars.by_ref() {
                        if c == ']' {
                            break;
                        }
                        num.push(c);
                    }
                    cur = cur.get_index(num.trim().parse().ok()?)?;
                }
                _ => return None,
            }
        }
        Some(cur)
    }
}

/// Render a JSON number without a needless trailing `.0` for integral values.
fn fmt_num(n: f64) -> String {
    if n.fract() == 0.0 && n.is_finite() && n.abs() < 1e15 {
        format!("{}", n as i64)
    } else {
        format!("{n}")
    }
}

fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\"');
    for c in s.chars() {
        match c {
            '\"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('\"');
    out
}

struct Parser<'a> {
    b: &'a [char],
    i: usize,
}

impl Parser<'_> {
    fn ws(&mut self) {
        while self.i < self.b.len() && self.b[self.i].is_ascii_whitespace() {
            self.i += 1;
        }
    }

    fn value(&mut self) -> Option<Json> {
        self.ws();
        match *self.b.get(self.i)? {
            '{' => self.object(),
            '[' => self.array(),
            '"' => self.string().map(Json::Str),
            't' => self.literal("true", Json::Bool(true)),
            'f' => self.literal("false", Json::Bool(false)),
            'n' => self.literal("null", Json::Null),
            _ => self.number(),
        }
    }

    fn literal(&mut self, word: &str, val: Json) -> Option<Json> {
        for c in word.chars() {
            if self.b.get(self.i) != Some(&c) {
                return None;
            }
            self.i += 1;
        }
        Some(val)
    }

    fn number(&mut self) -> Option<Json> {
        let start = self.i;
        while let Some(&c) = self.b.get(self.i) {
            if c.is_ascii_digit() || matches!(c, '-' | '+' | '.' | 'e' | 'E') {
                self.i += 1;
            } else {
                break;
            }
        }
        if self.i == start {
            return None;
        }
        let s: String = self.b[start..self.i].iter().collect();
        s.parse::<f64>().ok().map(Json::Num)
    }

    fn string(&mut self) -> Option<String> {
        if self.b.get(self.i) != Some(&'"') {
            return None;
        }
        self.i += 1;
        let mut s = String::new();
        while let Some(&c) = self.b.get(self.i) {
            self.i += 1;
            match c {
                '"' => return Some(s),
                '\\' => {
                    let e = *self.b.get(self.i)?;
                    self.i += 1;
                    match e {
                        '"' => s.push('"'),
                        '\\' => s.push('\\'),
                        '/' => s.push('/'),
                        'n' => s.push('\n'),
                        't' => s.push('\t'),
                        'r' => s.push('\r'),
                        'b' => s.push('\u{8}'),
                        'f' => s.push('\u{c}'),
                        'u' => {
                            // Astral code points arrive as a UTF-16 surrogate pair
                            // of escapes; a lone surrogate decodes to U+FFFD.
                            let code = self.hex4()?;
                            let ch = if (0xD800..0xDC00).contains(&code) {
                                self.low_surrogate()
                                    .map(|lo| 0x10000 + ((code - 0xD800) << 10) + (lo - 0xDC00))
                                    .and_then(char::from_u32)
                            } else {
                                char::from_u32(code)
                            };
                            s.push(ch.unwrap_or(char::REPLACEMENT_CHARACTER));
                        }
                        _ => return None,
                    }
                }
                c => s.push(c),
            }
        }
        None
    }

    /// Four hex digits of a `\uXXXX` escape, consumed.
    fn hex4(&mut self) -> Option<u32> {
        let mut code = 0u32;
        for _ in 0..4 {
            code = code * 16 + self.b.get(self.i)?.to_digit(16)?;
            self.i += 1;
        }
        Some(code)
    }

    /// A `\uXXXX` low surrogate (DC00..=DFFF) following a high one, consumed
    /// only if present — anything else is left for the main loop.
    fn low_surrogate(&mut self) -> Option<u32> {
        if self.b.get(self.i) != Some(&'\\') || self.b.get(self.i + 1) != Some(&'u') {
            return None;
        }
        let save = self.i;
        self.i += 2;
        match self.hex4() {
            Some(lo) if (0xDC00..0xE000).contains(&lo) => Some(lo),
            _ => {
                self.i = save;
                None
            }
        }
    }

    fn array(&mut self) -> Option<Json> {
        self.i += 1; // '['
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&']') {
            self.i += 1;
            return Some(Json::Arr(out));
        }
        loop {
            out.push(self.value()?);
            self.ws();
            match self.b.get(self.i) {
                Some(',') => {
                    self.i += 1;
                }
                Some(']') => {
                    self.i += 1;
                    return Some(Json::Arr(out));
                }
                _ => return None,
            }
        }
    }

    fn object(&mut self) -> Option<Json> {
        self.i += 1; // '{'
        let mut out = Vec::new();
        self.ws();
        if self.b.get(self.i) == Some(&'}') {
            self.i += 1;
            return Some(Json::Obj(out));
        }
        loop {
            self.ws();
            let key = self.string()?;
            self.ws();
            if self.b.get(self.i) != Some(&':') {
                return None;
            }
            self.i += 1;
            let val = self.value()?;
            out.push((key, val));
            self.ws();
            match self.b.get(self.i) {
                Some(',') => {
                    self.i += 1;
                }
                Some('}') => {
                    self.i += 1;
                    return Some(Json::Obj(out));
                }
                _ => return None,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn navigates_objects_and_arrays() {
        let j = Json::parse(r#"{"a":{"b":[10,20,30]},"s":"hi"}"#).unwrap();
        assert_eq!(j.get_key("s").unwrap().as_text().as_deref(), Some("hi"));
        let b = j.extract_path("$.a.b[1]").unwrap();
        assert_eq!(b.as_text().as_deref(), Some("20"));
        assert_eq!(
            j.extract_path("$.a.b[-1]").unwrap().as_text().as_deref(),
            Some("30")
        );
        assert!(j.get_key("missing").is_none());
    }

    #[test]
    fn decodes_surrogate_pairs() {
        let text = |src: &str| Json::parse(src).unwrap().as_text();
        assert_eq!(text(r#""\ud83e\udd80""#).as_deref(), Some("🦀"));
        // Lone surrogates (high without low, bare low) become U+FFFD, and a high
        // surrogate never swallows a following non-low escape.
        assert_eq!(text(r#""\ud83ex""#).as_deref(), Some("�x"));
        assert_eq!(text(r#""\udd80""#).as_deref(), Some("�"));
        assert_eq!(text(r#""\ud83e\u0041""#).as_deref(), Some("�A"));
        assert_eq!(text(r#""\ud83e\n""#).as_deref(), Some("�\n"));
    }

    #[test]
    fn reserializes_compactly() {
        let j = Json::parse(r#"{ "x" : [1, 2] }"#).unwrap();
        assert_eq!(j.to_json_text(), r#"{"x":[1,2]}"#);
    }
}
