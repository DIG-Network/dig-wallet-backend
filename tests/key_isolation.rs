//! Normative test for the key-isolation invariant (SPEC §1.4) — the foundational custody contract.
//!
//! The private key MUST live only behind the client seam's signer. Neither the engine seam NOR the
//! shared `types` layer (which the engine imports) may name a secret-bearing identifier — a secret
//! smuggled through `types` would evade an engine-only scan, so BOTH trees are scanned here. This
//! source-level check is the real API-isolation enforcer; the CI standalone-build job is a weaker,
//! complementary signal (the `chia` crate that defines `SecretKey` is a non-optional dependency and
//! is always linked, so "compiles without the secret type" is NOT provable by feature-gating alone).

use std::fs;
use std::path::{Path, PathBuf};

/// Identifiers that denote secret key / seed material. None may appear in the scanned trees.
///
/// Substring matching also catches `as`-aliased re-exports: `use chia::bls::SecretKey as Sk;` and
/// `type Foo = SecretKey;` both contain the forbidden token, so aliasing a secret type under a
/// benign name is caught at its declaration site (and `types` is scanned, so a re-export there is
/// caught before the engine could import the alias).
const FORBIDDEN: &[&str] = &[
    "SecretKey",
    "PrivateKey",
    "SigningKey",
    "Keypair",
    "Mnemonic",
    "Seed",
    "master_sk",
    "from_seed",
    "from_mnemonic",
];

/// Strip a Rust line's `//` comment tail, but ONLY when the `//` is real code — a `//` inside a
/// string literal (e.g. `"http://…"`) must NOT truncate the line, or a secret token AFTER such a
/// string on the same line would be masked (a false negative). Tracks double-quoted string state
/// (honouring `\` escapes) and returns the code portion.
fn strip_comment(line: &str) -> &str {
    let bytes = line.as_bytes();
    let mut in_string = false;
    let mut escaped = false;
    let mut i = 0;
    while i < bytes.len() {
        let c = bytes[i];
        if in_string {
            if escaped {
                escaped = false;
            } else if c == b'\\' {
                escaped = true;
            } else if c == b'"' {
                in_string = false;
            }
        } else if c == b'"' {
            in_string = true;
        } else if c == b'/' && bytes.get(i + 1) == Some(&b'/') {
            return &line[..i];
        }
        i += 1;
    }
    line
}

/// Recursively collect every `.rs` file under `dir`.
fn rs_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("read source dir") {
        let path = entry.expect("dir entry").path();
        if path.is_dir() {
            rs_files(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

#[test]
fn engine_and_types_source_name_no_secret_key_type() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
    let mut files = Vec::new();
    // Scan BOTH the engine seam and the shared types layer it imports. The client seam is deliberately
    // excluded — LocalSigner legitimately holds the key there.
    rs_files(&root.join("engine"), &mut files);
    rs_files(&root.join("types"), &mut files);
    assert!(!files.is_empty(), "expected source files under {root:?}");

    let mut violations = Vec::new();
    for file in &files {
        let source = fs::read_to_string(file).expect("read source");
        for (lineno, line) in source.lines().enumerate() {
            let code = strip_comment(line);
            for needle in FORBIDDEN {
                if code.contains(needle) {
                    violations.push(format!("{}:{}: `{needle}`", file.display(), lineno + 1));
                }
            }
        }
    }

    assert!(
        violations.is_empty(),
        "engine seam + shared types must not reference secret-key material (SPEC §1.4 key isolation):\n{}",
        violations.join("\n")
    );
}

#[cfg(test)]
mod strip_comment_tests {
    use super::strip_comment;

    #[test]
    fn strips_a_real_comment() {
        assert_eq!(
            strip_comment("let x = 1; // SecretKey in a comment").trim(),
            "let x = 1;"
        );
    }

    #[test]
    fn does_not_strip_slashes_inside_a_string() {
        // The `//` here is inside a string literal; a token AFTER it must remain visible.
        let line = r#"let u = "http://x"; let k = SecretKey;"#;
        assert!(strip_comment(line).contains("SecretKey"));
    }

    #[test]
    fn handles_escaped_quote_in_string() {
        let line = r#"let s = "a\"b"; // SecretKey"#;
        assert!(!strip_comment(line).contains("SecretKey"));
    }
}
