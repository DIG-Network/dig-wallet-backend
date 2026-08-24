//! Dependency-graph half of the key-isolation invariant (SPEC §1.4, dig-wallet-backend#47).
//!
//! `tests/key_isolation.rs` scans engine SOURCE TEXT, so it catches a secret type that engine code
//! *names*. It cannot catch the other direction: a secret-key crate added to the `engine` feature
//! list, whose types are never spelled in engine source. That change compiles, keeps the source scan
//! green, and keeps the CI "engine seam builds standalone" job green — while silently linking secret
//! key material into the seam five consumers take *because* it carries none.
//!
//! This test closes that direction by asserting a property of the **resolved dependency graph** for
//! `--no-default-features --features engine`.
//!
//! ## Why DIRECT dependencies, and not the whole transitive graph
//!
//! The full transitive engine graph already contains secret-key crates and cannot be made not to:
//! `chia-bls` (via the protocol wire types), `bip39` (via `chia-sdk-driver`), `rsa` (via `chia-ssl`)
//! and `k256` (via `clvmr`) are all reachable today. A whole-graph assertion would be red on an
//! untouched tree, so it would be deleted or blanket-allowed within a week and would guard nothing.
//!
//! The line this crate actually controls — and the one #47 names — is its own manifest: the set of
//! dependencies the `engine` feature activates. That set is small, deliberate, and reviewed, and it is
//! exactly what "a secret-key crate added to the engine feature list" changes.
//!
//! ## Why a property, not a crate-name list
//!
//! An enumerated ban-list only bans what someone thought to enumerate. So the check asks a question of
//! each dependency's own source — does it expose secret-key material on its public surface? — and
//! carries an explicit, justified allow-list for the two crates deliberately permitted.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::process::Command;

/// Tokens that name secret key / seed material on a public surface.
///
/// Type-name tokens only. Deliberately NOT `Seed`/`from_seed`: those appear on benign public APIs
/// across the ecosystem (RNG seeding, hash seeds) and would make the property fire on crates that
/// carry no key material, which is how a guard earns a blanket allow-list and stops guarding.
const SECRET_SURFACE_TOKENS: &[&str] = &[
    "SecretKey",
    "PrivateKey",
    "SigningKey",
    "Keypair",
    "KeyPair",
    "Mnemonic",
    "master_sk",
    "from_mnemonic",
];

/// Dependencies deliberately permitted under `engine` despite exposing secret-key surface.
///
/// Each entry is a decision, not an exemption granted by accident. Adding a row here is the ONLY
/// sanctioned way to widen the engine seam's key surface, and it is a custody decision (#908).
const ALLOWED: &[(&str, &str)] = &[
    (
        "chia-bls",
        "Defines the BLS wire types the protocol is expressed in (PublicKey, Signature) and cannot be split from them. Its SecretKey path is never named in engine source — that is what tests/key_isolation.rs enforces, and the two checks are complementary.",
    ),
    (
        "chia-wallet-sdk",
        "The canonical spend-driver crate (§4.1: never hand-rolled CLVM). Its prelude re-exports chia_bls::SecretKey; the engine composes only the key-free builder and RequiredSignature paths, which tests/key_isolation.rs holds by scanning engine source.",
    ),
];

/// Does this dependency expose secret-key material on its PUBLIC surface?
///
/// Scans the crate's own `src` for a public item (`pub …`, including `pub use` re-exports) naming a
/// secret token. Returns the hits so a failure names the evidence rather than only a verdict.
fn public_secret_surface(package_root: &Path) -> Vec<String> {
    let mut hits = Vec::new();
    let mut files = Vec::new();
    collect_rs(&package_root.join("src"), &mut files);
    for file in files {
        let Ok(source) = std::fs::read_to_string(&file) else {
            continue;
        };
        for (lineno, line) in source.lines().enumerate() {
            let code = line.split("//").next().unwrap_or("").trim();
            if !(code.starts_with("pub ") || code.contains("pub use")) {
                continue;
            }
            for token in SECRET_SURFACE_TOKENS {
                if code.contains(token) {
                    hits.push(format!(
                        "{}:{}: `{token}` in `{code}`",
                        file.display(),
                        lineno + 1
                    ));
                }
            }
        }
    }
    hits
}

/// Recursively collect every `.rs` file under `dir`. A missing directory yields nothing.
fn collect_rs(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_rs(&path, out);
        } else if path.extension().is_some_and(|e| e == "rs") {
            out.push(path);
        }
    }
}

/// The `(name, source_root)` of every non-dev dependency the `engine` feature activates.
fn direct_engine_dependencies() -> Vec<(String, PathBuf)> {
    let manifest = Path::new(env!("CARGO_MANIFEST_DIR")).join("Cargo.toml");
    let output = Command::new(std::env::var("CARGO").unwrap_or_else(|_| "cargo".into()))
        .args([
            "metadata",
            "--format-version",
            "1",
            "--no-default-features",
            "--features",
            "engine",
            "--manifest-path",
        ])
        .arg(&manifest)
        .output()
        .expect("run `cargo metadata`");
    assert!(
        output.status.success(),
        "`cargo metadata` failed — this guard cannot run, which is a FAILURE and not a skip:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );

    let meta: serde_json::Value =
        serde_json::from_slice(&output.stdout).expect("parse cargo metadata JSON");
    let resolve = &meta["resolve"];
    let root_id = resolve["root"].as_str().expect("resolve.root");
    let root_node = resolve["nodes"]
        .as_array()
        .expect("resolve.nodes")
        .iter()
        .find(|n| n["id"].as_str() == Some(root_id))
        .expect("root node present in resolve graph");

    let mut wanted = BTreeSet::new();
    for dep in root_node["deps"].as_array().expect("root deps") {
        // A dependency reached ONLY as a dev-dependency is out of scope: dev-deps are not linked
        // into the engine seam consumers build. `dig-did`, `bip39` and `chia-sdk-test` are dev-deps
        // of this crate and must not be mistaken for engine surface.
        let kinds: BTreeSet<Option<&str>> = dep["dep_kinds"]
            .as_array()
            .map(|ks| ks.iter().map(|k| k["kind"].as_str()).collect())
            .unwrap_or_default();
        if !kinds.is_empty() && kinds.iter().all(|k| *k == Some("dev")) {
            continue;
        }
        wanted.insert(dep["pkg"].as_str().expect("dep pkg id").to_string());
    }

    let mut out = Vec::new();
    for package in meta["packages"].as_array().expect("packages") {
        let id = package["id"].as_str().unwrap_or_default();
        if !wanted.contains(id) {
            continue;
        }
        let manifest_path =
            PathBuf::from(package["manifest_path"].as_str().expect("manifest_path"));
        let root = manifest_path
            .parent()
            .expect("manifest has a parent dir")
            .to_path_buf();
        out.push((
            package["name"].as_str().expect("package name").to_string(),
            root,
        ));
    }
    assert!(
        !out.is_empty(),
        "resolved zero direct engine dependencies — the graph query is broken, not the graph"
    );
    out
}

/// The invariant: no dependency the `engine` feature activates may expose secret-key material,
/// except the explicitly justified allow-list.
#[test]
fn engine_feature_activates_no_unvetted_secret_key_crate() {
    let allowed: BTreeSet<&str> = ALLOWED.iter().map(|(name, _)| *name).collect();

    let mut violations = Vec::new();
    for (name, root) in direct_engine_dependencies() {
        if allowed.contains(name.as_str()) {
            continue;
        }
        let hits = public_secret_surface(&root);
        if !hits.is_empty() {
            violations.push(format!(
                "`{name}` exposes secret-key material and is not on the justified allow-list:\n    {}",
                hits.iter()
                    .take(3)
                    .cloned()
                    .collect::<Vec<_>>()
                    .join("\n    ")
            ));
        }
    }

    assert!(
        violations.is_empty(),
        "the `engine` feature activates a secret-key crate (SPEC §1.4 key isolation, #908).\n\
         The engine seam is imported by consumers precisely because it links no key material.\n\
         Either drop the dependency, move it behind the `client` feature, or add a justified row to \
         ALLOWED in this file:\n\n{}",
        violations.join("\n")
    );
}

/// Positive control: the allow-listed crates MUST still be detected as secret-bearing.
///
/// Without this, a detector that silently found nothing — a wrong source root, a registry layout
/// change, an unreadable directory — would report an empty violation list and pass. That is the
/// sweep-over-an-empty-haystack false green, and it is the failure mode most likely to outlive
/// everyone who remembers this file. If a row here stops firing, the crate genuinely stopped exposing
/// secret material and the allow-list row should be DELETED, not the assertion.
#[test]
fn the_detector_still_detects_the_crates_it_allows() {
    let deps = direct_engine_dependencies();
    for (name, why) in ALLOWED {
        let Some((_, root)) = deps.iter().find(|(n, _)| n == name) else {
            panic!(
                "allow-listed `{name}` is no longer a direct engine dependency — delete its ALLOWED row ({why})"
            );
        };
        assert!(
            !public_secret_surface(root).is_empty(),
            "`{name}` no longer exposes secret-key material, so the detector cannot be shown to work against it. Delete its ALLOWED row rather than weakening this control."
        );
    }
}
