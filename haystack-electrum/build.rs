//! Records which source built this client, for the session log's provenance field: a structural
//! attacker trained on sessions from one client must not score sessions from another
//! (`docs/04-roadmap.md`, Week 3 safeguard 1).

use std::fs;
use std::path::{Path, PathBuf};

use bitcoin_hashes::{sha256, Hash, HashEngine};

fn files(dir: &Path, out: &mut Vec<PathBuf>) {
    for entry in fs::read_dir(dir).expect("readable source directory") {
        let path = entry.expect("readable entry").path();
        if path.is_dir() {
            files(&path, out);
        } else {
            out.push(path);
        }
    }
}

fn main() {
    let root = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").expect("set by cargo"));
    let mut paths = vec![root.join("Cargo.toml")];
    files(&root.join("src"), &mut paths);
    paths.sort();
    let mut engine = sha256::Hash::engine();
    for path in &paths {
        let name = path.strip_prefix(&root).expect("under the crate").to_string_lossy();
        let body = fs::read(path).expect("readable source file");
        // Length-prefixed, so moving bytes between a name and a body changes the hash.
        for part in [name.as_bytes(), &body] {
            engine.input(&(part.len() as u64).to_be_bytes());
            engine.input(part);
        }
    }
    let digest = sha256::Hash::from_engine(engine).to_byte_array();
    let hex: String = digest[..16].iter().map(|b| format!("{b:02x}")).collect();
    println!("cargo:rustc-env=HAYSTACK_SOURCE_HASH={hex}");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
}
