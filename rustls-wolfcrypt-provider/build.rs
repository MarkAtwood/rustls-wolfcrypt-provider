//! Build script for rustls-wolfcrypt-provider.
//!
//! Mirrors the feature-detection logic in wolfssl-wolfcrypt's build.rs so that
//! the same `cfg` flags (e.g. `ed25519`) are available to this crate's source
//! files.  This is necessary because Cargo does not propagate `cargo:rustc-cfg`
//! from a dependency's build script to its downstream dependents.
//!
//! The only source of truth is the wolfssl `options.h` header, which is
//! located by consulting the same `WOLFSSL_PREFIX` environment variable that
//! wolfssl-wolfcrypt uses.

use std::env;
use std::fs;
use std::path::Path;

fn main() {
    // Locate options.h using the same priority as wolfssl-wolfcrypt's build.rs:
    //   1. WOLFSSL_PREFIX/include/wolfssl/options.h
    //   2. ../../../wolfssl/options.h  (in-tree layout)
    let options_h = find_options_h();

    // Declare the custom cfgs we may emit so the compiler doesn't warn.
    println!("cargo::rustc-check-cfg=cfg(ed25519)");

    let Some(path) = options_h else {
        // No wolfssl found — emit no feature cfgs.  The code will compile
        // without ed25519 support.
        return;
    };

    println!("cargo:rerun-if-changed={}", path.display());

    let content = fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("Failed to read {}: {}", path.display(), e));

    if content.contains("HAVE_ED25519") && content.contains("#define HAVE_ED25519") {
        println!("cargo:rustc-cfg=ed25519");
    }
}

fn find_options_h() -> Option<std::path::PathBuf> {
    // Priority 1: WOLFSSL_PREFIX env var (set in .cargo/config.toml).
    if let Ok(prefix) = env::var("WOLFSSL_PREFIX") {
        let candidate = Path::new(&prefix)
            .join("include")
            .join("wolfssl")
            .join("options.h");
        if candidate.is_file() {
            return Some(candidate);
        }
    }

    // Priority 2: in-tree layout (crate is three levels deep inside wolfssl repo).
    // rustls-wolfcrypt-provider/ is at wolfssl/wrapper/rust/rustls-wolfcrypt-provider/
    // so ../../../wolfssl/options.h would be wolfssl/wolfssl/options.h.
    if let Ok(manifest_dir) = env::var("CARGO_MANIFEST_DIR") {
        let candidate = Path::new(&manifest_dir)
            .join("../../../wolfssl/options.h");
        if candidate.is_file() {
            return Some(candidate.canonicalize().unwrap_or(candidate));
        }
    }

    None
}
