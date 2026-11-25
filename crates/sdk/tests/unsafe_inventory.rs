//! The workspace has exactly one `unsafe` block: `OwnedFd::from_raw_fd` in
//! `crates/sdk/src/env_fd.rs` (docs/proof-register.md, A14). This test fails
//! if `unsafe` code appears anywhere else in the repository's Rust sources
//! (workspace crates, adapters, enforcement, fuzz targets, proofs).

use std::path::{Path, PathBuf};

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    let Ok(rd) = std::fs::read_dir(dir) else {
        return;
    };
    for e in rd.flatten() {
        let p = e.path();
        let name = e.file_name();
        if p.is_dir() {
            if name == "target" || name == ".git" {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs") {
            out.push(p);
        }
    }
}

/// `unsafe` as a keyword introducing code (block, fn, impl, trait, extern),
/// outside `//` comments.
fn unsafe_uses(src: &str) -> Vec<usize> {
    let mut hits = Vec::new();
    for (i, line) in src.lines().enumerate() {
        let code = line.split("//").next().unwrap_or("");
        let mut rest = code;
        while let Some(pos) = rest.find("unsafe") {
            let before = rest[..pos].chars().last();
            let after = &rest[pos + "unsafe".len()..];
            let word_start = before.is_none_or(|c| !(c.is_alphanumeric() || c == '_'));
            let next = after.trim_start();
            let keyword = after.starts_with(char::is_whitespace) || after.starts_with('{');
            if word_start
                && keyword
                && ["{", "fn", "impl", "trait", "extern"]
                    .iter()
                    .any(|k| next.starts_with(k))
            {
                hits.push(i + 1);
            }
            rest = after;
        }
    }
    hits
}

#[test]
fn env_fd_is_the_only_unsafe_code() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    let mut files = Vec::new();
    rust_files(&root, &mut files);
    assert!(
        files.len() > 50,
        "scan found too few files: {}",
        files.len()
    );
    let mut found = Vec::new();
    for f in files {
        // This file's own detector self-test strings.
        if f.ends_with("crates/sdk/tests/unsafe_inventory.rs") {
            continue;
        }
        let src = std::fs::read_to_string(&f).unwrap_or_default();
        for line in unsafe_uses(&src) {
            let rel = f.strip_prefix(&root).unwrap_or(&f).display().to_string();
            found.push(format!("{rel}:{line}"));
        }
    }
    assert_eq!(found.len(), 1, "unsafe code outside env_fd.rs: {found:?}");
    assert!(
        found[0].starts_with("crates/sdk/src/env_fd.rs:"),
        "{found:?}"
    );
    // The detector itself works.
    assert_eq!(unsafe_uses("let x = unsafe { f() };"), vec![1]);
    assert_eq!(
        unsafe_uses("// unsafe { }\nunsafe_code = 1"),
        Vec::<usize>::new()
    );
    assert_eq!(unsafe_uses("pub unsafe fn f() {}"), vec![1]);
}
