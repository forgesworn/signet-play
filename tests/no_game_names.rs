//! Kit rule 10: no game names in a kit crate. The app id, name and
//! callback are parameters. A name may appear in test code (below the file's
//! `#[cfg(test)] mod tests`, in `tests.rs`) and in `vectors/`, nowhere else.

use std::path::{Path, PathBuf};

const NAMES: [&str; 2] = ["twang", "axenstax"];

fn rust_files(dir: &Path, out: &mut Vec<PathBuf>) {
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            if p.file_name().is_some_and(|n| n == "vectors") {
                continue;
            }
            rust_files(&p, out);
        } else if p.extension().is_some_and(|x| x == "rs")
            && p.file_name().is_some_and(|n| n != "tests.rs")
        {
            out.push(p);
        }
    }
}

#[test]
fn no_game_name_outside_test_code() {
    let mut files = Vec::new();
    rust_files(
        &Path::new(env!("CARGO_MANIFEST_DIR")).join("src"),
        &mut files,
    );
    assert!(files.len() > 8, "found the sources");
    let mut hits = Vec::new();
    for f in files {
        let text = std::fs::read_to_string(&f).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        // The test module starts at a `#[cfg(test)]` that is followed by a `mod tests`.
        let tests_from = lines
            .iter()
            .enumerate()
            .position(|(i, l)| {
                l.trim() == "#[cfg(test)]"
                    && lines.get(i + 1).is_some_and(|n| n.contains("mod tests"))
            })
            .unwrap_or(lines.len());
        for (i, l) in lines.iter().enumerate().take(tests_from) {
            let lower = l.to_lowercase();
            if NAMES.iter().any(|n| lower.contains(n)) {
                hits.push(format!("{}:{}: {}", f.display(), i + 1, l.trim()));
            }
        }
    }
    assert!(
        hits.is_empty(),
        "game names in kit code:\n{}",
        hits.join("\n")
    );
}
