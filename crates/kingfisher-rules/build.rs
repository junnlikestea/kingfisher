use std::fs;
use std::path::Path;

fn main() {
    let data_dir = Path::new("data");
    println!("cargo:rerun-if-changed={}", data_dir.display());
    emit_rerun_for_tree(data_dir);
}

fn emit_rerun_for_tree(path: &Path) {
    let Ok(entries) = fs::read_dir(path) else {
        return;
    };

    for entry in entries.flatten() {
        let p = entry.path();
        if p.is_dir() {
            emit_rerun_for_tree(&p);
            continue;
        }

        println!("cargo:rerun-if-changed={}", p.display());
    }
}
