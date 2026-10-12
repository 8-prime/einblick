use std::{env, fs, path::PathBuf};
mod ebpf_validation;
fn main() {
    println!("cargo:rerun-if-changed=ebpf_validation.rs");
    println!("cargo:rerun-if-env-changed=EINBLICK_EBPF_OBJECT");
    println!("cargo:rerun-if-changed=../../frontend/dist");
    let out = PathBuf::from(env::var_os("OUT_DIR").unwrap());
    let bytes = if let Some(path) = env::var_os("EINBLICK_EBPF_OBJECT") {
        println!("cargo:rerun-if-changed={}", PathBuf::from(&path).display());
        let bytes = fs::read(path).expect("read EINBLICK_EBPF_OBJECT");
        ebpf_validation::validate(&bytes).expect("validate embedded eBPF object");
        bytes
    } else {
        Vec::new()
    };
    fs::write(out.join("einblick-ebpf"), bytes).unwrap();
    fn copy(from: &std::path::Path, to: &std::path::Path) {
        fs::create_dir_all(to).unwrap();
        for entry in fs::read_dir(from).unwrap() {
            let entry = entry.unwrap();
            let dest = to.join(entry.file_name());
            if entry.path().is_dir() {
                copy(&entry.path(), &dest);
            } else {
                fs::copy(entry.path(), dest).unwrap();
            }
        }
    }
    let web = out.join("web");
    if std::path::Path::new("../../frontend/dist/index.html").exists() {
        copy(std::path::Path::new("../../frontend/dist"), &web);
    } else {
        fs::create_dir_all(&web).unwrap();
        fs::write(web.join("index.html"), "<!doctype html><title>Einblick</title><p>Build the dashboard with pnpm --dir frontend build, then rebuild the server.</p>").unwrap();
    }
    println!("cargo:rustc-env=OUT_DIR={}", out.display());
}
