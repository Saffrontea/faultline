fn main() {
    let bpf_linker =
        which::which("bpf-linker").expect("bpf-linker is required; run `mise run setup`");
    println!("cargo:rerun-if-changed={}", bpf_linker.display());
}
