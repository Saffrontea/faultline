use std::{env, fs, path::Path};

use anyhow::{Context as _, anyhow};
use aya_build::Toolchain;
use object::{Object as _, ObjectSymbol as _, SymbolSection};

fn main() -> anyhow::Result<()> {
    let manifest_dir = env::var("CARGO_MANIFEST_DIR").context("CARGO_MANIFEST_DIR is not set")?;
    let rustc_wrapper = Path::new(&manifest_dir)
        .parent()
        .with_context(|| format!("{} has no workspace parent", env!("CARGO_PKG_NAME")))?
        .join("scripts/rustc-bpf-v3.sh");
    println!("cargo:rerun-if-changed={}", rustc_wrapper.display());
    if let Some(existing) = env::var_os("RUSTC_WRAPPER") {
        unsafe { env::set_var("FAULTLINE_RUSTC_WRAPPER_NEXT", existing) };
    }
    unsafe { env::set_var("RUSTC_WRAPPER", rustc_wrapper) };

    let cargo_metadata::Metadata { packages, .. } = cargo_metadata::MetadataCommand::new()
        .no_deps()
        .exec()
        .context("reading Cargo metadata")?;
    let package = packages
        .into_iter()
        .find(|package| package.name.as_str() == "faultline-ebpf")
        .ok_or_else(|| anyhow!("faultline-ebpf package not found"))?;
    let root_dir = package
        .manifest_path
        .parent()
        .ok_or_else(|| anyhow!("eBPF manifest has no parent directory"))?;

    aya_build::build_ebpf(
        [aya_build::Package {
            name: package.name.as_str(),
            root_dir: root_dir.as_str(),
            ..Default::default()
        }],
        Toolchain::default(),
    )?;

    validate_bpf_elf(
        Path::new(&env::var_os("OUT_DIR").context("OUT_DIR is not set")?).join("faultline"),
    )
}

fn validate_bpf_elf(path: impl AsRef<Path>) -> anyhow::Result<()> {
    let path = path.as_ref();
    let bytes = fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let object = object::File::parse(bytes.as_slice())
        .with_context(|| format!("parsing {}", path.display()))?;
    let undefined = object
        .symbols()
        .filter(|symbol| symbol.section() == SymbolSection::Undefined)
        .filter_map(|symbol| symbol.name().ok())
        .filter(|name| !name.is_empty())
        .collect::<Vec<_>>();
    if !undefined.is_empty() {
        return Err(anyhow!(
            "BPF object contains unresolved symbols that Aya cannot relocate: {}",
            undefined.join(", ")
        ));
    }
    Ok(())
}
