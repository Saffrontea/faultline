#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"

for license_file in LICENSE-APACHE LICENSE-MIT LICENSE-GPL-2.0; do
  if [[ ! -s "$license_file" ]]; then
    echo "missing or empty project license: $license_file" >&2
    exit 1
  fi
done

if ! grep -Fqx 'license = "MIT OR Apache-2.0"' Cargo.toml; then
  echo 'workspace license must be MIT OR Apache-2.0' >&2
  exit 1
fi

if ! grep -Fqx 'license = "MIT OR GPL-2.0-only"' faultline-ebpf/Cargo.toml; then
  echo 'faultline-ebpf license must be MIT OR GPL-2.0-only' >&2
  exit 1
fi

if ! grep -Fqx 'static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";' faultline-ebpf/src/main.rs; then
  echo 'eBPF object license must be Dual MIT/GPL' >&2
  exit 1
fi
