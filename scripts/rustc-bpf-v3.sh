#!/bin/sh
set -eu

rustc=$1
shift
is_bpf=false
expect_target=false
for argument in "$@"; do
    if [ "$expect_target" = true ]; then
        case "$argument" in
            bpfel-unknown-none|bpfeb-unknown-none) is_bpf=true ;;
        esac
        expect_target=false
    fi
    case "$argument" in
        --target) expect_target=true ;;
        --target=bpfel-unknown-none|--target=bpfeb-unknown-none) is_bpf=true ;;
    esac
done

if [ "$is_bpf" = true ]; then
    set -- "$@" -Ctarget-cpu=v3
fi

if [ -n "${FAULTLINE_RUSTC_WRAPPER_NEXT:-}" ]; then
    exec "$FAULTLINE_RUSTC_WRAPPER_NEXT" "$rustc" "$@"
fi
exec "$rustc" "$@"
