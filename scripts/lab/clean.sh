#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:clean must run as root" >&2
    exit 1
fi

"$LAB_DIR/down.sh"
for name in faultline-client faultline-server; do
    if lxc-info -n "$name" >/dev/null 2>&1; then
        lxc-destroy -n "$name"
    fi
done

echo "LXC lab containers were destroyed"
