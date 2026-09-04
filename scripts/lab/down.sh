#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:down must run as root" >&2
    exit 1
fi

for name in faultline-client faultline-server; do
    if lxc-info -n "$name" >/dev/null 2>&1; then
        lxc-stop -n "$name" -k 2>/dev/null || true
    fi
done
ip link delete faultlinebr0 type bridge 2>/dev/null || true

echo "LXC lab is stopped"
