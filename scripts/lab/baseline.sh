#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:baseline must run as root" >&2
    exit 1
fi

lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab client \
    --address 10.203.0.3:8080 --requests 100 --timeout-ms 500 --require-success
