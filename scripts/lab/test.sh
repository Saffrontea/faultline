#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:test must run as root" >&2
    exit 1
fi

cleanup() {
    "$LAB_DIR/down.sh"
}
trap cleanup EXIT INT TERM

echo "LXC lab: starting"
"$LAB_DIR/up.sh"

echo "LXC lab: baseline"
"$LAB_DIR/baseline.sh"

echo "LXC lab: deterministic hash loss"
LOSS_ALGORITHM=hash "$LAB_DIR/loss.sh"

echo "LXC lab: random loss"
LOSS_ALGORITHM=random "$LAB_DIR/loss.sh"

echo "LXC lab: multiple-rule scenario"
SCENARIO="$LAB_DIR/../../scenarios/lab.yaml" "$LAB_DIR/loss.sh"

"$LAB_DIR/impairments.sh"

echo "LXC lab: all scenarios passed"
