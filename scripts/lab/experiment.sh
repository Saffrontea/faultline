#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
CLIENT=faultline-client
output=$(mktemp /tmp/faultline-experiment.XXXXXX)

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:experiment must run as root" >&2
    exit 1
fi

cleanup() {
    rm -f "$output" "$output.resolved.json"
}
trap cleanup EXIT INT TERM

install -D -m 0755 "$WORKSPACE/target/release/faultline-agent" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-agent"
install -D -m 0755 "$WORKSPACE/target/release/faultline-engine" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-engine"

"$TUI" \
    --experiment "$WORKSPACE/experiments/lab-outage.yaml" \
    --agent /usr/local/bin/faultline-agent \
    --engine /usr/local/bin/faultline-engine \
    --resolved-output "$output.resolved.json" \
    --snapshot-after-ms 3500 >"$output"

grep -q '"networks"' "$output.resolved.json"
grep -q '10.203.0.3/32' "$output.resolved.json"

grep -q '✓ Provision.*✓ Connect.*✓ Impair.*● Observe' "$output"
grep -Eq 'matched +[1-9][0-9]*' "$output"
grep -Eq 'TRAFFIC ok +[1-9][0-9]* fail +[1-9][0-9]*' "$output"
grep -q '10.203.0.3/32' "$output"

echo "Experiment TUI observed baseline, outage, recovery, and generated traffic:"
grep -E 'Provision|matched|NOW loss|TRAFFIC' "$output"
