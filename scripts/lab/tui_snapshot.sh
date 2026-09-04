#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
CLIENT=faultline-client
CLIENT_CMD="lxc-attach -n $CLIENT -- /usr/local/bin/faultline-lab"
output=$(mktemp /tmp/faultline-snapshot.XXXXXX)
tui_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:tui must run as root" >&2
    exit 1
fi

cleanup() {
    status=$?
    if [ -n "$tui_pid" ]; then
        kill "$tui_pid" 2>/dev/null || true
        wait "$tui_pid" 2>/dev/null || true
    fi
    if [ "$status" -ne 0 ] && [ -s "$output" ]; then
        echo "TUI snapshot at failure:" >&2
        cat "$output" >&2
    fi
    rm -f "$output"
}
trap cleanup EXIT INT TERM

install -D -m 0755 "$WORKSPACE/target/release/faultline-agent" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-agent"
install -D -m 0755 "$WORKSPACE/target/release/faultline-engine" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-engine"

"$TUI" "lxc://$CLIENT/eth0" \
    --agent /usr/local/bin/faultline-agent \
    --engine /usr/local/bin/faultline-engine \
    --destination 10.203.0.3/32 \
    --snapshot-after-ms 3000 >"$output" &
tui_pid=$!

sleep 0.4
$CLIENT_CMD client --address 10.203.0.3:8080 \
    --requests 100 --interval-ms 20 --timeout-ms 200 --require-success

wait "$tui_pid"
tui_pid=

grep -q 'lxc://faultline-client/eth0 \[egress\]' "$output"
grep -Eq 'matched +[1-9][0-9]*' "$output"
grep -q 'pkt/s' "$output"
grep -q 'WIRE' "$output"
grep -q 'MISS DST' "$output"
grep -q 'MISS PROTO' "$output"

echo "Rendered TUI snapshot contains live egress stats:"
grep -E 'lxc://|matched|NOW loss|WIRE|MISS DST|MISS PROTO' "$output"

$CLIENT_CMD client --address 10.203.0.3:8080 \
    --requests 3 --timeout-ms 300 --require-success
echo "TUI snapshot session detached the dataplane"
