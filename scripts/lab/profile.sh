#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
AGENT=$WORKSPACE/target/release/faultline-agent
ENGINE=$WORKSPACE/target/release/faultline-engine
PROFILE=$WORKSPACE/profiles/brief-outage.yaml
CLIENT="lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab"
output=$(mktemp /tmp/faultline-profile.XXXXXX)
tui_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:profile must run as root" >&2
    exit 1
fi

cleanup() {
    if [ -n "$tui_pid" ]; then
        kill "$tui_pid" 2>/dev/null || true
        wait "$tui_pid" 2>/dev/null || true
    fi
    rm -f "$output"
}
trap cleanup EXIT INT TERM

"$TUI" local://flt-client0 \
    --agent "$AGENT" \
    --engine "$ENGINE" \
    --direction ingress \
    --profile "$PROFILE" >"$output" &
tui_pid=$!

attempt=0
while ! grep -q 'applied event 0' "$output" && [ "$attempt" -lt 50 ]; do
    if ! kill -0 "$tui_pid" 2>/dev/null; then
        wait "$tui_pid"
        cat "$output" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.05
done
grep -q 'applied event 0' "$output"

echo "Profile phase 0: traffic passes"
$CLIENT client --address 10.203.0.3:8080 --requests 3 --timeout-ms 150 --require-success

while ! grep -q 'applied event 1' "$output"; do sleep 0.05; done
echo "Profile phase 1: outage drops traffic"
$CLIENT client --address 10.203.0.3:8080 --requests 3 --timeout-ms 150 --require-failure

while ! grep -q 'applied event 2' "$output"; do sleep 0.05; done
echo "Profile phase 2: traffic recovers"
$CLIENT client --address 10.203.0.3:8080 --requests 3 --timeout-ms 300 --require-success

wait "$tui_pid"
tui_pid=
grep -q 'applied event 2' "$output"
echo "Profile timeline completed and detached the dataplane"
