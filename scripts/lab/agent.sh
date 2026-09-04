#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
AGENT=$WORKSPACE/target/release/faultline-agent
ENGINE=$WORKSPACE/target/release/faultline-engine
CLIENT="lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab"
output=$(mktemp /tmp/faultline-agent.XXXXXX)
tui_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:agent must run as root" >&2
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

"$TUI" local://faultline-client0 \
    --agent "$AGENT" \
    --engine "$ENGINE" \
    --direction ingress \
    --destination 10.203.0.3/32 \
    --set-loss 100 \
    --hold-seconds 3 >"$output" &
tui_pid=$!

attempt=0
while ! grep -q '"type":"applied"' "$output" && [ "$attempt" -lt 50 ]; do
    if ! kill -0 "$tui_pid" 2>/dev/null; then
        wait "$tui_pid"
        echo "ephemeral agent exited before applying its rule" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
grep -q '"type":"applied"' "$output"

echo "LXC lab: ephemeral local agent is applying 100% loss"
$CLIENT client --address 10.203.0.3:8080 --requests 5 --timeout-ms 200 --require-failure

wait "$tui_pid"
tui_pid=
echo "LXC lab: agent session ended; dataplane must be detached"
$CLIENT client --address 10.203.0.3:8080 --requests 5 --timeout-ms 500 --require-success
echo "LXC lab: ephemeral agent cleanup restored traffic"
