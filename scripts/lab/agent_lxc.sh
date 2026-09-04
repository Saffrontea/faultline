#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
CLIENT=faultline-client
CLIENT_CMD="lxc-attach -n $CLIENT -- /usr/local/bin/faultline-lab"
output=$(mktemp /tmp/faultline-agent-lxc.XXXXXX)
tui_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:agent-lxc must run as root" >&2
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

install -D -m 0755 "$WORKSPACE/target/release/faultline-agent" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-agent"
install -D -m 0755 "$WORKSPACE/target/release/faultline-engine" \
    "/var/lib/lxc/$CLIENT/rootfs/usr/local/bin/faultline-engine"

"$TUI" "lxc://$CLIENT/eth0" \
    --agent /usr/local/bin/faultline-agent \
    --engine /usr/local/bin/faultline-engine \
    --destination 10.203.0.3/32 \
    --set-loss 100 \
    --hold-seconds 3 >"$output" &
tui_pid=$!

attempt=0
while ! grep -q '"type":"applied"' "$output" && [ "$attempt" -lt 50 ]; do
    if ! kill -0 "$tui_pid" 2>/dev/null; then
        wait "$tui_pid"
        echo "LXC agent exited before applying its rule" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
grep -q '"type":"applied"' "$output"

echo "LXC lab: agent is running inside the client network namespace"
$CLIENT_CMD client --address 10.203.0.3:8080 --requests 5 --timeout-ms 200 --require-failure
wait "$tui_pid"
tui_pid=
$CLIENT_CMD client --address 10.203.0.3:8080 --requests 5 --timeout-ms 500 --require-success
echo "LXC lab: stdio session cleanup detached the in-container dataplane"
