#!/usr/bin/env bash
set -euo pipefail

CLIENT=${LAB_CLIENT:-faultline-client}
ADDRESS=${LAB_ADDRESS:-10.203.0.3:8080}
REQUESTS=${LAB_TRAFFIC_REQUESTS:-10}
INTERVAL_MS=${LAB_TRAFFIC_INTERVAL_MS:-100}
TIMEOUT_MS=${LAB_TRAFFIC_TIMEOUT_MS:-300}

traffic_pid=

stop() {
    # Disable recursive traps before forwarding the signal to the active
    # lxc-attach process. wait reaps it so neither lxc-attach nor faultline-lab is
    # left behind when mise/sudo forwards Ctrl-C as INT or TERM.
    trap - INT TERM HUP
    if [ -n "$traffic_pid" ]; then
        kill -TERM "$traffic_pid" 2>/dev/null || true
        wait "$traffic_pid" 2>/dev/null || true
        traffic_pid=
    fi
    echo "Continuous lab traffic stopped"
    exit 0
}
trap stop INT TERM HUP

echo "Continuous lab traffic: $CLIENT -> $ADDRESS"
echo "batch=$REQUESTS interval_ms=$INTERVAL_MS timeout_ms=$TIMEOUT_MS (Ctrl-C to stop)"

while :; do
    lxc-attach -n "$CLIENT" -- /usr/local/bin/faultline-lab client \
        --address "$ADDRESS" \
        --requests "$REQUESTS" \
        --interval-ms "$INTERVAL_MS" \
        --timeout-ms "$TIMEOUT_MS" &
    traffic_pid=$!
    wait "$traffic_pid" || true
    traffic_pid=
done
