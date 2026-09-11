#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
FAULTLINE_ENGINE=$WORKSPACE/target/release/faultline-engine
FAULTLINE=$WORKSPACE/target/release/flt
CLIENT="lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab"
SOCKET=/tmp/faultline-control.sock
stats_file=$(mktemp /tmp/faultline-control-stats.XXXXXX)
faultline_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:control must run as root" >&2
    exit 1
fi

cleanup() {
    if [ -n "$faultline_pid" ]; then
        kill -INT "$faultline_pid" 2>/dev/null || true
        wait "$faultline_pid" 2>/dev/null || true
    fi
    rm -f "$stats_file" "$SOCKET"
}
trap cleanup EXIT INT TERM

RUST_LOG=info "$FAULTLINE_ENGINE" \
    --interface flt-client0 \
    --direction ingress \
    --destination 10.203.0.3/32 \
    --protocol tcp \
    --port 8080 \
    --loss 0 \
    --stats-interval 200ms \
    --stats-format json \
    --control-socket "$SOCKET" >"$stats_file" &
faultline_pid=$!

attempt=0
while [ ! -S "$SOCKET" ] && [ "$attempt" -lt 50 ]; do
    attempt=$((attempt + 1))
    sleep 0.1
done
if [ ! -S "$SOCKET" ]; then
    echo "control socket did not appear" >&2
    exit 1
fi

echo "LXC lab: socket update to 100% loss"
"$FAULTLINE" --socket "$SOCKET" --set-loss 100
$CLIENT client --address 10.203.0.3:8080 --requests 5 --timeout-ms 200 --require-failure

echo "LXC lab: socket update back to 0% loss"
"$FAULTLINE" --socket "$SOCKET" --set-loss 0
$CLIENT client --address 10.203.0.3:8080 --requests 5 --timeout-ms 500 --require-success

# A SYN to a different destination port reaches the classifier but must miss
# the configured rule, exercising the global diagnostic path.
$CLIENT client --address 10.203.0.3:8081 --requests 1 --timeout-ms 100 --require-failure

socket_stats=$(python3 "$LAB_DIR/control_socket.py" --socket "$SOCKET" --next-stats)
matched=$(printf '%s\n' "$socket_stats" | sed -n 's/.*"matched":\([0-9][0-9]*\).*/\1/p')
dropped=$(printf '%s\n' "$socket_stats" | sed -n 's/.*"dropped":\([0-9][0-9]*\).*/\1/p')
if [ -z "$matched" ] || [ "$matched" -eq 0 ] || [ -z "$dropped" ] || [ "$dropped" -eq 0 ]; then
    echo "socket stats did not report both matched and dropped traffic: $socket_stats" >&2
    exit 1
fi
echo "LXC lab: control socket applied both updates and returned stats matched=$matched dropped=$dropped"

diagnostics=$(python3 "$LAB_DIR/control_socket.py" --socket "$SOCKET" --next-diagnostics)
seen=$(printf '%s\n' "$diagnostics" | sed -n 's/.*"seen":\([0-9][0-9]*\).*/\1/p')
port_miss=$(printf '%s\n' "$diagnostics" | sed -n 's/.*"port_miss":\([0-9][0-9]*\).*/\1/p')
if [ -z "$seen" ] || [ "$seen" -eq 0 ] || [ -z "$port_miss" ] || [ "$port_miss" -eq 0 ]; then
    echo "diagnostics did not report classified traffic and port misses: $diagnostics" >&2
    exit 1
fi
echo "LXC lab: diagnostics seen=$seen port_miss=$port_miss"
