#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
FAULTLINE_ENGINE=$WORKSPACE/target/release/faultline-engine
LAB_CLIENT="lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab"
faultline_pid=
stats_file=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:impairments must run as root" >&2
    exit 1
fi
if [ ! -x "$FAULTLINE_ENGINE" ]; then
    echo "missing $FAULTLINE_ENGINE; run mise run build" >&2
    exit 1
fi
if ! command -v tc >/dev/null 2>&1; then
    echo "missing tc; run mise run lab:install" >&2
    exit 1
fi
stats_file=$(mktemp /tmp/faultline-impairment-stats.XXXXXX)

stop_faultline() {
    if [ -n "$faultline_pid" ]; then
        # SIGTERM is the usual service-manager shutdown path and must run the
        # same RAII cleanup as Ctrl-C, including removal of the fq qdisc.
        kill -TERM "$faultline_pid" 2>/dev/null || true
        wait "$faultline_pid" 2>/dev/null || true
        faultline_pid=
    fi
}
cleanup() {
    stop_faultline
    tc qdisc del dev faultline-server0 root handle 7fff: 2>/dev/null || true
    rm -f "$stats_file"
}
trap cleanup EXIT INT TERM

start_egress() {
    RUST_LOG=info "$FAULTLINE_ENGINE" \
        --interface faultline-server0 \
        --direction egress \
        --destination 10.203.0.3/32 \
        --protocol tcp \
        --port 8080 \
        --stats-interval 10s \
        --stats-format json \
        "$@" >"$stats_file" &
    faultline_pid=$!
    sleep 0.3
    if ! kill -0 "$faultline_pid" 2>/dev/null; then
        wait "$faultline_pid"
    fi
    tc qdisc show dev faultline-server0 | grep -q 'qdisc fq 7fff:'
}

start_egress_bpf() {
    RUST_LOG=info "$FAULTLINE_ENGINE" \
        --interface faultline-server0 \
        --direction egress \
        --destination 10.203.0.3/32 \
        --protocol tcp \
        --port 8080 \
        --stats-interval 10s \
        --stats-format json \
        "$@" >"$stats_file" &
    faultline_pid=$!
    sleep 0.3
    if ! kill -0 "$faultline_pid" 2>/dev/null; then
        wait "$faultline_pid"
    fi
    if tc qdisc show dev faultline-server0 | grep -q 'qdisc fq 7fff:'; then
        echo "BPF-only impairment unexpectedly installed fq" >&2
        exit 1
    fi
}

assert_stat_positive() {
    field=$1
    value=$(tail -n 1 "$stats_file" | sed -n "s/.*\"$field\":\([0-9][0-9]*\).*/\1/p")
    if [ -z "$value" ] || [ "$value" -eq 0 ]; then
        echo "expected positive $field counter; final stats: $(tail -n 1 "$stats_file")" >&2
        exit 1
    fi
}

assert_stat_zero() {
    field=$1
    value=$(tail -n 1 "$stats_file" | sed -n "s/.*\"$field\":\([0-9][0-9]*\).*/\1/p")
    if [ "$value" != "0" ]; then
        echo "expected zero $field counter; final stats: $(tail -n 1 "$stats_file")" >&2
        exit 1
    fi
}

assert_pacing_removed() {
    if tc qdisc show dev faultline-server0 | grep -q 'qdisc fq 7fff:'; then
        echo "faultline-engine left its fq qdisc attached" >&2
        exit 1
    fi
}

echo "LXC lab: fixed delay"
start_egress --delay 20ms
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 10 --timeout-ms 1000 \
    --min-elapsed-ms 150 --require-success
stop_faultline
assert_stat_positive delayed
assert_pacing_removed

echo "LXC lab: delay with jitter"
start_egress --delay 20ms --jitter 5ms
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 30 --timeout-ms 1000 \
    --min-elapsed-ms 300 --min-spread-ms 3 --require-success
stop_faultline
assert_stat_positive delayed
assert_pacing_removed

echo "LXC lab: duplication"
start_egress_bpf --duplicate 20
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 50 --timeout-ms 1000 --require-success
stop_faultline
assert_stat_positive duplicated
assert_pacing_removed

echo "LXC lab: reordering"
start_egress --delay 20ms --reorder 25
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 30 --timeout-ms 1000 --require-success
stop_faultline
assert_stat_positive reordered
assert_pacing_removed

echo "LXC lab: bandwidth limit"
start_egress --bandwidth 1mbit
$LAB_CLIENT upload --address 10.203.0.3:8080 --bytes 262144 --timeout-ms 10000 \
    --min-elapsed-ms 1000
stop_faultline
assert_stat_positive delayed
assert_stat_zero pacing_dropped
assert_pacing_removed

echo "LXC lab: duplicated traffic consumes bandwidth"
start_egress --bandwidth 1mbit --duplicate 100
$LAB_CLIENT upload --address 10.203.0.3:8080 --bytes 262144 --timeout-ms 15000 \
    --min-elapsed-ms 3000
stop_faultline
assert_stat_positive duplicated
assert_stat_positive delayed
assert_stat_zero pacing_dropped
assert_pacing_removed

echo "LXC lab: burst loss"
start_egress_bpf --burst-loss 10 --burst-recovery 30 --burst-bad-loss 100 \
    --burst-idle-reset 30s
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 100 --timeout-ms 250 --require-mixed
stop_faultline
assert_pacing_removed

echo "LXC lab: outage window"
RUST_LOG=info "$FAULTLINE_ENGINE" \
    --interface faultline-client0 \
    --direction ingress \
    --destination 10.203.0.3/32 \
    --protocol tcp \
    --port 8080 \
    --outage-after 1s \
    --outage-duration 1s \
    --stats-interval 10s &
faultline_pid=$!
sleep 0.3
$LAB_CLIENT client --address 10.203.0.3:8080 --requests 60 --timeout-ms 250 \
    --interval-ms 50 --require-mixed
stop_faultline

echo "LXC lab: impairment scenarios passed"
