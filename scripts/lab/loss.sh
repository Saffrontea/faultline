#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
FAULTLINE_ENGINE=$WORKSPACE/target/release/faultline-engine
LOSS_ALGORITHM=${LOSS_ALGORITHM:-hash}
SCENARIO=${SCENARIO:-}
stats_file=
faultline_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:loss must run as root" >&2
    exit 1
fi
if [ ! -x "$FAULTLINE_ENGINE" ]; then
    echo "missing $FAULTLINE_ENGINE; run mise run build" >&2
    exit 1
fi
if [ -n "$SCENARIO" ]; then
    LOSS_MIN=${LOSS_MIN:-40}
    LOSS_MAX=${LOSS_MAX:-60}
else
    case "$LOSS_ALGORITHM" in
        hash)
            LOSS_MIN=${LOSS_MIN:-30}
            LOSS_MAX=${LOSS_MAX:-55}
            ;;
        random)
            LOSS_MIN=${LOSS_MIN:-40}
            LOSS_MAX=${LOSS_MAX:-60}
            ;;
        *)
            echo "LOSS_ALGORITHM must be hash or random" >&2
            exit 1
            ;;
    esac
fi
stats_file=$(mktemp /tmp/faultline-stats.XXXXXX)

stop_faultline() {
    if [ -n "$faultline_pid" ]; then
        kill -INT "$faultline_pid" 2>/dev/null || true
        wait "$faultline_pid" 2>/dev/null || true
        faultline_pid=
    fi
}

cleanup() {
    stop_faultline
    if [ -n "$stats_file" ]; then
        rm -f "$stats_file"
    fi
}
trap cleanup EXIT INT TERM

if [ -n "$SCENARIO" ]; then
    RUST_LOG=info "$FAULTLINE_ENGINE" \
        --interface faultline-client0 \
        --direction ingress \
        --scenario "$SCENARIO" \
        --stats-format json >"$stats_file" &
else
    RUST_LOG=info "$FAULTLINE_ENGINE" \
        --interface faultline-client0 \
        --direction ingress \
        --destination 10.203.0.3/32 \
        --protocol tcp \
        --port 8080 \
        --loss 50 \
        --loss-algorithm "$LOSS_ALGORITHM" \
        --seed 42 \
        --stats-format json >"$stats_file" &
fi
faultline_pid=$!
sleep 1

lxc-attach -n faultline-client -- /usr/local/bin/faultline-lab client \
    --address 10.203.0.3:8080 --requests 100 --timeout-ms 250 --require-failure

stop_faultline
if [ -n "$SCENARIO" ]; then
    catch_all_stats=$(grep '"rule_id":0,' "$stats_file" | tail -n 1)
    last_stats=$(grep '"rule_id":1,' "$stats_file" | tail -n 1)
    if [ -z "$catch_all_stats" ] || [ -z "$last_stats" ]; then
        echo "scenario stats did not contain both rule_id=0 and rule_id=1" >&2
        exit 1
    fi
    catch_all_matched=$(printf '%s\n' "$catch_all_stats" | sed -n 's/.*"matched":\([0-9][0-9]*\).*/\1/p')
    if [ "$catch_all_matched" != "0" ]; then
        echo "catch-all rule unexpectedly matched ${catch_all_matched} packets" >&2
        exit 1
    fi
else
    last_stats=$(tail -n 1 "$stats_file")
fi
loss_percent=$(printf '%s\n' "$last_stats" | sed -n 's/.*"loss_percent":\([0-9][0-9.]*\).*/\1/p')
if [ -z "$loss_percent" ]; then
    echo "could not read final loss_percent from faultline-engine stats" >&2
    exit 1
fi
if ! awk -v actual="$loss_percent" -v minimum="$LOSS_MIN" -v maximum="$LOSS_MAX" \
    'BEGIN { exit !(actual >= minimum && actual <= maximum) }'
then
    echo "packet loss ${loss_percent}% is outside expected range ${LOSS_MIN}%..${LOSS_MAX}%" >&2
    exit 1
fi
if [ -n "$SCENARIO" ]; then
    algorithm=scenario
else
    algorithm=$LOSS_ALGORITHM
fi
echo "packet_loss=${loss_percent}% expected=${LOSS_MIN}%..${LOSS_MAX}% algorithm=$algorithm scenario=${SCENARIO:-inline}"
