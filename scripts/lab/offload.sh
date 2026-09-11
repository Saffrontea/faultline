#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
FAULTLINE_ENGINE=$WORKSPACE/target/release/faultline-engine
CLIENT=faultline-client
INTERFACE=flt-client0
UPLOAD_BYTES=${UPLOAD_BYTES:-8388608}
LOSS_PERCENT=${LOSS_PERCENT:-2}
stats_file=$(mktemp /tmp/faultline-offload-stats.XXXXXX)
capture_dir=$(mktemp -d /tmp/faultline-offload-capture.XXXXXX)
chmod 0777 "$capture_dir"
pcap_file=
faultline_pid=
tcpdump_pid=

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:offload must run as root" >&2
    exit 1
fi
for command in ethtool lxc-info nsenter tcpdump; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing $command; run mise run lab:install" >&2
        exit 1
    fi
done
if [ ! -x "$FAULTLINE_ENGINE" ]; then
    echo "missing $FAULTLINE_ENGINE; run mise run build" >&2
    exit 1
fi

client_pid=$(lxc-info -n "$CLIENT" -pH)

host_feature() {
    ethtool -k "$INTERFACE" | sed -n "s/^$1: \(on\|off\).*/\1/p"
}
guest_feature() {
    nsenter --target "$client_pid" --net ethtool -k eth0 |
        sed -n "s/^$1: \(on\|off\).*/\1/p"
}

host_tso=$(host_feature tcp-segmentation-offload)
host_gso=$(host_feature generic-segmentation-offload)
host_gro=$(host_feature generic-receive-offload)
guest_tso=$(guest_feature tcp-segmentation-offload)
guest_gso=$(guest_feature generic-segmentation-offload)
guest_gro=$(guest_feature generic-receive-offload)

stop_processes() {
    if [ -n "$faultline_pid" ]; then
        kill -INT "$faultline_pid" 2>/dev/null || true
        wait "$faultline_pid" 2>/dev/null || true
        faultline_pid=
    fi
    if [ -n "$tcpdump_pid" ]; then
        kill -INT "$tcpdump_pid" 2>/dev/null || true
        wait "$tcpdump_pid" 2>/dev/null || true
        tcpdump_pid=
    fi
}

set_features() {
    mode=$1
    ethtool -K "$INTERFACE" tso "$mode" gso "$mode" gro "$mode"
    nsenter --target "$client_pid" --net ethtool -K eth0 \
        tso "$mode" gso "$mode" gro "$mode"
}

restore_features() {
    ethtool -K "$INTERFACE" tso "$host_tso" gso "$host_gso" gro "$host_gro" \
        2>/dev/null || true
    nsenter --target "$client_pid" --net ethtool -K eth0 \
        tso "$guest_tso" gso "$guest_gso" gro "$guest_gro" 2>/dev/null || true
}

cleanup() {
    stop_processes
    restore_features
    rm -f "$stats_file"
    rm -f "$capture_dir/off.pcap" "$capture_dir/on.pcap"
    rmdir "$capture_dir" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

run_mode() {
    mode=$1
    pcap_file=$capture_dir/$mode.pcap
    : >"$stats_file"
    set_features "$mode"

    rx_packets_before=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets")
    rx_bytes_before=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes")

    tcpdump -i "$INTERFACE" -Q in -n -U -w "$pcap_file" \
        'dst host 10.203.0.3 and tcp dst port 8080' >/dev/null 2>&1 &
    tcpdump_pid=$!
    RUST_LOG=info "$FAULTLINE_ENGINE" \
        --interface "$INTERFACE" \
        --direction ingress \
        --destination 10.203.0.3/32 \
        --protocol tcp \
        --port 8080 \
        --loss "$LOSS_PERCENT" \
        --loss-algorithm hash \
        --seed 42 \
        --stats-interval 1s \
        --stats-format json >"$stats_file" &
    faultline_pid=$!
    sleep 0.3

    upload_output=$(lxc-attach -n "$CLIENT" -- /usr/local/bin/faultline-lab upload \
        --address 10.203.0.3:8080 --bytes "$UPLOAD_BYTES" --timeout-ms 60000)
    stop_processes

    rx_packets_after=$(cat "/sys/class/net/$INTERFACE/statistics/rx_packets")
    rx_bytes_after=$(cat "/sys/class/net/$INTERFACE/statistics/rx_bytes")
    stats=$(tail -n 1 "$stats_file")
    matched=$(printf '%s\n' "$stats" | sed -n 's/.*"matched":\([0-9][0-9]*\).*/\1/p')
    dropped=$(printf '%s\n' "$stats" | sed -n 's/.*"dropped":\([0-9][0-9]*\).*/\1/p')
    matched_segments=$(printf '%s\n' "$stats" | sed -n 's/.*"matched_segments":\([0-9][0-9]*\).*/\1/p')
    dropped_segments=$(printf '%s\n' "$stats" | sed -n 's/.*"dropped_segments":\([0-9][0-9]*\).*/\1/p')
    matched_bytes=$(printf '%s\n' "$stats" | sed -n 's/.*"matched_bytes":\([0-9][0-9]*\).*/\1/p')
    dropped_bytes=$(printf '%s\n' "$stats" | sed -n 's/.*"dropped_bytes":\([0-9][0-9]*\).*/\1/p')
    gso_skbs=$(printf '%s\n' "$stats" | sed -n 's/.*"gso_skbs":\([0-9][0-9]*\).*/\1/p')
    skb_loss=$(printf '%s\n' "$stats" | sed -n 's/.*"skb_loss_percent":\([0-9.][0-9.]*\).*/\1/p')
    segment_loss=$(printf '%s\n' "$stats" | sed -n 's/.*"segment_loss_percent":\([0-9.][0-9.]*\).*/\1/p')
    byte_loss=$(printf '%s\n' "$stats" | sed -n 's/.*"byte_loss_percent":\([0-9.][0-9.]*\).*/\1/p')
    app_bytes=$(printf '%s\n' "$upload_output" | sed -n 's/.*bytes=\([0-9][0-9]*\).*/\1/p')
    captured=$(tcpdump -n -r "$pcap_file" 2>/dev/null | wc -l)

    if [ "$app_bytes" != "$UPLOAD_BYTES" ] || [ -z "$matched" ] || [ "$matched" -eq 0 ] ||
        [ -z "$matched_segments" ] || [ -z "$matched_bytes" ]; then
        echo "offload=$mode produced incomplete observations: upload='$upload_output' stats='$stats'" >&2
        exit 1
    fi
    echo "offload=$mode app_bytes=$app_bytes matched_skbs=$matched dropped_skbs=$dropped matched_segments=$matched_segments dropped_segments=$dropped_segments matched_bytes=$matched_bytes dropped_bytes=$dropped_bytes gso_skbs=$gso_skbs skb_loss=${skb_loss}% segment_loss=${segment_loss}% byte_loss=${byte_loss}% pcap_packets=$captured interface_rx_packets=$((rx_packets_after - rx_packets_before)) interface_rx_bytes=$((rx_bytes_after - rx_bytes_before))"
}

echo "LXC lab: comparing client upload with GSO/TSO/GRO disabled and enabled"
run_mode off
run_mode on
echo "LXC lab: both offload modes delivered $UPLOAD_BYTES application bytes"
