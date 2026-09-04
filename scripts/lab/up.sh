#!/bin/sh
set -eu

CLIENT=faultline-client
SERVER=faultline-server
BRIDGE=faultlinebr0
LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
LAB_BINARY=$WORKSPACE/target/release/faultline-lab

case "$(uname -m)" in
    aarch64|arm64) IMAGE_ARCH=arm64 ;;
    x86_64|amd64) IMAGE_ARCH=amd64 ;;
    *)
        echo "unsupported LXC lab architecture: $(uname -m)" >&2
        exit 1
        ;;
esac

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:up must run as root" >&2
    exit 1
fi
for command in grep install ip lxc-attach lxc-create lxc-info lxc-start lxc-stop lxc-wait nsenter sed; do
    if ! command -v "$command" >/dev/null 2>&1; then
        echo "missing $command; run mise run lab:install" >&2
        exit 1
    fi
done
if [ ! -x "$LAB_BINARY" ]; then
    echo "missing $LAB_BINARY; run mise run build" >&2
    exit 1
fi

if ! ip link show "$BRIDGE" >/dev/null 2>&1; then
    ip link add "$BRIDGE" type bridge
fi
if ! ip -4 address show dev "$BRIDGE" | grep -q '10.203.0.1/24'; then
    ip address add 10.203.0.1/24 dev "$BRIDGE"
fi
ip link set "$BRIDGE" up

create_container() {
    name=$1
    host_veth=$2
    address=$3
    if ! lxc-info -n "$name" >/dev/null 2>&1; then
        lxc-create -n "$name" -t download -- \
            --dist debian --release trixie --arch "$IMAGE_ARCH"
    fi

    if [ "$(lxc-info -n "$name" -sH)" = RUNNING ]; then
        lxc-stop -n "$name" -k
    fi

    config=/var/lib/lxc/$name/config
    sed -i \
        -e '/^lxc\.net\.0\./d' \
        -e '/^lxc\.uts\.name[[:space:]]*=/d' \
        "$config"
    {
        printf '\nlxc.uts.name = %s\n' "$name"
        printf 'lxc.net.0.type = veth\n'
        printf 'lxc.net.0.link = %s\n' "$BRIDGE"
        printf 'lxc.net.0.flags = up\n'
        printf 'lxc.net.0.veth.pair = %s\n' "$host_veth"
        printf 'lxc.net.0.ipv4.address = %s\n' "$address"
    } >>"$config"

    install -D -m 0755 "$LAB_BINARY" "/var/lib/lxc/$name/rootfs/usr/local/bin/faultline-lab"
}

start_container() {
    name=$1
    if [ "$(lxc-info -n "$name" -sH)" != RUNNING ]; then
        lxc-start -n "$name" -d
    fi
}

create_container "$CLIENT" faultline-client0 10.203.0.2/24
create_container "$SERVER" faultline-server0 10.203.0.3/24
start_container "$CLIENT"
start_container "$SERVER"

lxc-wait -n "$CLIENT" -s RUNNING -t 20
lxc-wait -n "$SERVER" -s RUNNING -t 20

wait_for_guest_init() {
    name=$1
    attempt=0
    while [ "$attempt" -lt 100 ]; do
        state=$(lxc-attach -n "$name" -- /bin/systemctl is-system-running 2>/dev/null || true)
        case "$state" in
            running|degraded) return 0 ;;
        esac
        attempt=$((attempt + 1))
        sleep 0.1
    done
    echo "$name did not finish booting (system state: $state)" >&2
    return 1
}

configure_address() {
    name=$1
    address=$2
    pid=$(lxc-info -n "$name" -pH)
    nsenter --target "$pid" --net ip link set eth0 up
    nsenter --target "$pid" --net ip address replace "$address" dev eth0
    if ! nsenter --target "$pid" --net ip -4 address show dev eth0 | grep -q "${address%/*}/"; then
        echo "failed to configure $address on $name" >&2
        return 1
    fi
}

# The downloaded Debian image starts its own network manager, which can clear
# the address LXC applies before init while it attempts DHCP. Apply the lab's
# isolated static addresses after init from the host network namespace tools.
wait_for_guest_init "$CLIENT"
wait_for_guest_init "$SERVER"
configure_address "$CLIENT" 10.203.0.2/24
configure_address "$SERVER" 10.203.0.3/24

lxc-attach -n "$SERVER" -- /bin/systemctl stop faultline-lab-server.service \
    >/dev/null 2>&1 || true
lxc-attach -n "$SERVER" -- /bin/systemd-run \
    --unit=faultline-lab-server.service \
    --collect \
    --property=Restart=on-failure \
    --property=RestartSec=100ms \
    --quiet \
    /usr/local/bin/faultline-lab server --bind 10.203.0.3:8080

attempt=0
ready=false
while [ "$attempt" -lt 50 ]; do
    if lxc-attach -n "$CLIENT" -- /usr/local/bin/faultline-lab client \
        --address 10.203.0.3:8080 --requests 1 --timeout-ms 100 --require-success \
        >/dev/null 2>&1; then
        ready=true
        break
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done

if [ "$ready" != true ]; then
    echo "LXC lab server did not become ready" >&2
    echo "client addresses:" >&2
    lxc-info -n "$CLIENT" -iH >&2 || true
    echo "server addresses:" >&2
    lxc-info -n "$SERVER" -iH >&2 || true
    echo "effective client network config:" >&2
    grep '^lxc\.net' "/var/lib/lxc/$CLIENT/config" >&2 || true
    echo "effective server network config:" >&2
    grep '^lxc\.net' "/var/lib/lxc/$SERVER/config" >&2 || true
    echo "server log:" >&2
    lxc-attach -n "$SERVER" -- /bin/systemctl status faultline-lab-server.service \
        --no-pager >&2 || true
    lxc-attach -n "$SERVER" -- /bin/journalctl -u faultline-lab-server.service \
        --no-pager -n 50 >&2 || true
    echo "server TCP sockets:" >&2
    lxc-attach -n "$SERVER" -- /bin/cat /proc/net/tcp >&2 || true
    exit 1
fi

echo "LXC lab is running: client=10.203.0.2 server=10.203.0.3:8080"
