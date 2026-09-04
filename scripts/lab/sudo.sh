#!/bin/sh
set -eu

if [ "$#" -eq 0 ]; then
    echo "usage: scripts/lab/sudo.sh COMMAND [ARGUMENT ...]" >&2
    exit 2
fi

if [ "$(id -u)" -eq 0 ]; then
    exec "$@"
fi

# mise may capture task stdin/stdout. Authenticate against the controlling TTY
# explicitly, then keep the sudo timestamp alive in a separate process while
# the lab command runs. Every actual command uses non-interactive sudo.
# Test the controlling terminal by actually opening it: the permission bits on
# /dev/tty say nothing about whether this session has one, and the open fails
# with ENXIO under a daemon such as scripts/mise-agent.py.
if ! sudo -n true 2>/dev/null; then
    if (exec </dev/tty >/dev/tty) 2>/dev/null; then
        sudo -v </dev/tty >/dev/tty 2>&1
    elif [ -n "${SUDO_ASKPASS:-}" ] && [ -x "${SUDO_ASKPASS}" ]; then
        sudo -A -v
    else
        echo "sudo.sh: no controlling terminal and no usable SUDO_ASKPASS." >&2
        echo "  Warm the sudo timestamp first, set SUDO_ASKPASS to an askpass" >&2
        echo "  helper, or grant NOPASSWD for the lab scripts in sudoers." >&2
        exit 1
    fi
fi

keepalive() {
    while sudo -n true 2>/dev/null; do
        sleep 45
    done
}
keepalive &
keepalive_pid=$!

cleanup() {
    kill "$keepalive_pid" 2>/dev/null || true
    wait "$keepalive_pid" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

sudo -n "$@"
