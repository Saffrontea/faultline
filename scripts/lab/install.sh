#!/bin/sh
set -eu

if [ "$(id -u)" -ne 0 ]; then
    echo "lab:install must run as root" >&2
    exit 1
fi

apt-get update
apt-get install --yes lxc lxc-templates debootstrap uidmap iproute2 ethtool tcpdump
