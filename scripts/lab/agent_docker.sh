#!/bin/sh
set -eu

LAB_DIR=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
WORKSPACE=$(CDPATH= cd -- "$LAB_DIR/../.." && pwd)
TUI=$WORKSPACE/target/release/flt
TARGET=faultline-docker-client
IMAGE=faultline-agent:latest
output=$(mktemp /tmp/faultline-agent-docker.XXXXXX)
tui_pid=

cleanup() {
    if [ -n "$tui_pid" ]; then
        kill "$tui_pid" 2>/dev/null || true
        wait "$tui_pid" 2>/dev/null || true
    fi
    docker rm --force "$TARGET" >/dev/null 2>&1 || true
    rm -f "$output"
}
trap cleanup EXIT INT TERM

docker rm --force "$TARGET" >/dev/null 2>&1 || true
docker run --detach --name "$TARGET" --entrypoint /bin/sleep "$IMAGE" infinity >/dev/null

docker exec "$TARGET" /usr/local/bin/faultline-lab client \
    --address 10.203.0.3:8080 --requests 3 --timeout-ms 500 --require-success

"$TUI" "docker://$TARGET/eth0" \
    --agent-image "$IMAGE" \
    --destination 10.203.0.3/32 \
    --set-loss 100 --hold-seconds 3 >"$output" &
tui_pid=$!

attempt=0
while ! grep -q '"type":"applied"' "$output" && [ "$attempt" -lt 80 ]; do
    if ! kill -0 "$tui_pid" 2>/dev/null; then
        wait "$tui_pid"
        cat "$output" >&2
        exit 1
    fi
    attempt=$((attempt + 1))
    sleep 0.1
done
grep -q '"type":"applied"' "$output"

docker exec "$TARGET" /usr/local/bin/faultline-lab client \
    --address 10.203.0.3:8080 --requests 3 --timeout-ms 200 --require-failure

wait "$tui_pid"
tui_pid=

docker exec "$TARGET" /usr/local/bin/faultline-lab client \
    --address 10.203.0.3:8080 --requests 3 --timeout-ms 500 --require-success

test "$(docker inspect --format '{{.State.Running}}' "$TARGET")" = true
echo "Docker target remained running and dataplane cleanup restored traffic"
