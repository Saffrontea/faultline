#!/usr/bin/env python3
import argparse
import json
import socket


def receive(stream):
    line = stream.readline()
    if not line:
        raise RuntimeError("control socket closed before a response")
    return json.loads(line)


def main():
    parser = argparse.ArgumentParser(description="Headless faultline-engine JSON Lines control client")
    parser.add_argument("--socket", required=True)
    action = parser.add_mutually_exclusive_group(required=True)
    action.add_argument("--get-state", action="store_true")
    action.add_argument("--loss-permyriad", type=int)
    action.add_argument("--next-stats", action="store_true")
    action.add_argument("--next-diagnostics", action="store_true")
    args = parser.parse_args()

    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
        client.connect(args.socket)
        stream = client.makefile("rwb", buffering=0)
        if args.next_stats:
            while True:
                event = receive(stream)
                if event.get("type") == "stats":
                    print(json.dumps(event, separators=(",", ":")))
                    return
        if args.next_diagnostics:
            while True:
                event = receive(stream)
                if event.get("type") == "diagnostics":
                    print(json.dumps(event, separators=(",", ":")))
                    return

        stream.write(b'{"type":"get_state","id":1}\n')
        state = receive(stream)
        if state.get("type") != "state":
            raise RuntimeError(f"expected state, got {state}")
        if args.get_state:
            print(json.dumps(state, separators=(",", ":")))
            return

        if not 0 <= args.loss_permyriad <= 10_000:
            raise ValueError("--loss-permyriad must be between 0 and 10000")
        rules = state["state"]["rules"]
        if not rules:
            raise RuntimeError("daemon has no active rules")
        rules[0]["drop_permyriad"] = args.loss_permyriad
        request = {"type": "replace_rules", "id": 2, "rules": rules}
        stream.write(json.dumps(request, separators=(",", ":")).encode() + b"\n")
        while True:
            response = receive(stream)
            if response.get("id") == 2:
                print(json.dumps(response, separators=(",", ":")))
                if response.get("type") != "applied":
                    raise RuntimeError(f"rule update failed: {response}")
                return


if __name__ == "__main__":
    main()
