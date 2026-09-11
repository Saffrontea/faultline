#!/usr/bin/env python3
"""Bounded concurrent uploads on the dedicated LXC lab; retain raw observations."""

import concurrent.futures
import ctypes
import errno
import json
import os
from pathlib import Path
import platform
import re
import signal
import socket
import subprocess
import tempfile
import time


WORKSPACE = Path(__file__).resolve().parents[2]
INTERFACE = "flt-server0"
CLIENT = ["lxc-attach", "-n", "faultline-client", "--",
          "/usr/local/bin/faultline-lab"]


class BpfProgQuery(ctypes.Structure):
    # Include the entire query ABI: TCX writes revision at offset 56 even
    # when a caller supplies only the legacy 32-byte prefix as attr_size.
    _fields_ = [("ifindex", ctypes.c_uint32), ("attach_type", ctypes.c_uint32),
                ("query_flags", ctypes.c_uint32), ("attach_flags", ctypes.c_uint32),
                ("prog_ids", ctypes.c_uint64), ("prog_cnt", ctypes.c_uint32),
                ("padding", ctypes.c_uint32), ("prog_attach_flags", ctypes.c_uint64),
                ("link_ids", ctypes.c_uint64), ("link_attach_flags", ctypes.c_uint64),
                ("revision", ctypes.c_uint64)]


def tcx_program_count(interface):
    syscall_number = {"aarch64": 280, "x86_64": 321}.get(platform.machine())
    if syscall_number is None:
        raise RuntimeError("TCX observation currently supports aarch64 and x86_64")
    query = BpfProgQuery(ifindex=socket.if_nametoindex(interface), attach_type=47)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long
    result = libc.syscall(syscall_number, 16, ctypes.byref(query), ctypes.sizeof(query))
    if result < 0 and ctypes.get_errno() not in (errno.EINVAL, errno.EOPNOTSUPP):
        raise OSError(ctypes.get_errno(), "BPF_PROG_QUERY failed")
    return query.prog_cnt if result == 0 else None


def run(args, **kwargs):
    return subprocess.run(args, check=True, text=True, capture_output=True,
                          timeout=60, **kwargs).stdout


def network_state():
    # Aya uses TCX on recent kernels; those links do not appear in tc filter show.
    return {
        "tcx_program_count": tcx_program_count(INTERFACE),
        "filters": run(["tc", "filter", "show", "dev", INTERFACE, "egress"]),
        "root_qdisc": [q for q in json.loads(run(
            ["tc", "-j", "qdisc", "show", "dev", INTERFACE])) if q.get("root")],
    }


def main():
    if os.geteuid() != 0:
        raise SystemExit("Run through mise run lab:load (requires root)")
    workers = int(os.environ.get("LAB_LOAD_WORKERS", "8"))
    seconds = int(os.environ.get("LAB_LOAD_SECONDS", "10"))
    if not 1 <= workers <= 32 or not 1 <= seconds <= 120:
        raise SystemExit("workers must be 1..32 and seconds 1..120")
    output = Path(tempfile.mkdtemp(prefix="network-load-", dir=WORKSPACE / "target"))
    output.chmod(0o755)
    print(f"observations={output}", flush=True)
    original = network_state()
    if original["filters"] or original["tcx_program_count"]:
        raise SystemExit("Dedicated lab interface already has egress filters")
    results = []
    cases = [
        ("baseline", None, 64 * 1024 * 1024),
        ("bpf-pass", ["--loss", "0"], 64 * 1024 * 1024),
        ("loss-1pct", ["--loss", "1", "--seed", "42"], 1024 * 1024),
        ("bandwidth-100mbit", ["--bandwidth", "100mbit"], 1024 * 1024),
    ]
    for name, fault_args, size in cases:
        engine = None
        stats_path = output / f"{name}.jsonl"
        started = time.monotonic()
        with stats_path.open("w") as stats_file, (output / f"{name}.log").open("w") as log:
            try:
                if fault_args is not None:
                    engine = subprocess.Popen([
                        str(WORKSPACE / "target/release/faultline-engine"),
                        "--interface", INTERFACE, "--direction", "egress",
                        "--destination", "10.203.0.3/32", "--protocol", "tcp",
                        "--port", "8080", "--stats-format", "json",
                        "--stats-interval", "1s", "--duration", f"{seconds + 60}s", *fault_args,
                    ], stdout=stats_file, stderr=log)
                    ready_by = time.monotonic() + 10
                    while True:
                        state = network_state()
                        if state["filters"] or state["tcx_program_count"]:
                            break
                        if engine.poll() is not None or time.monotonic() >= ready_by:
                            raise RuntimeError(f"{name}: engine failed to attach; see {log.name}")
                        time.sleep(0.05)
                started = time.monotonic()
                deadline = started + seconds

                def upload_loop(_):
                    samples = []
                    while time.monotonic() < deadline:
                        begin = time.monotonic()
                        try:
                            proc = subprocess.run([
                                *CLIENT, "upload", "--address", "10.203.0.3:8080",
                                "--bytes", str(size), "--timeout-ms", "30000",
                            ], capture_output=True, text=True, timeout=45)
                            success = proc.returncode == 0 and re.search(
                                rf"bytes={size} sent={size} elapsed_ms=\d+", proc.stdout) is not None
                            detail = proc.stdout + proc.stderr
                        except subprocess.TimeoutExpired:
                            success, detail = False, "absolute 45s upload timeout"
                        samples.append({"ok": success, "seconds": time.monotonic() - begin,
                                        "bytes": size if success else 0, "output": detail})
                    return samples

                print(f"starting {name}: workers={workers} load_seconds={seconds}", flush=True)
                with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
                    samples = [sample for batch in pool.map(upload_loop, range(workers)) for sample in batch]
                elapsed = time.monotonic() - started
            finally:
                if engine is not None:
                    engine.send_signal(signal.SIGTERM)
                    try:
                        engine.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        engine.kill()
                        engine.wait()
                        raise RuntimeError("engine did not shut down gracefully")
        restored = network_state()
        events = [json.loads(line) for line in stats_path.read_text().splitlines()]
        stats = [event for event in events if event.get("type") == "stats"]
        total = sum(sample["bytes"] for sample in samples)
        result = {"case": name, "workers": workers, "load_seconds": seconds,
                  "elapsed_seconds_including_drain": elapsed,
                  "completed_uploads": sum(sample["ok"] for sample in samples),
                  "failed_uploads": sum(not sample["ok"] for sample in samples),
                  "application_bytes": total, "application_mbps": total * 8 / elapsed / 1e6,
                  "cleanup_ok": restored == original,
                  "engine_exit": engine.returncode if engine else None,
                  "final_stats": stats[-1] if stats else None}
        (output / f"{name}-uploads.json").write_text(json.dumps(samples, indent=2) + "\n")
        results.append(result)
        (output / "summary.json").write_text(json.dumps(results, indent=2) + "\n")
        print(json.dumps(result), flush=True)
        if not result["cleanup_ok"]:
            raise RuntimeError("TC filters/root qdisc were not restored")
        if result["failed_uploads"] or not total:
            raise RuntimeError(f"{name}: uploads failed")
        if engine and (engine.returncode != 0 or not stats or stats[-1]["matched"] == 0):
            raise RuntimeError(f"{name}: incomplete engine observations")
        if name == "bpf-pass" and stats[-1]["dropped"] != 0:
            raise RuntimeError("pass rule dropped packets")
        if name == "loss-1pct" and not 0.5 <= stats[-1]["skb_loss_percent"] <= 1.5:
            raise RuntimeError("observed loss is outside 0.5..1.5 percent")
        if name == "bandwidth-100mbit" and (
            not stats[-1]["delayed"] or stats[-1]["pacing_dropped"] or result["application_mbps"] > 110
        ):
            raise RuntimeError("bandwidth pacing invariant failed")
    recovery = run([*CLIENT, "client", "--address", "10.203.0.3:8080",
                    "--requests", "100", "--timeout-ms", "1000", "--require-success"])
    (output / "recovery.txt").write_text(recovery)
    print(f"recovery: {recovery.strip()}\nPASS observations={output}", flush=True)


if __name__ == "__main__":
    main()
