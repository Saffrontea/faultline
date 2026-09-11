#!/usr/bin/env python3
"""Live ruleset churn and agent lifetime checks while LXC uploads stay active."""
import argparse
import concurrent.futures
import copy
import fcntl
import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import tempfile
import time

from load import CLIENT, INTERFACE, WORKSPACE, network_state, run


class Control:
    def __init__(self, path):
        self.socket = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.socket.settimeout(10)
        self.socket.connect(str(path))
        self.stream = self.socket.makefile('rb')
        self.sequence = 0
        self.latencies = []

    def request(self, kind, **fields):
        self.sequence += 1
        start = time.monotonic()
        self.socket.sendall((json.dumps(dict(type=kind, id=self.sequence, **fields)) + '\n').encode())
        while time.monotonic() - start < 10:
            line = self.stream.readline()
            if not line:
                raise RuntimeError('control connection closed')
            response = json.loads(line)
            if response.get('id') == self.sequence:
                self.latencies.append(time.monotonic() - start)
                return response
        raise TimeoutError('control response exceeded 10 seconds')

    def close(self):
        self.stream.close()
        self.socket.close()


def wait_socket(path, process):
    deadline = time.monotonic() + 10
    while not path.exists():
        if process.poll() is not None or time.monotonic() >= deadline:
            raise RuntimeError(f'process failed to open {path}')
        time.sleep(.02)


def stop(process):
    if process.poll() is None:
        process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait()
        raise RuntimeError('process needed SIGKILL')


def uploads(deadline):
    count = total = 0
    while time.monotonic() < deadline:
        size = 8 * 1024 * 1024
        output = run([*CLIENT, 'upload', '--address', '10.203.0.3:8080',
                      '--bytes', str(size), '--timeout-ms', '30000'])
        if f'bytes={size} sent={size} ' not in output:
            raise RuntimeError(f'incomplete upload: {output}')
        count += 1
        total += size
    return dict(uploads=count, bytes=total)


def resources(pid):
    status = Path(f'/proc/{pid}/status').read_text().splitlines()
    selected = ('VmRSS:', 'VmSize:', 'Threads:')
    return {**{line.split(':')[0]: int(line.split()[1]) for line in status
               if line.startswith(selected)}, 'fds': len(list(Path(f'/proc/{pid}/fd').iterdir()))}


def verify_stats(path):
    previous = {}
    final = {}
    events = 0
    with path.open() as stream:
        for line in stream:
            event = json.loads(line)
            key = (event['type'], event.get('rule_id'))
            old = previous.get(key, {})
            for field, value in event.items():
                if field.endswith('_delta'):
                    counter = field[:-6]
                    assert event[counter] >= old.get(counter, 0), (key, counter, 'non-monotonic')
                    assert value == event[counter] - old.get(counter, 0), (key, counter, 'incorrect delta')
            previous[key] = event
            final[key] = event
            events += 1
    diagnostic = final[('diagnostics', None)]
    assert diagnostic['invalid_rule'] == diagnostic['no_rules'] == diagnostic['malformed'] == 0
    # Every background upload uses the more specific allow rule, never catch-all drop.
    assert final[('stats', 1)]['matched'] == 0, 'source precedence failed during map swaps'
    assert final[('stats', 0)]['matched'] > 10000
    return dict(events=events, active_rule=final[('stats', 0)], diagnostics=diagnostic)


def churn(output, seconds):
    original = network_state()
    path = output / 'control.sock'
    controller = None
    slow = []
    observations = []
    with (output / 'churn.jsonl').open('w') as stats, (output / 'churn.log').open('w') as log:
        process = subprocess.Popen([
            str(WORKSPACE / 'target/release/faultline-engine'), '--interface', INTERFACE,
            '--direction', 'egress', '--destination', '10.203.0.3/32', '--protocol', 'tcp',
            '--port', '8080', '--loss', '0', '--control-socket', str(path),
            '--stats-format', 'json', '--stats-interval', '1s'], stdout=stats, stderr=log)
        try:
            wait_socket(path, process)
            controller = Control(path)
            base = controller.request('get_state')['state']['rules'][0]
            allow = {**base, 'source': '10.203.0.2/32'}
            deny = {**base, 'id': 1, 'drop_permyriad': 10000}
            large = [allow, deny] + [
                {**base, 'id': i, 'source': f'198.18.{i // 256}.{i % 256}/32'}
                for i in range(2, 1024)]
            initial = controller.request('replace_rules', rules=large[:34])
            assert initial['type'] == 'applied'
            for _ in range(16):
                peer = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                peer.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 1024)
                peer.connect(str(path))
                slow.append(peer)  # Deliberately do not consume pushed stats.
            deadline = time.monotonic() + seconds
            updates = rejected = 0
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                pending = [pool.submit(uploads, deadline) for _ in range(8)]
                while time.monotonic() < deadline:
                    rules = copy.deepcopy(large if updates % 16 == 0 else large[:34])
                    rules[0]['seed'] = updates
                    if updates % 2:
                        rules.reverse()
                    response = controller.request('replace_rules', rules=rules)
                    assert response['type'] == 'applied' and response['state']['rules'] == rules
                    assert controller.request('get_state')['state']['rules'] == rules
                    if updates % 10 == 0:
                        invalid = controller.request('replace_rules', rules=[rules[0], rules[0]])
                        assert invalid['type'] == 'error'
                        assert controller.request('get_state')['state']['rules'] == rules
                        rejected += 1
                        observations.append(resources(process.pid))
                    updates += 1
                    time.sleep(.05)
                traffic = [future.result() for future in pending]
            assert controller.request('replace_rules', rules=[{**allow, 'drop_permyriad': 10000}, deny])['type'] == 'applied'
            outage = run([*CLIENT, 'client', '--address', '10.203.0.3:8080', '--requests', '20',
                          '--timeout-ms', '100', '--require-failure'])
            assert 'succeeded=0 failed=20' in outage
            assert controller.request('replace_rules', rules=[allow, deny])['type'] == 'applied'
            recovery = run([*CLIENT, 'client', '--address', '10.203.0.3:8080', '--requests', '100',
                            '--timeout-ms', '1000', '--require-success'])
            assert 'succeeded=100 failed=0' in recovery
            (output / 'probes.txt').write_text(outage + recovery)
        finally:
            for peer in slow:
                peer.close()
            if controller:
                controller.close()
            stop(process)
    assert process.returncode == 0
    assert not path.exists() and network_state() == original
    verified = verify_stats(output / 'churn.jsonl')
    result = dict(seconds=seconds, updates=updates, rejected_invalid_updates=rejected,
                  uploads=sum(item['uploads'] for item in traffic),
                  bytes=sum(item['bytes'] for item in traffic),
                  max_ack_seconds=max(controller.latencies), resources=observations,
                  cleanup_ok=True, **verified)
    (output / 'churn-summary.json').write_text(json.dumps(result, indent=2) + '\n')
    print(f'churn PASS updates={updates} invalid={rejected} bytes={result["bytes"]} '
          f'max_ack={result["max_ack_seconds"]:.3f}s', flush=True)


def agent_lifetime(output):
    results = []
    for ending in ('stdout-close', 'stdin-eof', 'blocked-stdout-eof', 'sigterm'):
        original = network_state()
        controller = None
        with (output / f'agent-{ending}.log').open('w') as log:
            process = subprocess.Popen([
                str(WORKSPACE / 'target/release/faultline-agent'),
                '--engine', str(WORKSPACE / 'target/release/faultline-engine'),
                '--interface', INTERFACE, '--direction', 'egress',
                '--destination', '10.203.0.3/32', '--protocol', 'tcp', '--port', '8080'],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log)
            path = Path(f'/tmp/faultline-agent-{process.pid}.sock')
            try:
                if ending == 'blocked-stdout-eof':
                    fcntl.fcntl(process.stdout, fcntl.F_SETPIPE_SZ, 4096)
                wait_socket(path, process)
                controller = Control(path)
                base = controller.request('get_state')['state']['rules'][0]
                assert controller.request('replace_rules', rules=[{**base, 'bandwidth_bps': 100000000}])['type'] == 'applied'
                deadline = time.monotonic() + 10
                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                    pending = [pool.submit(uploads, deadline) for _ in range(8)]
                    time.sleep(5 if ending == 'blocked-stdout-eof' else 3)
                    if ending == 'stdout-close':
                        process.stdout.close()
                    elif ending in ('stdin-eof', 'blocked-stdout-eof'):
                        process.stdin.close()
                    else:
                        process.terminate()
                    process.wait(timeout=10)
                    detached_by = time.monotonic() + 10
                    while network_state() != original:
                        if time.monotonic() >= detached_by:
                            raise RuntimeError(f'{ending}: BPF or fq survived agent termination')
                        time.sleep(.05)
                    traffic = [future.result() for future in pending]
                assert process.returncode == ( -signal.SIGTERM if ending == 'sigterm' else 0)
                results.append(dict(ending=ending, returncode=process.returncode,
                                    uploads=sum(item['uploads'] for item in traffic),
                                    bytes=sum(item['bytes'] for item in traffic), cleanup_ok=True))
            finally:
                if controller:
                    controller.close()
                process.stdin.close()
                process.stdout.close()
                stop(process)
        print(f'agent {ending}: PASS', flush=True)
    (output / 'agent-summary.json').write_text(json.dumps(results, indent=2) + '\n')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--agent-only', action='store_true')
    args = parser.parse_args()
    seconds = int(os.environ.get('LAB_SOAK_SECONDS', '120'))
    if os.geteuid() != 0 or not 10 <= seconds <= 600:
        raise SystemExit('requires root and LAB_SOAK_SECONDS in 10..600')
    output = Path(tempfile.mkdtemp(prefix='semantic-soak-', dir=WORKSPACE / 'target'))
    output.chmod(0o755)
    print(f'observations={output}', flush=True)
    state = network_state()
    assert not state['filters'] and not state['tcx_program_count']
    if not args.agent_only:
        churn(output, seconds)
    agent_lifetime(output)
    print(f'PASS observations={output}', flush=True)


if __name__ == '__main__':
    main()
