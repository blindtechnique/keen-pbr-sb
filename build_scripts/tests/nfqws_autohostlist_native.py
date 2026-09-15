"""Late TCP autohostlist regression using the official nfqws2 and real NFQUEUE.

Only runs in a disposable Docker --network none container (NET_ADMIN/NET_RAW).
There is no DNS, Internet, host firewall, router access or website content. A
real TLS ClientHello supplies SNI; subsequent bytes are an opaque test stream,
not a complete TLS session. This proves C-engine autolist selection/counters,
not effectiveness of bypass actions, Keenetic PPE or browser acceptance.
"""
from __future__ import annotations

import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import runpy
import socket
import ssl
import struct
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
ENGINE_SHA256 = '0145465409170fe4beeb160ec7acae526e5b1c0a6b2a1d3df197c5e10c21de1d'
HOST = 'cdn.example.test'
QUEUE = 309
LATE_BYTES = 19729  # observed stream position, not an asset or user hostname


def run(*argv):
    return subprocess.run([str(x) for x in argv], check=True, text=True,
                          stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                          timeout=15).stdout


def stop(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def until(predicate, timeout=3):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(.025)
    raise AssertionError('Timed out waiting for test packet/engine evidence')


def queue_row():
    path = Path('/proc/net/netfilter/nfnetlink_queue')
    if path.exists():
        for row in path.read_text().splitlines():
            fields = row.split()
            if fields and int(fields[0]) == QUEUE:
                return [int(x) for x in fields]
    return []


def hello():
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    connection = ssl.create_default_context().wrap_bio(
        incoming, outgoing, server_hostname=HOST)
    try:
        connection.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return outgoing.read()


def receive(sock, length):
    data = bytearray()
    while len(data) < length:
        part = sock.recv(length - len(data))
        assert part, 'Unexpected EOF'
        data.extend(part)
    return bytes(data)


def transfer(size, ending='fin', server='127.0.0.2', upload=0):
    """Kernel sockets create the handshake, prefix, late reset/retransmissions."""
    with ExitStack() as stack:
        def opened():
            sock = stack.enter_context(socket.socket())
            sock.settimeout(3)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            return sock

        listener = opened()
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((server, 443))
        listener.listen(1)
        client = opened()
        client.bind(('127.0.0.1', 0))
        client.connect((server, 443))
        peer = stack.enter_context(listener.accept()[0])
        peer.settimeout(3)
        peer.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        request = hello()
        client.sendall(request)
        assert receive(peer, len(request)) == request
        # Chunked reads prevent a single loopback GSO packet hiding maxseq.
        for pos in range(0, size, 1024):
            chunk = b'x' * min(1024, size - pos)
            peer.sendall(chunk)
            assert receive(client, len(chunk)) == chunk
        if upload:
            for pos in range(0, upload, 1024):
                chunk = b'u' * min(1024, upload - pos)
                client.sendall(chunk)
                assert receive(peer, len(chunk)) == chunk
        if ending == 'rst':
            peer.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack('ii', 1, 0))
            peer.close()
            try:
                client.recv(1)
            except ConnectionResetError:
                return
            raise AssertionError('Test server did not produce its requested RST')
        if ending == 'retrans':
            # OUTPUT NFQUEUE observes real kernel retransmissions; INPUT
            # drops only this test connection's client application data.
            rule = ['-s', '127.0.0.1', '-d', server, '-p', 'tcp',
                    '--sport', str(client.getsockname()[1]), '--dport', '443',
                    '--tcp-flags', 'PSH', 'PSH', '-j', 'DROP']
            run('iptables', '-A', 'KpbrAutoDrop', *rule)
            try:
                client.sendall(b'r' * 64)
                def retransmitted():
                    rows = run('iptables', '-nvxL', 'KpbrAutoDrop').splitlines()
                    return any(row.split() and row.split()[0].isdigit()
                               and int(row.split()[0]) >= 4 for row in rows)
                until(retransmitted, timeout=8)
            finally:
                run('iptables', '-D', 'KpbrAutoDrop', *rule)
            # v1.0.5 defaults hostlist-auto-retrans-reset to 1. Preserve it,
            # and observe the engine's reset instead of expecting this socket
            # to recover after the test blackhole has been removed.
            client.setblocking(False)
            try:
                data = client.recv(1, socket.MSG_DONTWAIT)
            except ConnectionResetError:
                return 'engine-reset'
            except (BlockingIOError, TimeoutError):
                data = None
            finally:
                client.settimeout(3)
            assert data is None, ('Unexpected test reply', data)
            peer.settimeout(6)
            assert receive(peer, 64) == b'r' * 64
        peer.shutdown(socket.SHUT_WR)
        assert client.recv(1) == b''
        client.shutdown(socket.SHUT_WR)
        assert peer.recv(1) == b''


def native_options(profile):
    if profile == 'stock':
        return []
    generator = runpy.run_path(str(ROOT / 'build_scripts/build-nfqws-strategies.py'))
    parse = runpy.run_path(str(ROOT / 'build_scripts/check-nfqws-assets.py'))['parse_shell_assignments']
    text, _ = generator['build'](profile, generator['PROFILES'][profile])
    return [token for token in parse(text)['NFQWS_ARGS'].split()
            if token.startswith('--hostlist-auto-')]


def check_case(args, name, profile, steps, expected_added, expected_failures,
               expected_resets=0, listed=False, excluded=False):
    # Writable autolist state is private to this container, never the repo.
    with tempfile.TemporaryDirectory(prefix='nfqws-auto-') as temporary:
        state = Path(temporary)
        os.chown(state, 65534, 65534)
        for leaf, text in [('user.list', HOST + '\n' if listed else ''),
                           ('exclude.list', HOST + '\n' if excluded else ''),
                           ('auto.list', ''), ('auto.log', '')]:
            path = state / leaf
            path.write_text(text)
            os.chown(path, 65534, 65534)
        observer = state / 'observer.lua'
        observer.write_text("function auto_test_noop()\n"
                            " io.stdout:write('AUTO_ACTION_SELECTED\\n'); io.stdout:flush()\n"
                            " return VERDICT_PASS\nend\n")
        # Read a live log on the container filesystem, not a Windows bind
        # mount (concurrent read/write can return ENODATA there). Export the
        # closed log afterwards; test results never depend on that transport.
        path = state / (name + '.log')
        options = native_options(profile)
        argv = [str(args.upstream / 'binaries/linux-x86_64/nfqws2'),
                f'--qnum={QUEUE}', '--debug=1', '--uid=65534:65534',
                '--lua-init=@' + str(args.upstream / 'lua/zapret-lib.lua'),
                '--lua-init=@' + str(observer), '--filter-tcp=443', '--filter-l7=tls',
                '--hostlist=' + str(state / 'user.list'),
                '--hostlist-exclude=' + str(state / 'exclude.list'),
                '--hostlist-auto=' + str(state / 'auto.list'),
                '--hostlist-auto-debug=' + str(state / 'auto.log'), *options,
                '--payload=tls_client_hello', '--lua-desync=auto_test_noop']
        with path.open('w') as log:
            engine = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT)
            try:
                until(lambda: bool(queue_row()) or engine.poll() is not None)
                assert engine.poll() is None, path.read_text()[-3000:]
                outcomes = [transfer(size, ending, server, upload)
                            for size, ending, server, upload in steps]
                before = path.read_text().count('AUTO_ACTION_SELECTED')
                if not listed:
                    assert before == 0, 'An unlisted/excluded host reached Lua early'
                transfer(1024)  # next connection proves selection after autolist add
                time.sleep(.05)
                after = path.read_text().count('AUTO_ACTION_SELECTED')
                auto = (state / 'auto.list').read_text()
                debug = (state / 'auto.log').read_text()
                failures = len(re.findall(r' : fail counter \d+/\d+', debug))
                resets = debug.count('fail counter reset. website is working.')
                added = HOST in auto.splitlines()
                assert added == expected_added, (name, auto, debug)
                assert failures == expected_failures, (name, failures, debug)
                assert resets == expected_resets, (name, resets, debug)
                tcp_resets = path.read_text().count('sending RST to retransmitter.')
                expected_tcp_resets = sum(step[1] == 'retrans' for step in steps) if expected_failures else 0
                assert tcp_resets == outcomes.count('engine-reset') == expected_tcp_resets, (name, tcp_resets, outcomes)
                assert (after > before) == (expected_added or listed) and not (excluded and after), (name, before, after)
                row = queue_row()
                assert row and row[5:7] == [0, 0], ('NFQUEUE drops', row)
                (args.output / (name + '.auto.log')).write_text(debug)
                result = dict(name=name, profile=profile, options=options,
                              auto_added=added, failures=failures, healthy_resets=resets,
                              engine_tcp_resets=tcp_resets,
                              actions_before=before, actions_after=after, queue=row,
                              steps=steps)
                print('PASS ' + name, flush=True)
                return result
            finally:
                stop(engine)
                (args.output / (name + '.log')).write_text(path.read_text())


def main(args):
    if not Path('/.dockerenv').is_file():
        raise RuntimeError('Disposable Docker container required')
    if [v['ifname'] for v in json.loads(run('ip', '-j', 'link'))] != ['lo']:
        raise RuntimeError('--network none required')
    engine = args.upstream / 'binaries/linux-x86_64/nfqws2'
    assert hashlib.sha256(engine.read_bytes()).hexdigest() == ENGINE_SHA256, 'Use the pinned official v1.0.5 binary'
    version = run(engine, '--version').strip()
    assert 'v1.0.5 ' in version, version
    # New output directory prevents accidental replacement of older evidence.
    args.output.mkdir(parents=True, exist_ok=False)
    run('ip', 'link', 'set', 'lo', 'up')
    run('iptables', '-t', 'mangle', '-N', 'KpbrAutoObserve')
    run('iptables', '-N', 'KpbrAutoDrop')
    run('iptables', '-t', 'mangle', '-A', 'OUTPUT', '-j', 'KpbrAutoObserve')
    run('iptables', '-A', 'INPUT', '-j', 'KpbrAutoDrop')
    results = []
    try:
        for port in ('--dport', '--sport'):
            run('iptables', '-t', 'mangle', '-A', 'KpbrAutoObserve',
                '-p', 'tcp', port, '443', '-j', 'NFQUEUE', '--queue-num', QUEUE, '--queue-bypass')
        late_rst = (LATE_BYTES, 'rst', '127.0.0.2', 0)
        late_retrans = (LATE_BYTES, 'retrans', '127.0.0.2', 0)
        late_upload = (1024, 'retrans', '127.0.0.2', 40000)
        short_ok = (10000, 'fin', '127.0.0.3', 0)
        large_ok = (32000, 'fin', '127.0.0.3', 0)
        cases = [
            ('stock-late-rst-missed', 'stock', [late_rst] * 3, False, 0),
            ('balanced-late-rst-detected', '02 balanced', [late_rst] * 3, True, 3),
            ('max-late-rst-detected', '03 max', [late_rst] * 3, True, 3),
            ('stock-late-retrans-missed', 'stock', [late_retrans] * 3, False, 0),
            ('max-late-retrans-detected', '03 max', [late_retrans] * 3, True, 3),
            ('stock-outgoing-40k-retrans-missed', 'stock', [late_upload] * 3, False, 0),
            ('max-outgoing-40k-retrans-detected', '03 max', [late_upload] * 3, True, 3),
            ('short-healthy-does-not-erase-late-failures', '03 max', [late_rst, short_ok] * 2 + [late_rst], True, 3),
            # Remaining upstream boundary, deliberately NOT called fixed:
            # a genuinely large healthy connection resets hostname-wide state.
            ('large-healthy-still-resets-host-wide-counter', '03 max', [late_rst, large_ok] * 3, False, 3, 3),
            ('healthy-short-and-large-not-added', '03 max', [short_ok, large_ok] * 3, False, 0),
        ]
        if args.case:
            known = {case[0] for case in cases} | {'exclusion-preserved', 'explicit-list-preserved'}
            assert set(args.case) <= known, ('Unknown case', args.case)
        for case in cases:
            if not args.case or case[0] in args.case:
                results.append(check_case(args, *case))
        if not args.case or 'exclusion-preserved' in args.case:
            results.append(check_case(args, 'exclusion-preserved', '03 max', [late_rst] * 3, False, 0, excluded=True))
        if not args.case or 'explicit-list-preserved' in args.case:
            results.append(check_case(args, 'explicit-list-preserved', '03 max', [late_rst] * 3, False, 0, listed=True))
        (args.output / 'results.json').write_text(json.dumps(
            dict(engine=version, engine_sha256=ENGINE_SHA256, results=results,
                 scope='Native C autohostlist semantics only; no bypass/Keenetic/browser claim'), indent=2) + '\n')
    finally:
        run('iptables', '-t', 'mangle', '-D', 'OUTPUT', '-j', 'KpbrAutoObserve')
        run('iptables', '-D', 'INPUT', '-j', 'KpbrAutoDrop')
        run('iptables', '-t', 'mangle', '-F', 'KpbrAutoObserve')
        run('iptables', '-t', 'mangle', '-X', 'KpbrAutoObserve')
        run('iptables', '-F', 'KpbrAutoDrop')
        run('iptables', '-X', 'KpbrAutoDrop')


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--upstream', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--case', action='append')
    main(parser.parse_args())
