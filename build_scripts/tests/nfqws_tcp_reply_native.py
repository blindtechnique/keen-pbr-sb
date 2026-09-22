"""Native packet acceptance for the production helper, only in a disposable container.

No network/downloads/router credentials. Supply an extracted official zapret2 tree.
Requires --network none and NET_ADMIN/NET_RAW/SYS_ADMIN; refuses a host namespace.
Set container sysctls net.ipv4.ip_forward, net.ipv6.conf.all.forwarding,
net.ipv6.conf.default.forwarding and net.netfilter.nf_conntrack_acct to 1.
"""
import argparse
from contextlib import ExitStack
import hashlib
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import time

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / 'packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr'
COMPANION = ROOT / 'packages/keenetic/keen-pbr/files/opt/usr/share/keen-pbr/nfqws-lua/rotator-telemetry.lua'
HOOKS = ROOT / 'packages/keenetic/keen-pbr/files/opt/etc/ndm/netfilter.d'
ALERT = bytes.fromhex('1503030002023215030300020100')
REPLIES = {'alert': ALERT, 'empty-fin': b'',
           'server-data-fin': bytes.fromhex('15030300020100'), 'client-fin': b''}
NATIVE_INPUT_MATCH = '-m state --state RELATED,ESTABLISHED -m connmark --mark 0x1/0x1'
KEENETIC_INPUT_MATCH = '-m state --state RELATED,ESTABLISHED -m connndmmark ! --mark 0x20/0x20'
NATIVE_INPUT_ACCEPT = '-A INPUT ' + NATIVE_INPUT_MATCH + ' -j ACCEPT'


def firewall_policy_lines(text):
    # iptables-save includes live chain counters even without -c. IPv6 neighbour
    # discovery can advance them between snapshots, without any policy change.
    # Keep every chain/policy and ordered rule; ignore only counters and headers.
    return [re.sub(r'^(:\S+ \S+) \[\d+:\d+\]$', r'\1', line)
            for line in text.splitlines() if not line.startswith('#')]


OBSERVER = r'''
local original, ids, serial = circular, setmetatable({}, {__mode='k'}), 0
function circular(ctx,d)
    local state = d.track and d.track.lua_state
    if state and not ids[state] then serial=serial+1; ids[state]=serial end
    local verdict=original(ctx,d)
    local c=state and state.automate or {}
    local tcp=d.dis.tcp or {}
    local h=autostate and autostate.tcp_general and autostate.tcp_general[keen_pbr_tcp_endpoint(d)] or {}
    local row={'PACKET',tostring(d.outgoing),tostring(ids[state] or 0),tostring(pos_get(d,'s')),
        tostring(d.l7payload),tostring(#(d.dis.payload or '')),tostring(h.nstrategy),
        tostring(c.failure or false),tostring(tcp.th_sport),tostring(tcp.th_dport),
        tostring(tcp.th_flags or 0)}
    io.stdout:write(table.concat(row,'\t')..'\n'); io.stdout:flush()
    return verdict
end
function reply_test_noop() return VERDICT_PASS end
function reply_test_udp(ctx,d)
    print('UDP_PACKET '..tostring(d.outgoing))
    return VERDICT_PASS
end
'''


def run(*argv, **kwargs):
    result = subprocess.run(list(map(str, argv)), text=True, capture_output=True,
                            timeout=15, **kwargs)
    if result.returncode:
        raise RuntimeError(f'{argv}: exit {result.returncode}\n{result.stdout}\n{result.stderr}')
    return result.stdout


def ns(pid, *argv):
    return ['nsenter', '--net=/proc/%d/ns/net' % pid, '--', *map(str, argv)]


def close(process):
    if process.poll() is None:
        process.terminate()
        try:
            process.wait(timeout=2)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=2)


def tcp_retransmissions(conn):
    # Linux UAPI tcp_info: tcpi_total_retrans at byte 100 (native uint32).
    # https://github.com/torvalds/linux/blob/v6.1/include/uapi/linux/tcp.h
    return struct.unpack_from('=I', conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104), 100)[0]


def wait_for_fin_ack(conn):
    deadline = time.monotonic() + 2
    while True:
        state = conn.getsockopt(socket.IPPROTO_TCP, socket.TCP_INFO, 104)[0]
        if state in (6, 7):  # Linux TCP_TIME_WAIT / TCP_CLOSE: our FIN was ACKed
            return
        if time.monotonic() > deadline:
            raise RuntimeError('controlled server close was not acknowledged')
        time.sleep(.005)


def retry_budget(output, expected):
    values = re.findall(r'^TCP_RETRANSMISSIONS=(\d+)$', output, re.M)
    assert len(values) == expected, ('missing socket retransmission evidence', expected, values)
    return sum(map(int, values))


def verify_observation_count(observed, connections, retransmissions, label):
    # Scheduling delays can trigger real TCP retransmissions even on a veth.
    # Do not mistake these for double queueing, but require kernel evidence for
    # every extra observation; deduplicated connection coverage is checked too.
    assert connections <= observed <= connections + retransmissions, (
        label, 'missing or duplicate queue observation', observed, connections, retransmissions)


def serve(address, port, count, udp=False, reply_kind='alert'):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, port))
        listener.settimeout(6)
        if not udp:
            listener.listen(8)
        print('READY', flush=True)
        for _ in range(count):
            if udp:
                data, peer = listener.recvfrom(1024)
                listener.sendto(data, peer)
                continue
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                data = b''
                while len(data) < 5 or len(data) < 5 + int.from_bytes(data[3:5], 'big'):
                    part = conn.recv(4096)
                    if not part:
                        raise RuntimeError('incomplete ClientHello')
                    data += part
                assert data[0] == 22 and data[5] == 1
                before_retrans = tcp_retransmissions(conn)
                if reply_kind == 'client-fin':
                    # Wait for the client's half-close before initiating ours.
                    while conn.recv(4096):
                        pass
                if REPLIES[reply_kind]:
                    conn.sendall(REPLIES[reply_kind])
                conn.shutdown(socket.SHUT_WR)
                # Keep the socket until the client closes, so late response
                # retries are visible in TCP_INFO instead of losing the fd.
                while conn.recv(4096):
                    pass
                wait_for_fin_ack(conn)
                print('TCP_RETRANSMISSIONS=' + str(tcp_retransmissions(conn) - before_retrans), flush=True)


def request(server, port, sources, udp=False, same_port=False, reply_kind='alert'):
    incoming, outgoing = ssl.MemoryBIO(), ssl.MemoryBIO()
    context = ssl.create_default_context()
    tls = context.wrap_bio(incoming, outgoing, server_hostname='example.invalid')
    try:
        tls.do_handshake()
    except ssl.SSLWantReadError:
        pass
    hello = outgoing.read()
    family = socket.AF_INET6 if ':' in server else socket.AF_INET
    for attempt in range(3):
        for source in sources:
            with socket.socket(family, socket.SOCK_DGRAM if udp else socket.SOCK_STREAM) as conn:
                conn.settimeout(3)
                conn.bind((source, 45100 + attempt if same_port else 0))
                conn.connect((server, port))
                before_retrans = tcp_retransmissions(conn) if not udp else 0
                conn.sendall(b'isolated-udp-test' if udp else hello)
                if not udp and reply_kind == 'client-fin':
                    conn.shutdown(socket.SHUT_WR)
                if udp:
                    reply = conn.recv(1024)
                    assert reply == b'isolated-udp-test'
                else:
                    reply = b''
                    while True:
                        part = conn.recv(1024)
                        if not part:
                            break
                        reply += part
                    assert reply == REPLIES[reply_kind], reply.hex()
                    print('TCP_RETRANSMISSIONS=' + str(tcp_retransmissions(conn) - before_retrans), flush=True)
            print('REPLY_OK', source, attempt + 1, flush=True)


def stock(family, queue, interface, policy):
    lines = ['*mangle', ':PREROUTING ACCEPT [0:0]', ':INPUT ACCEPT [0:0]',
             ':FORWARD ACCEPT [0:0]', ':OUTPUT ACCEPT [0:0]', ':POSTROUTING ACCEPT [0:0]',
             ':nfqws_pre - [0:0]', ':nfqws_post - [0:0]']
    if policy in ('mark', 'processed', 'keenetic-input-processed'):
        mark = '0x123' if policy == 'mark' else '0x40000000'
        lines += [f'-A PREROUTING -j MARK --set-xmark {mark}/0xffffffff']
    elif policy == 'connmark':
        lines += ['-A PREROUTING -j CONNMARK --set-xmark 0x20000000/0x20000000']
    if policy.startswith('keenetic-input') and not policy.startswith('keenetic-input-unmatched'):
        # Test-only boolean selector, NOT an interpretation of NDMS mark bits.
        lines += ['-A PREROUTING -j CONNMARK --set-xmark 0x1/0x1']
    lines += ['-A PREROUTING -j nfqws_pre', '-A POSTROUTING -j nfqws_post',
              '-A FORWARD -p icmp' + ('v6' if family == 6 else '') + ' -j ACCEPT']
    if policy == 'early-accept':
        lines += ['-A FORWARD -i kpbr-wan -p tcp -j ACCEPT',
                  '-A INPUT -i kpbr-wan -p tcp -j ACCEPT']
    if policy.startswith('keenetic-input'):
        lines += ['-A INPUT -p udp -m comment --comment "native-input-prefix" -j ACCEPT']
        if policy == 'keenetic-input-prior-accept':
            lines += ['-A INPUT -i kpbr-wan -p tcp -m comment --comment "foreign-prior-accept" -j ACCEPT']
        tail_target = 'MARK --set-xmark 0x10/0x10' if policy == 'keenetic-input-unmatched-tail' else 'ACCEPT'
        lines += [NATIVE_INPUT_ACCEPT,
                  '-A INPUT -p tcp -m comment --comment "native-input-tail" -j ' + tail_target]
    for chain, flag, ports, direction in [('nfqws_pre', '-i', '--sports', 'reply'),
                                          ('nfqws_post', '-o', '--dports', 'original')]:
        prefix = f'-A {chain} {flag} {interface}'
        lines += [prefix + ' -m mark --mark 0x123/0x0fffffff -j RETURN',
                  prefix + ' -m connmark --mark 0x20000000/0x20000000 -j RETURN']
        for proto in ('udp', 'tcp'):
            lines += [prefix + f' -p {proto} -m mark ! --mark 0x40000000/0x40000000'
                      f' -m multiport {ports} 443 -m connbytes --connbytes 1:15'
                      f' --connbytes-mode packets --connbytes-dir {direction}'
                      f' -j NFQUEUE --queue-num {queue} --queue-bypass']
        for flags in (['SYN,ACK'] if direction == 'reply' else []) + ['FIN', 'RST']:
            lines += [prefix + ' -p tcp -m mark ! --mark 0x40000000/0x40000000'
                      f' -m multiport {ports} 443 -m tcp --tcp-flags {flags} {flags}'
                      f' -j NFQUEUE --queue-num {queue} --queue-bypass']
    return lines + ['COMMIT']


def input_model_bin(output):
    """Model only a matching native INPUT shortcut's serialization.

    Generic Linux has no Keenetic connndmmark module. Real packets hit an
    ordinary established/boolean-test-bit ACCEPT at the same position. The
    shim translates ONLY the native selector in snapshots and owned INPUT
    commands; kernel restore, NFQUEUE, NAT, engine and companion are real.
    The boolean is intentionally false in unmatched cases. This is NOT a
    test of proprietary NDMS mark/PPE semantics or firmware compatibility.
    """
    directory = output / 'input-model-bin'
    directory.mkdir(exist_ok=True)
    for command in ('iptables-save', 'ip6tables-save', 'iptables-restore', 'ip6tables-restore'):
        real_command = shutil.which(command)
        assert real_command
        wrapper = directory / command
        header = ('#!/usr/bin/env python3\nimport subprocess, sys\n'
                  f'command = [{real_command!r}, *sys.argv[1:]]\n'
                  f'native, keenetic = {NATIVE_INPUT_MATCH!r}, {KEENETIC_INPUT_MATCH!r}\n')
        if command.endswith('-save'):
            body = ('lines = subprocess.check_output(command, text=True).splitlines()\n'
                    'assert lines.count("-A INPUT " + native + " -j ACCEPT") == 1, "missing model anchor"\n'
                    'for line in lines:\n'
                    '    if native in line:\n'
                    '        assert line.startswith("-A INPUT "), line\n'
                    '        line = line.replace(native, keenetic)\n'
                    '    print(line)\n')
        else:
            body = ('lines = sys.stdin.read().splitlines()\n'
                    'for index, line in enumerate(lines):\n'
                    '    if keenetic in line:\n'
                    '        assert line.startswith(("-I INPUT ", "-A INPUT ", "-D INPUT ")), line\n'
                    '        assert "keen-pbr-sb:nfqws:tcp-reply:v1" in line and line.endswith("-j KpbrNfqTcpReply"), line\n'
                    '        lines[index] = line.replace(keenetic, native)\n'
                    'sys.exit(subprocess.run(command, input="\\n".join(lines) + "\\n", text=True).returncode)\n')
        wrapper.write_text(header + body)
        wrapper.chmod(0o755)
    return directory


def main(args):
    assert Path('/.dockerenv').exists(), 'disposable Docker container required'
    assert [v['ifname'] for v in json.loads(run('ip', '-j', 'link'))] == ['lo'], '--network none required'
    for key in ('net.ipv4.ip_forward', 'net.ipv6.conf.all.forwarding',
                'net.ipv6.conf.default.forwarding', 'net.netfilter.nf_conntrack_acct'):
        # Docker owns /proc/sys (read-only inside even with NET_ADMIN).
        # Verify actual values, not sysctl -w's misleading zero exit status.
        assert run('sysctl', '-n', key).strip() == '1', f'container --sysctl {key}=1 required'
    args.output.mkdir(parents=True, exist_ok=True)
    model_bin = input_model_bin(args.output)
    engine_path = args.upstream / 'binaries/linux-x86_64/nfqws2'
    assert hashlib.sha256(engine_path.read_bytes()).hexdigest() == '0145465409170fe4beeb160ec7acae526e5b1c0a6b2a1d3df197c5e10c21de1d'
    version = run(engine_path, '--version').strip()
    assert 'v1.0.5 (0b8182d24a887059a628d7266577c4ba8e9b8f2d)' in version, version
    print(version, flush=True)
    runtime_companion = Path('/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua')
    runtime_companion.parent.mkdir(parents=True, exist_ok=True)
    runtime_companion.symlink_to(COMPANION)
    installed_lib = Path('/opt/usr/lib/keen-pbr')
    installed_lib.parent.mkdir(parents=True, exist_ok=True)
    installed_lib.symlink_to(LIB, target_is_directory=True)
    pidfile = Path('/opt/var/run/nfqws2.pid')
    pidfile.parent.mkdir(parents=True, exist_ok=True)
    observer = args.output / 'observer.lua'
    observer.write_text(OBSERVER)
    run('ip', 'link', 'set', 'lo', 'up')
    with ExitStack() as owned:
        peers = []
        for _ in range(3):
            p = subprocess.Popen(['unshare', '-n', 'sleep', '300'])
            owned.callback(close, p)
            peers.append(p.pid)
        time.sleep(.1)
        client_ns, server_ns, vpn_ns = peers
        networks = [('kpbr-lan', 'peer-lan', client_ns, '192.0.2.1', '192.0.2.2', '2001:db8:1::1', '2001:db8:1::2'),
                    ('kpbr-wan', 'peer-wan', server_ns, '198.51.100.1', '198.51.100.2', '2001:db8:2::1', '2001:db8:2::2'),
                    ('nwg-test', 'peer-vpn', vpn_ns, '203.0.113.1', '203.0.113.2', '2001:db8:3::1', '2001:db8:3::2')]
        for iface, peer, pid, r4, p4, r6, p6 in networks:
            run('ip', 'link', 'add', iface, 'type', 'veth', 'peer', 'name', peer)
            run('ip', 'link', 'set', peer, 'netns', pid)
            run('ip', 'addr', 'add', r4 + '/24', 'dev', iface)
            run('ip', '-6', 'addr', 'add', r6 + '/64', 'dev', iface, 'nodad')
            run('ip', 'link', 'set', iface, 'up')
            run(*ns(pid, 'ip', 'link', 'set', 'lo', 'up'))
            run(*ns(pid, 'ip', 'addr', 'add', p4 + '/24', 'dev', peer))
            run(*ns(pid, 'ip', '-6', 'addr', 'add', p6 + '/64', 'dev', peer, 'nodad'))
            run(*ns(pid, 'ip', 'link', 'set', peer, 'up'))
            run(*ns(pid, 'ip', 'route', 'add', 'default', 'via', r4))
            run(*ns(pid, 'ip', '-6', 'route', 'add', 'default', 'via', r6))
        run(*ns(client_ns, 'ip', 'addr', 'add', '192.0.2.3/24', 'dev', 'peer-lan'))
        assert run('sysctl', '-n', 'net.ipv6.conf.all.forwarding').strip() == '1'
        cases = [
            ('ipv4-routed', 4, False, 'apply', '', False, 'client'),
            ('ipv4-snat-baseline', 4, True, 'none', '', False, 'client'),
            ('ipv4-snat', 4, True, 'apply', '', False, 'client'),
            ('ipv4-port-remap', 4, True, 'apply', '', True, 'client'),
            ('ipv4-local-router', 4, False, 'apply', '', False, 'router'),
            ('ipv4-local-router-snat', 4, True, 'apply', '', False, 'router-lan'),
            ('ipv4-two-client-same-port', 4, True, 'apply', '', False, 'two'),
            ('ipv4-other-input-pool', 4, True, 'apply', '', False, 'vpn'),
            ('ipv4-policy-mark', 4, True, 'apply', 'mark', False, 'client'),
            ('ipv4-policy-connmark', 4, True, 'apply', 'connmark', False, 'client'),
            ('ipv4-processed-mark', 4, True, 'apply', 'processed', False, 'client'),
            ('ipv4-earlier-forward-accept', 4, True, 'apply', 'early-accept', False, 'client'),
            ('ipv4-earlier-input-accept', 4, False, 'apply', 'early-accept', False, 'router'),
            ('ipv4-input-shortcut-old-append', 4, False, 'append', 'keenetic-input', False, 'router'),
            ('ipv4-input-shortcut', 4, False, 'apply', 'keenetic-input', False, 'router'),
            ('ipv4-input-shortcut-snat', 4, True, 'apply', 'keenetic-input', False, 'router-lan'),
            ('ipv4-input-shortcut-port-remap', 4, True, 'apply', 'keenetic-input', True, 'router-lan'),
            ('ipv4-input-shortcut-repair', 4, True, 'repair', 'keenetic-input', False, 'router-lan'),
            ('ipv4-input-shortcut-remove', 4, True, 'remove', 'keenetic-input', False, 'router-lan'),
            ('ipv4-input-shortcut-rebuild', 4, True, 'rebuild', 'keenetic-input', False, 'router-lan'),
            ('ipv4-input-shortcut-prior-accept', 4, False, 'apply', 'keenetic-input-prior-accept', False, 'router'),
            ('ipv4-input-shortcut-processed-replies', 4, False, 'apply', 'keenetic-input-processed', False, 'router'),
            ('ipv4-input-shortcut-unmatched-accept', 4, False, 'apply', 'keenetic-input-unmatched-accept', False, 'router'),
            ('ipv4-input-shortcut-unmatched-tail', 4, False, 'apply', 'keenetic-input-unmatched-tail', False, 'router'),
            ('ipv4-outside-ports', 4, True, 'apply', 'port', False, 'client'),
            ('ipv4-outside-interface', 4, True, 'apply', 'iface', False, 'client'),
            ('ipv4-udp-baseline', 4, True, 'none', 'udp', False, 'client'),
            ('ipv4-udp-unchanged', 4, True, 'apply', 'udp', False, 'client'),
            ('ipv4-remove', 4, True, 'remove', '', False, 'client'),
            ('ipv4-vendor-rebuild', 4, True, 'rebuild', '', False, 'client'),
            ('ipv6-routed', 6, False, 'apply', '', False, 'client'),
            ('ipv6-snat', 6, True, 'apply', '', False, 'client'),
            ('ipv6-port-remap', 6, True, 'apply', '', True, 'client'),
            ('ipv6-policy-connmark', 6, True, 'apply', 'connmark', False, 'client'),
            ('ipv6-input-shortcut', 6, False, 'apply', 'keenetic-input', False, 'router'),
        ]
        if args.case:
            assert set(args.case) <= {case[0] for case in cases}, 'unknown case'
            cases = [case for case in cases if case[0] in args.case]
        for name, family, nat, mode, policy, remap, origin in cases:
            command = 'ip6tables' if family == 6 else 'iptables'
            server = '2001:db8:2::2' if family == 6 else '198.51.100.2'
            wan = '2001:db8:2::1' if family == 6 else '198.51.100.1'
            source = '2001:db8:1::2' if family == 6 else '192.0.2.2'
            sources, source_ns = [source], client_ns
            if origin == 'router': sources, source_ns = [wan], None
            if origin == 'router-lan': sources, source_ns = ['192.0.2.1'], None
            if origin == 'two': sources = ['192.0.2.2', '192.0.2.3']
            if origin == 'vpn': sources, source_ns = ['203.0.113.2'], vpn_ns
            port, udp = (9443 if policy == 'port' else 443), policy == 'udp'
            queue = 301 if mode == 'rebuild' else 300
            rules = stock(family, queue, 'other-wan' if policy == 'iface' else 'kpbr-wan', policy)
            # Every table is in this disposable network namespace, never host networking.
            run(command + '-restore', input='\n'.join(rules) + '\n')
            run(command, '-t', 'nat', '-F')
            if nat:
                target = '[' + wan + ']:44000-44099' if family == 6 and remap else wan + (':44000-44099' if remap else '')
                for src in sources:
                    run(command, '-t', 'nat', '-A', 'POSTROUTING', '-s', src, '-d', server,
                        '-p', 'udp' if udp else 'tcp', '--dport', port, '-j', 'SNAT', '--to-source', target)
            argv = [str(engine_path), f'--qnum={queue}', '--debug=1',
                    '--lua-init=@' + str(args.upstream / 'lua/zapret-lib.lua'),
                    '--lua-init=@' + str(args.upstream / 'lua/zapret-auto.lua'),
                    '--lua-init=@' + str(runtime_companion), '--lua-init=@' + str(observer),
                    '--filter-tcp=443', '--filter-l7=unknown,http,tls,mtproto',
                    '--payload=tls_client_hello,tls_server_hello,mtproto_initial,unknown,empty',
                    '--in-range=-s27460', '--out-range=-s66996',
                    '--lua-desync=circular:key=tcp_general:hostkey=keen_pbr_tcp_endpoint:fails=2:time=300:retrans=2:inseq=26000:maxseq=65536'
                    ':failure_detector=keen_pbr_syn_failure_detector:success_detector=keen_pbr_tcp_success_detector'
                    ':kpbr_tcp_window=96:kpbr_tcp_reply=postnat_v1',
                    '--in-range=x', '--payload=tls_client_hello,mtproto_initial',
                    '--lua-desync=reply_test_noop:strategy=1', '--lua-desync=reply_test_noop:strategy=2',
                    '--new', '--filter-udp=443', '--payload=all', '--lua-desync=reply_test_udp']
            path = args.output / (name + '.log')
            # The stock engine drops root. Keep its ordinary writable state
            # inside the disposable container, not on the read-only repo mount.
            state = Path('/tmp/nfqws-reply-state') / name
            state.mkdir(parents=True, exist_ok=True)
            os.chown(state, 2147483647, 2147483647)
            env = {**os.environ, 'WRITABLE': str(state),
                   'KEEN_PBR_NFQWS_ROTATOR_LEARNED_PREFIX': str(state / 'learned'),
                   'KEEN_PBR_NFQWS_WINDOW_LIB': str(LIB)}
            if policy.startswith('keenetic-input'):
                env['PATH'] = str(model_bin) + os.pathsep + os.environ['PATH']
                # Keep the injected save wrapper in PATH without faking the
                # running process, pidfile, queue or filesystem: / is still
                # this disposable container's real root.
                env['KEEN_PBR_NFQWS_WINDOW_ROOT'] = '/'
            # Per-packet debug output on a host bind mount can stall the queue
            # and provoke unrelated TCP retries. Capture inside the container;
            # persist the complete evidence after the engine has stopped.
            with tempfile.TemporaryFile(mode='w+', encoding='utf-8') as log:
                engine = subprocess.Popen(argv, stdout=log, stderr=subprocess.STDOUT, env=env)
                try:
                    pidfile.write_text(str(engine.pid) + '\n')
                    deadline = time.monotonic() + 3
                    queue_file = Path('/proc/net/netfilter/nfnetlink_queue')
                    while not (queue_file.exists() and any(
                            row.split() and row.split()[0] == str(queue)
                            for row in queue_file.read_text().splitlines())):
                        if engine.poll() is not None or time.monotonic() > deadline:
                            raise RuntimeError(f'NFQUEUE startup failed; inspect {path}')
                        time.sleep(.02)
                    before = run(command + '-save', '-t', 'mangle')
                    (args.output / (name + '.before.rules')).write_text(before)
                    if mode != 'none':
                        run('sh', LIB / 'nfqws-tcp-window.sh', 'apply', command, env=env)
                        after = run(command + '-save', '-t', 'mangle')
                        (args.output / (name + '.after.rules')).write_text(after)
                        assert 'keen-pbr-sb:nfqws:tcp-reply:v1' in after, after
                        run('sh', LIB / 'nfqws-tcp-window.sh', 'apply', command, env=env)
                        repeated = run(command + '-save', '-t', 'mangle')
                        (args.output / (name + '.repeat.rules')).write_text(repeated)
                        clean = firewall_policy_lines
                        assert clean(after) == clean(repeated), 'non-idempotent helper'
                        original = lambda text: [x for x in clean(text) if 'keen-pbr-sb:nfqws:' not in x and not x.startswith(':KpbrNfqTcpReply ')]
                        assert original(after) == original(before), 'unowned firewall policy changed'
                        if policy.startswith('keenetic-input'):
                            input_rules = [x for x in after.splitlines() if x.startswith('-A INPUT ')]
                            hooks = [x for x in input_rules if 'keen-pbr-sb:nfqws:tcp-reply:v1' in x]
                            assert len(hooks) == 2 and input_rules[-1] == hooks[-1], input_rules
                            hook = hooks[0]
                            assert NATIVE_INPUT_MATCH in hook, 'early observation must use all native match conditions'
                            assert input_rules.index(hook) + 1 == input_rules.index(NATIVE_INPUT_ACCEPT), input_rules
                            assert 'native-input-prefix' in input_rules[0], input_rules
                            if policy == 'keenetic-input-prior-accept':
                                assert 'foreign-prior-accept' in input_rules[1], input_rules
                            if mode in ('append', 'repair'):
                                # Exact previous placement: only the generic
                                # tail hook remains. Prove repair or reproduce
                                # the missing incoming observation.
                                rule = shlex.split(hook)[1:]
                                run(command, '-t', 'mangle', '-D', *rule)
                                if mode == 'repair':
                                    run('sh', LIB / 'nfqws-tcp-window.sh', 'apply', command, env=env)
                                    assert clean(after) == clean(run(command + '-save', '-t', 'mangle')), 'old INPUT placement not repaired'
                        if mode == 'remove':
                            run('sh', LIB / 'nfqws-tcp-window.sh', 'remove', command, env=env)
                            assert clean(before) == clean(run(command + '-save', '-t', 'mangle'))
                        if mode == 'rebuild':
                            hook_env = {**env, 'table': 'mangle', 'type': command}
                            run('sh', HOOKS / '099-keen-pbr-nfqws-tcp.sh', env=hook_env)
                            assert 'KpbrNfqTcpReply' not in run(command + '-save', '-t', 'mangle')
                            for chain in ('nfqws_pre', 'nfqws_post'):
                                run(command, '-t', 'mangle', '-F', chain)
                            refill = ['*mangle'] + [x for x in rules if x.startswith(('-A nfqws_pre ', '-A nfqws_post '))] + ['COMMIT']
                            run(command + '-restore', '--noflush', input='\n'.join(refill) + '\n')
                            run('sh', HOOKS / '110-keen-pbr-nfqws-tcp.sh', env=hook_env)
                            assert 'keen-pbr-sb:nfqws:tcp-reply:v1' in run(command + '-save', '-t', 'mangle')
                    (args.output / (name + '.rules')).write_text(run(command + '-save', '-t', 'mangle'))
                    assert run('sysctl', '-n', 'net.ipv6.conf.all.forwarding').strip() == '1', 'IPv6 forwarding changed during case'
                    count = 3 * len(sources)
                    srv = subprocess.Popen(ns(server_ns, sys.executable, __file__, 'serve', server, port,
                                              count, int(udp), args.reply_kind),
                                           stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                    try:
                        assert srv.stdout.readline().strip() == 'READY'
                        req = [sys.executable, __file__, 'request', server, port, ','.join(sources),
                               int(udp), int(origin == 'two'), args.reply_kind]
                        if source_ns: req = ns(source_ns, *req)
                        try:
                            result = run(*req)
                        except RuntimeError:
                            # Only the disposable test namespaces, for failures
                            # before the queued packet reaches the engine.
                            diagnostic = []
                            for label, pid in [('router', None), ('client', client_ns), ('server', server_ns)]:
                                for command_args in [('ip', '-6', 'addr'), ('ip', '-6', 'route'),
                                                     ('ip', '-6', 'neigh'),
                                                     ('sysctl', 'net.ipv6.conf.all.forwarding',
                                                      'net.ipv6.conf.all.disable_ipv6')]:
                                    command_args = ns(pid, *command_args) if pid else command_args
                                    diagnostic += [label, run(*command_args)]
                            diagnostic += [run(command, '-t', 'mangle', '-nvL')]
                            (args.output / (name + '-network.txt')).write_text('\n'.join(diagnostic))
                            raise
                        assert result.count('REPLY_OK') == count, result
                        assert srv.wait(timeout=4) == 0, srv.stderr.read()
                        server_output = srv.stdout.read()
                        client_retries = retry_budget(result, count) if not udp else 0
                        server_retries = retry_budget(server_output, count) if not udp else 0
                        (args.output / (name + '.sockets.log')).write_text(result + server_output)
                    finally:
                        close(srv)
                    time.sleep(.05)
                    if policy.startswith('keenetic-input'):
                        counters = run(command + '-save', '-c', '-t', 'mangle')
                        tail = next(x for x in counters.splitlines() if 'native-input-tail' in x)
                        tail_packets = int(tail.split(']', 1)[0].split(':', 1)[0].lstrip('['))
                        if policy.startswith('keenetic-input-unmatched'):
                            assert tail_packets > 0, 'nonmatching shortcut bypassed later native INPUT policy'
                        else:
                            assert tail_packets == 0, 'matching shortcut did not end native INPUT processing'
                        (args.output / (name + '.counters')).write_text(counters)
                finally:
                    close(engine)
                    pidfile.unlink(missing_ok=True)
                    log.seek(0)
                    path.write_text(log.read())
            text = path.read_text()
            rows = [x.split('\t') for x in text.splitlines() if x.startswith('PACKET\t')]
            hellos = [r for r in rows if r[1] == 'true' and r[4] == 'tls_client_hello']
            out = {r[2] for r in hellos}
            verify_observation_count(len(hellos), len(out), client_retries, name + ' ClientHello')
            if args.reply_kind in ('empty-fin', 'client-fin'):
                responses = [r for r in rows if r[1] == 'false' and r[3] == '1'
                             and r[5] == '0' and int(r[10]) & 1]
            else:
                responses = [r for r in rows if r[1] == 'false' and r[3] == '1'
                             and r[5] == str(len(REPLIES[args.reply_kind]))]
            incoming = {r[2] for r in responses}
            slots = {r[6] for r in rows}
            failed = {r[2] for r in rows if r[7] == 'true'}
            excluded = policy in ('mark', 'connmark', 'processed', 'port', 'iface', 'udp')
            earlier_accept = policy in ('early-accept', 'keenetic-input-prior-accept', 'keenetic-input-unmatched-accept') or mode == 'append'
            # Local requests do not traverse PREROUTING: this model marks
            # replies only. Existing client cases mark both directions.
            incoming_excluded = policy == 'keenetic-input-processed'
            if earlier_accept or incoming_excluded:
                assert len(out) == count and not responses and not failed, (name, out, responses, failed)
                assert not any(r[1] == 'false' for r in rows), (name, 'excluded reply was queued')
                assert '2' not in slots, 'must respect preceding policy and processed-reply exclusion'
            elif excluded:
                assert not rows, (name, rows[:3])
                if udp:
                    # UDP deliberately keeps stock pre-DNAT observation. The
                    # incoming tuple therefore still contains the WAN address;
                    # do not mistake its separate engine context for packet loss.
                    udp_out = text.count(f'IP4: {source} => {server} proto=udp ')
                    udp_in = text.count(f'IP4: {server} => {wan} proto=udp ')
                    assert udp_out == udp_in == count, (name, udp_out, udp_in)
                    assert text.count('UDP_PACKET true') == count, text[-3000:]
                    assert text.count('UDP_PACKET false') == 0, text[-3000:]
                    assert text.count('proto=udp ') == 2 * count, 'UDP queued twice'
            else:
                assert len(out) == count and len(incoming) == count, (name, out, responses)
                verify_observation_count(len(responses), count, server_retries, name + ' response')
                expected = not nat or mode not in ('none', 'remove')
                assert (out == incoming) == expected, (name, out, incoming)
                expected_failure = expected and args.reply_kind in ('alert', 'empty-fin')
                assert ('2' in slots) == expected_failure, (name, slots)
                assert len(failed) == (count if expected_failure else 0), (name, failed)
            print(json.dumps(dict(case=name, replies=count, outgoing_contexts=len(out),
                                  client_retries=client_retries, server_retries=server_retries,
                                  reply_kind=args.reply_kind, incoming_responses=len(responses),
                                  incoming_alerts=len(responses) if args.reply_kind == 'alert' else 0,
                                  shared_contexts=bool(out) and out == incoming,
                                  failed_contexts=len(failed), slots=sorted(slots),
                                  policy_preserved=True if excluded or earlier_accept or incoming_excluded else None,
                                  input_shortcut_model=policy.startswith('keenetic-input'))), flush=True)
        print(f'{len(cases)} native packet cases passed ({args.reply_kind}); no live router/Chrome acceptance', flush=True)


if __name__ == '__main__':
    if sys.argv[1:2] == ['serve']:
        serve(sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), bool(int(sys.argv[5])), sys.argv[6])
    elif sys.argv[1:2] == ['request']:
        request(sys.argv[2], int(sys.argv[3]), sys.argv[4].split(','), bool(int(sys.argv[5])),
                bool(int(sys.argv[6])), sys.argv[7])
    else:
        parser = argparse.ArgumentParser()
        parser.add_argument('--upstream', required=True, type=Path)
        parser.add_argument('--output', required=True, type=Path)
        parser.add_argument('--case', action='append', help='run a named case (default: all)')
        parser.add_argument('--reply-kind', choices=tuple(REPLIES), default='alert',
                            help='controlled server response or client-initiated close')
        main(parser.parse_args())
