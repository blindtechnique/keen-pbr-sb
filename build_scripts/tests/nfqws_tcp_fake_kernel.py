"""TCP fake isolation regression, only in a disposable --network none container.

Requires Linux AF_PACKET/CAP_NET_RAW. Both endpoints are local sockets; refuses
any network interface except loopback. This checks receiver semantics, not
Keenetic ABI, TLS/DPI bypass, or browser acceptance.
"""
from contextlib import ExitStack
from pathlib import Path
import runpy
import socket
import struct
import time


def checksum(data):
    if len(data) % 2:
        data += b'\0'
    total = sum(struct.unpack('!%dH' % (len(data) // 2), data))
    while total >> 16:
        total = (total & 65535) + (total >> 16)
    return (~total) & 65535


def decode(frame):
    if len(frame) < 54 or frame[12:14] != b'\x08\x00':
        return None
    ip = frame[14:]
    ihl = (ip[0] & 15) * 4
    if ip[9] != 6 or ip[12:20] != b'\x7f\0\0\1' * 2:
        return None
    total = struct.unpack_from('!H', ip, 2)[0]
    tcp = ip[ihl:total]
    if len(tcp) < 20:
        return None
    size = (tcp[12] >> 4) * 4
    return (*struct.unpack('!HHII', tcp[:12]), tcp[13], tcp[:size], tcp[size:])


def receive_matching(sniffer, match):
    until = time.monotonic() + 2
    while time.monotonic() < until:
        sniffer.settimeout(max(0.001, until - time.monotonic()))
        row = decode(sniffer.recv(65535))
        if row and match(row):
            return row
    raise RuntimeError('Local handshake/injected packet was not observed')


def experiment(offset, ack_offset, badsum=False):
    with ExitStack() as stack:
        def opened(*args):
            return stack.enter_context(socket.socket(*args))

        sniff = opened(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3))
        sniff.bind(('lo', 0))
        listener = opened()
        listener.bind(('127.0.0.1', 0))
        listener.listen(1)
        port = listener.getsockname()[1]
        client = opened()
        client.connect(('127.0.0.1', port))
        peer = stack.enter_context(listener.accept()[0])
        peer.settimeout(2)
        cport = client.getsockname()[1]
        row = receive_matching(sniff, lambda r: r[0] == cport and r[1] == port and r[4] == 16)
        _, _, seq, ack, _, original, _ = row
        tcp = bytearray(original)
        fake_seq = (seq + offset) % 2**32
        struct.pack_into('!II', tcp, 4, fake_seq, (ack + ack_offset) % 2**32)
        tcp[13] = 24  # ACK + PSH, never SYN/RST/FIN
        tcp[16:18] = b'\0\0'
        segment = tcp + b'FAKE'
        addresses = socket.inet_aton('127.0.0.1') * 2
        pseudo = addresses + struct.pack('!BBH', 0, 6, len(segment))
        struct.pack_into('!H', segment, 16, checksum(pseudo + segment) ^ int(badsum))
        assert (checksum(pseudo + segment) != 0) == badsum
        ip = bytearray(struct.pack('!BBHHHBBH4s4s', 69, 0, 20 + len(segment), 42, 0, 64, 6, 0,
                                   socket.inet_aton('127.0.0.1'), socket.inet_aton('127.0.0.1')))
        struct.pack_into('!H', ip, 10, checksum(ip))
        raw = opened(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
        raw.sendto(ip + segment, ('127.0.0.1', port))
        # A bad checksum must not get an ACK: observe our injected frame instead
        # of waiting for a reply that would contradict the rejection contract.
        receive_matching(sniff, lambda r: r[0] == cport and r[1] == port
                         and r[2] == fake_seq and r[6] == b'FAKE')
        if not badsum:
            receive_matching(sniff, lambda r: r[0] == port and r[1] == cport
                             and r[4] & 16 and not r[4] & 2)
        client.sendall(b'A' * 10000)
        client.sendall(b'REAL')
        received = b''
        while len(received) < 10004:
            block = peer.recv(16384)
            if not block:
                break
            received += block
        return received


def main():
    if {name for _, name in socket.if_nameindex()} != {'lo'}:
        raise SystemExit('Refusing non-isolated network: run in a disposable --network none container')
    root = Path(__file__).resolve().parents[2]
    gen = runpy.run_path(str(root / 'build_scripts/build-nfqws-strategies.py'))
    # Keep the unsafe baseline as positive evidence that this test can detect
    # future-sequence injection, not merely a no-op raw socket fixture.
    old = experiment(10000, 0)
    assert old == b'A' * 10000 + b'FAKE', (len(old), old[-4:])
    print('Unsafe +10000 without independent guard: reproduced FAKE replacing REAL')
    negative = experiment(-10000, -66000)
    assert negative == b'A' * 10000 + b'REAL', (len(negative), negative[-4:])
    print('Negative offsets: receiver intact (not a claim of real Keenetic TLS success)')
    for index in (0, 4, 6):
        action = gen['TCP_TIERS'][index][0]
        parts = action.split(':')[1:]
        fields = dict(item.split('=', 1) for item in parts if '=' in item)
        assert 'badsum' in parts, 'Standalone positive-sequence fake lost its independent guard'
        fixed = experiment(int(fields['tcp_seq']), int(fields.get('tcp_ack', '0')), True)
        assert fixed == b'A' * 10000 + b'REAL', (index, len(fixed), fixed[-4:])
        print('Generated TCP slot %d: bad checksum rejected, REAL intact' % (index + 1))
    print('5 local kernel cases PASS; Internet/router/browser acceptance is separate')


if __name__ == '__main__':
    main()
