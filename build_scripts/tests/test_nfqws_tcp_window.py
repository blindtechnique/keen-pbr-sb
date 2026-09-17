"""Optional TCP rules: stock policy ownership, lifecycle and upgrade replay."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from build_scripts.tests.nfqws_tcp_reply_native import firewall_policy_lines

ROOT = Path(__file__).resolve().parents[2]
LIB = ROOT / 'packages/keenetic/keen-pbr/files/opt/usr/lib/keen-pbr'
TAG = 'keen-pbr-sb:nfqws:tcp-window:v1'
REPLY_TAG = 'keen-pbr-sb:nfqws:tcp-reply:v1'
REPLY_CHAIN = 'KpbrNfqTcpReply'
KEENETIC_INPUT_ACCEPT = '-A INPUT -m state --state RELATED,ESTABLISHED -m connndmmark ! --mark 0x20/0x20 -j ACCEPT'


class NativePolicyComparisonTest(unittest.TestCase):
    def test_live_chain_counters_and_save_headers_are_not_policy(self):
        before = '# before\n*mangle\n:INPUT ACCEPT [1:72]\nCOMMIT\n'
        after = '# after\n*mangle\n:INPUT ACCEPT [3:264]\nCOMMIT\n'
        self.assertEqual(firewall_policy_lines(before), firewall_policy_lines(after))

    def test_default_policy_change_remains_visible(self):
        self.assertNotEqual(firewall_policy_lines(':INPUT ACCEPT [0:0]'),
                            firewall_policy_lines(':INPUT DROP [0:0]'))

    def test_chain_identity_and_removal_remain_visible(self):
        original = ':INPUT ACCEPT [0:0]\n:FOREIGN - [0:0]'
        self.assertNotEqual(firewall_policy_lines(original),
                            firewall_policy_lines(original.replace('FOREIGN', 'OTHER')))
        self.assertNotEqual(firewall_policy_lines(original),
                            firewall_policy_lines(':INPUT ACCEPT [0:0]'))

    def test_rule_target_changes_remain_visible(self):
        original = '-A INPUT -p tcp --dport 443 -j ACCEPT'
        self.assertNotEqual(firewall_policy_lines(original),
                            firewall_policy_lines(original.replace('ACCEPT', 'DROP')))

    def test_rule_order_remains_visible(self):
        rules = ['-A INPUT -p udp -j ACCEPT', '-A INPUT -j DROP']
        self.assertNotEqual(firewall_policy_lines('\n'.join(rules)),
                            firewall_policy_lines('\n'.join(reversed(rules))))

    def test_counter_like_rule_content_is_not_normalized(self):
        original = '-A INPUT -m comment --comment "[1:72]" -j ACCEPT'
        self.assertEqual(firewall_policy_lines(original), [original])
        self.assertNotEqual(firewall_policy_lines(original),
                            firewall_policy_lines(original.replace('[1:72]', '[3:264]')))


def keenetic_input_stock():
    # Sanitized shape of the observed Keenetic mangle INPUT chain. The custom
    # match is only a placement anchor; its mark semantics are not emulated.
    return stock()[:-1] + [
        ':_NDM_WGOBFS_IN - [0:0]', ':_NDM_HTTP_INPUT_TLS_ - [0:0]',
        '-A INPUT -p udp -j _NDM_WGOBFS_IN', KEENETIC_INPUT_ACCEPT,
        '-A INPUT -p tcp -m tcp --dport 443 -j _NDM_HTTP_INPUT_TLS_', 'COMMIT']


def stock(limit=15, queue=300, interface='eth3', policy=True):
    lines = ['*mangle', ':nfqws_pre - [0:0]', ':nfqws_post - [0:0]',
             '-A PREROUTING -j nfqws_pre', '-A POSTROUTING -j nfqws_post',
             '-A FORWARD -m comment --comment "unrelated-user-rule" -j ACCEPT']
    for chain, direction, iface, ports in [('nfqws_pre', 'reply', '-i', '--sports'),
                                           ('nfqws_post', 'original', '-o', '--dports')]:
        prefix = f'-A {chain} {iface} {interface}'
        if policy:
            lines += [prefix + ' -m mark --mark 0x123/0x0fffffff -j RETURN',
                      prefix + ' -m connmark --mark 0x20000000/0x20000000 -j RETURN']
        for proto, port in [('tcp', '80,443,8443'), ('udp', '443,590:600')]:
            lines += [f'{prefix} -p {proto} -m mark ! --mark 0x40000000/0x40000000'
                      f' -m multiport {ports} {port} -m connbytes --connbytes 1:{limit}'
                      f' --connbytes-mode packets --connbytes-dir {direction}'
                      f' -j NFQUEUE --queue-num {queue} --queue-bypass']
        flags = ['FIN', 'RST'] + (['SYN,ACK'] if direction == 'reply' else [])
        for flag in flags:
            lines += [f'{prefix} -p tcp -m mark ! --mark 0x40000000/0x40000000'
                      f' -m multiport {ports} 80,443,8443 -m tcp --tcp-flags {flag} {flag}'
                      f' -j NFQUEUE --queue-num {queue} --queue-bypass']
    return lines + ['COMMIT']


FAKE = r'''#!/usr/bin/env python3
import json, os, pathlib, sys
p = pathlib.Path(os.environ['KEEN_PBR_NFQWS_WINDOW_ROOT'])
family = 'ip6tables' if pathlib.Path(sys.argv[0]).name.startswith('ip6') else 'iptables'
state = p / (family + '.json')
lines = json.loads(state.read_text())
if sys.argv[0].endswith('-save'):
    print('\n'.join(lines))
else:
    assert sys.argv[1:] == ['--noflush'], sys.argv
    batch = sys.stdin.read().splitlines()
    assert batch[0] == '*mangle' and batch[-1] == 'COMMIT'
    if (p / 'fail-restore').exists(): sys.exit(4)
    if (p / 'lock-once').exists():
        (p / 'lock-once').unlink()
        sys.exit(4)
    for line in batch[1:-1]:
        if line == '-N KpbrNfqTcpReply':
            assert ':KpbrNfqTcpReply - [0:0]' not in lines
            lines.insert(1, ':KpbrNfqTcpReply - [0:0]')
            continue
        if line == '-X KpbrNfqTcpReply':
            assert not any(' KpbrNfqTcpReply ' in x or x.endswith(' KpbrNfqTcpReply') for x in lines)
            lines.remove(':KpbrNfqTcpReply - [0:0]')
            continue
        assert any(tag in line for tag in ('keen-pbr-sb:nfqws:tcp-window:v1', 'keen-pbr-sb:nfqws:tcp-reply:v1')), line
        assert line.split()[1] in ('nfqws_pre', 'nfqws_post', 'KpbrNfqTcpReply', 'INPUT', 'FORWARD'), line
        if line.startswith('-I '):
            _, chain, number, rule = line.split(' ', 3)
            assert chain in ('nfqws_pre', 'INPUT'), line
            positions = [i for i,x in enumerate(lines) if x.startswith('-A ' + chain + ' ')]
            number = int(number)
            assert 1 <= number <= len(positions) + 1, line
            index = positions[number - 1] if number <= len(positions) else (positions[-1] + 1 if positions else len(lines) - 1)
            lines.insert(index, '-A ' + chain + ' ' + rule)
            continue
        if line.startswith('-D '): lines.remove('-A ' + line[3:])
        else: lines.insert(-1, line)
    state.write_text(json.dumps(lines))
    with (p / 'restores').open('a') as f: f.write(family + '\n')
'''


class WindowTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix='kpbr-nfqws-window-')
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / 'bin'
        self.bin.mkdir()
        for family in ('iptables', 'ip6tables'):
            for command in ('save', 'restore'):
                path = self.bin / f'{family}-{command}'
                path.write_text(FAKE)
                path.chmod(0o755)
            self.save(stock(), family)
        proc = self.root / 'proc/42'
        proc.mkdir(parents=True)
        (proc / 'comm').write_text('nfqws2\n')
        (proc / 'stat').write_text('42 (nfqws2) S ' + '0 ' * 18 + '1000\n')
        self.argv()
        self.queues()
        pid = self.root / 'opt/var/run/nfqws2.pid'
        pid.parent.mkdir(parents=True)
        pid.write_text('42\n')
        self.env = {**os.environ, 'PATH': str(self.bin) + os.pathsep + os.environ['PATH'],
                    'KEEN_PBR_NFQWS_WINDOW_ROOT': str(self.root),
                    'KEEN_PBR_NFQWS_WINDOW_LIB': str(LIB)}

    def save(self, lines, family='iptables'):
        (self.root / (family + '.json')).write_text(json.dumps(lines))

    def read(self, family='iptables'):
        return json.loads((self.root / (family + '.json')).read_text())

    def argv(self, enabled=True, queue=300, reply=False):
        args = ['/opt/usr/bin/nfqws2', f'--qnum={queue}',
                '--lua-init=@/opt/var/lib/keen-pbr/nfqws-rotator-telemetry-v1.lua',
                '--lua-desync=circular:fails=2:success_detector=keen_pbr_tcp_success_detector'
                + (':kpbr_tcp_window=96' if enabled else '')
                + (':kpbr_tcp_reply=postnat_v1' if reply else '') + ':key=tcp_general']
        (self.root / 'proc/42/cmdline').write_bytes(('\0'.join(args) + '\0').encode())

    def queues(self, queue=300):
        table = self.root / 'proc/net/netfilter/nfnetlink_queue'
        table.parent.mkdir(parents=True, exist_ok=True)
        table.write_text(f'{queue} 42 0 2 65531 0 0 111 1\n')

    def run_helper(self, mode='apply', family='all', expected=0, shell=None):
        shell = shell or ([shutil.which('busybox'), 'sh'] if shutil.which('busybox') else ['sh'])
        result = subprocess.run(shell + [str(LIB / 'nfqws-tcp-window.sh'), mode, family],
                                env=self.env, capture_output=True, text=True, timeout=8)
        self.assertEqual(result.returncode, expected, result.stdout + result.stderr)
        return result.stdout

    def ours(self, family='iptables'):
        return [line for line in self.read(family) if TAG in line]

    def test_extends_tcp_only_after_vendor_policy_and_keeps_stock_bytes(self):
        before = self.read()
        self.run_helper()
        self.assertEqual([x for x in self.read() if TAG not in x], before)
        self.assertEqual(len(self.ours()), 2)
        self.assertEqual(len(self.ours('ip6tables')), 2)
        for line in self.ours():
            self.assertIn('-p tcp', line)
            self.assertIn('--tcp-flags FIN,SYN,RST NONE', line)
            self.assertIn('--connbytes 16:96', line)
            self.assertIn('! --mark 0x40000000/0x40000000', line)
            self.assertIn('--queue-num 300 --queue-bypass', line)
            self.assertNotIn('CONNMARK', line)

    def test_repeated_apply_preserves_counters_without_new_restore(self):
        self.run_helper()
        before = (self.root / 'restores').read_text()
        for _ in range(3): self.run_helper()
        self.assertEqual((self.root / 'restores').read_text(), before)

    def test_upgrade_replaces_vendor_chains_then_existing_events_restore_window(self):
        self.run_helper()
        # Like package reinstall/start: vendor recreates its own chains. Our
        # installed helper and live profile survive outside its package paths.
        self.save(stock(queue=301, interface='eth4'))
        self.save(stock(queue=301, interface='eth4'), 'ip6tables')
        self.argv(queue=301)
        self.queues(queue=301)
        self.run_helper()
        self.assertTrue(all('eth4' in x and '--queue-num 301' in x for x in self.ours()))
        self.assertEqual(len(self.ours()), 2)

    def test_changed_vendor_packet_budget_is_not_hardcoded_as_fifteen(self):
        self.save(stock(limit=32))
        self.run_helper(family='iptables')
        self.assertTrue(all('--connbytes 33:96' in x for x in self.ours()))
        self.save(stock(limit=128))
        self.run_helper(family='iptables')
        self.assertFalse(self.ours())

    def test_stop_or_removed_capability_only_removes_our_rules(self):
        self.run_helper()
        self.argv(enabled=False)
        self.run_helper()
        self.assertEqual(self.read(), stock())
        self.argv()
        self.run_helper()
        (self.root / 'opt/var/run/nfqws2.pid').unlink()
        self.run_helper()
        self.assertEqual(self.read(), stock())

    def test_no_bound_queue_no_extension(self):
        self.queues(queue=305)
        self.run_helper()
        self.assertEqual(self.read(), stock())

    def test_future_unknown_queue_selector_disables_only_extension(self):
        self.run_helper()
        lines = [x.replace('--connbytes 1:15', '--connbytes 1:15 -m length --length 0:1500')
                 if '-p tcp' in x and TAG not in x else x for x in self.read()]
        self.save(lines)
        self.run_helper(family='iptables')
        self.assertEqual(self.read(), [x for x in lines if TAG not in x])

    def test_unbounded_new_tcp_queue_rule_does_not_cause_double_processing(self):
        self.save(stock()[:-1] + ['-A nfqws_pre -p tcp -j NFQUEUE --queue-num 300 --queue-bypass', 'COMMIT'])
        self.run_helper(family='iptables')
        self.assertFalse(self.ours())

    def test_restore_failure_never_flushes_or_controls_services(self):
        (self.root / 'fail-restore').touch()
        self.run_helper(expected=1)
        self.assertEqual(self.read(), stock())

    def test_transient_xtables_contention_retries_without_service_control(self):
        (self.root / 'lock-once').touch()
        self.run_helper()
        self.assertEqual(len(self.ours()), 2)
        self.assertEqual(len(self.ours('ip6tables')), 2)

    def test_duplicate_vendor_template_declines_extension(self):
        lines = stock()
        duplicate = next(x for x in lines if '-p tcp' in x and '--connbytes' in x)
        self.save(lines[:-1] + [duplicate, 'COMMIT'])
        self.run_helper(family='iptables')
        self.assertFalse(self.ours())

    def test_protocol_agnostic_queue_declines_extension(self):
        self.save(stock()[:-1] + ['-A nfqws_pre -j NFQUEUE --queue-num 300 --queue-bypass', 'COMMIT'])
        self.run_helper(family='iptables')
        self.assertFalse(self.ours())

    def lock(self, content):
        runtime = self.root / 'var/run/keen-pbr-nfqws-window'
        runtime.mkdir(parents=True)
        path = runtime / 'lock'
        path.write_text(content)
        return path

    def test_live_helper_lock_is_nonblocking_and_not_stolen(self):
        ticks = Path('/proc/self/stat').read_text().rsplit(') ', 1)[1].split()[19]
        content = f'{os.getpid()} {ticks}\n'
        path = self.lock(content)
        self.run_helper()
        self.assertEqual(path.read_text(), content)
        self.assertEqual(self.read(), stock())

    def test_stale_process_generation_lock_recovers(self):
        path = self.lock(f'{os.getpid()} 0\n')
        self.run_helper()
        self.assertEqual(len(self.ours()), 2)
        self.assertFalse(path.exists())

    def test_malformed_lock_never_mutates_vendor_state(self):
        self.lock(' 123\n')
        self.run_helper()
        self.assertEqual(self.read(), stock())

    def test_reduced_stat_without_custom_format_is_supported(self):
        # Keenetic exposes only BusyBox terse metadata, not GNU stat -c.
        stat = self.bin / 'stat'
        stat.write_text('#!/usr/bin/env python3\nimport os, sys\n'
                        'assert sys.argv[1] == "-t", sys.argv\n'
                        's = os.stat(sys.argv[2])\n'
                        'print(sys.argv[2], s.st_size, s.st_blocks, format(s.st_mode, "x"), s.st_uid, s.st_gid)\n')
        stat.chmod(0o755)
        self.run_helper()
        self.assertEqual(len(self.ours()), 2)

    def test_installed_comment_module_is_loaded_only_for_an_active_extension(self):
        release = os.uname().release
        module = self.root / 'lib/modules' / release / 'xt_comment.ko'
        module.parent.mkdir(parents=True)
        module.touch()
        loader = self.bin / 'insmod'
        loader.write_text('#!/usr/bin/env python3\nimport os, pathlib, sys\n'
                          'p = pathlib.Path(os.environ["KEEN_PBR_NFQWS_WINDOW_ROOT"])\n'
                          'assert sys.argv[1] == str(p / "lib/modules" / os.uname().release / "xt_comment.ko")\n'
                          '(p / "proc/net/ip_tables_matches").write_text("comment\\n")\n')
        loader.chmod(0o755)
        # BusyBox standalone ash resolves insmod as a builtin, ahead of PATH;
        # use dash for this injected loader. All other cases still use ash.
        self.run_helper('status', shell=['/bin/sh'])
        self.assertFalse((self.root / 'proc/net/ip_tables_matches').exists())
        self.run_helper(shell=['/bin/sh'])
        self.assertEqual((self.root / 'proc/net/ip_tables_matches').read_text(), 'comment\n')
        self.assertEqual(len(self.ours()), 2)

    def test_family_hook_does_not_touch_other_family(self):
        self.run_helper(family='iptables')
        self.assertEqual(len(self.ours()), 2)
        self.assertFalse(self.ours('ip6tables'))

    def test_remove_has_no_dependency_on_active_process_or_config(self):
        self.run_helper()
        (self.root / 'proc/42/comm').write_text('other-process\n')
        self.run_helper('remove')
        self.assertEqual(self.read(), stock())

    def test_oversized_argv_declines_capability(self):
        (self.root / 'proc/42/cmdline').write_bytes(b'x' * 262145)
        self.run_helper()
        self.assertFalse(self.ours())


class ReplyWindowTest(unittest.TestCase):
    def setUp(self):
        self.f = WindowTest()
        self.f.setUp()
        self.addCleanup(self.f.doCleanups)
        self.f.argv(reply=True)

    def reply_rules(self, family='iptables'):
        return [x for x in self.f.read(family) if REPLY_TAG in x]

    def clean(self, lines):
        return [x for x in lines if TAG not in x and REPLY_TAG not in x and not x.startswith(':' + REPLY_CHAIN)]

    def test_postnat_copies_read_only_policy_and_tcp_but_preserves_vendor_and_udp(self):
        before = self.f.read()
        self.f.run_helper()
        self.assertEqual(self.clean(self.f.read()), before)
        incoming = [x for x in self.reply_rules() if x.startswith('-A ' + REPLY_CHAIN)]
        self.assertEqual(len(incoming), 7)  # two exclusions, four stock queues, extension
        self.assertEqual(sum('--connbytes 16:96' in x for x in incoming), 1)
        self.assertFalse(any('-p udp' in x or '-j CONNMARK' in x for x in incoming))
        self.assertTrue(all('-i eth3' in x for x in incoming))
        pre = next(x for x in self.f.read() if x.startswith('-A nfqws_pre '))
        self.assertIn(REPLY_TAG, pre)
        self.assertTrue(pre.endswith('-j RETURN'))
        for hook in ('INPUT', 'FORWARD'):
            self.assertEqual(sum(x.startswith('-A '+hook+' ') for x in self.reply_rules()), 1)
        self.assertEqual(len(self.f.ours()), 1)
        self.assertIn('-A nfqws_post ', self.f.ours()[0])

    def test_repeated_apply_is_idempotent(self):
        self.f.run_helper()
        restores = (self.f.root / 'restores').read_text()
        for _ in range(3): self.f.run_helper()
        self.assertEqual((self.f.root / 'restores').read_text(), restores)

    @unittest.skipUnless(shutil.which('busybox'), 'target BusyBox required')
    def test_reply_planner_and_lifecycle_use_target_busybox_awk(self):
        (self.f.bin / 'awk').symlink_to(shutil.which('busybox'))
        self.f.save(keenetic_input_stock())
        before = self.f.read()
        self.f.run_helper(family='iptables')
        self.assertTrue(self.reply_rules())
        restores = (self.f.root / 'restores').read_text()
        self.f.run_helper(family='iptables')
        self.assertEqual((self.f.root / 'restores').read_text(), restores)
        self.f.run_helper('remove', family='iptables')
        self.assertEqual(self.f.read(), before)

    def input_rules(self, family='iptables'):
        return [x for x in self.f.read(family) if x.startswith('-A INPUT ')]

    def assert_input_anchor(self, family='iptables'):
        rules = self.input_rules(family)
        hooks = [x for x in rules if REPLY_TAG in x]
        self.assertEqual(len(hooks), 2, rules)
        hook, tail = hooks
        self.assertEqual(rules.index(hook) + 1, rules.index(KEENETIC_INPUT_ACCEPT), rules)
        self.assertIn('-p tcp -m state --state RELATED,ESTABLISHED -m connndmmark ! --mark 0x20/0x20', hook)
        self.assertEqual(rules[-1], tail)
        self.assertNotIn('connndmmark', tail)

    def test_known_keenetic_input_accept_is_observed_without_editing_native_policy(self):
        before = keenetic_input_stock()
        self.f.save(before)
        self.f.run_helper(family='iptables')
        self.assert_input_anchor()
        self.assertEqual(self.input_rules()[0], '-A INPUT -p udp -j _NDM_WGOBFS_IN')
        self.assertEqual(self.clean(self.f.read()), before)
        self.assertEqual(self.f.read('ip6tables'), stock())
        self.f.run_helper('remove', family='iptables')
        self.assertEqual(self.f.read(), before)

    def test_old_appended_input_hook_is_moved_once_not_duplicated(self):
        before = keenetic_input_stock()
        self.f.save(before)
        self.f.run_helper(family='iptables')
        lines = self.f.read()
        hook = next(x for x in self.input_rules() if REPLY_TAG in x)
        # Previous implementation had only the unconditional tail hook.
        lines.remove(hook)
        self.f.save(lines)
        restores = (self.f.root / 'restores').read_text()
        self.f.run_helper(family='iptables')
        self.assert_input_anchor()
        self.assertEqual((self.f.root / 'restores').read_text(), restores + 'iptables\n')
        repaired = self.f.read()
        for _ in range(3): self.f.run_helper(family='iptables')
        self.assertEqual(self.f.read(), repaired)
        self.assertEqual((self.f.root / 'restores').read_text(), restores + 'iptables\n')
        self.assertEqual(self.clean(repaired), before)

    def test_native_input_anchor_reorder_repositions_only_owned_hook(self):
        self.f.save(keenetic_input_stock())
        self.f.run_helper(family='iptables')
        lines = self.f.read()
        # Simulate a native rebuild moving its own rule above the old hook.
        lines.remove(KEENETIC_INPUT_ACCEPT)
        index = next(i for i,x in enumerate(lines) if x.startswith('-A INPUT '))
        lines.insert(index, KEENETIC_INPUT_ACCEPT)
        self.f.save(lines)
        before = self.clean(lines)
        self.f.run_helper(family='iptables')
        self.assert_input_anchor()
        self.assertIn(REPLY_TAG, self.input_rules()[0])
        self.assertEqual(self.clean(self.f.read()), before)

    def test_unknown_rules_before_known_input_anchor_still_precede_observation(self):
        before = keenetic_input_stock()
        extra = ['-A INPUT -i guest0 -p tcp -j ACCEPT',
                 '-A INPUT -m mark --mark 0x80/0x80 -j DROP',
                 '-A INPUT -j MARK --set-xmark 0x10/0x10']
        index = before.index(KEENETIC_INPUT_ACCEPT)
        before[index:index] = extra
        self.f.save(before)
        self.f.run_helper(family='iptables')
        self.assert_input_anchor()
        self.assertEqual(self.input_rules()[1:4], extra)
        self.assertEqual(self.clean(self.f.read()), before)

    def test_unknown_or_ambiguous_input_accept_is_not_used_as_an_anchor(self):
        variants = [
            [KEENETIC_INPUT_ACCEPT, KEENETIC_INPUT_ACCEPT],
            [KEENETIC_INPUT_ACCEPT.replace('0x20/0x20', '0x20/0xff')],
            [KEENETIC_INPUT_ACCEPT.replace('-j ACCEPT', '-i eth3 -j ACCEPT')],
            [KEENETIC_INPUT_ACCEPT.replace(' -m connndmmark ! --mark 0x20/0x20', '')],
            [KEENETIC_INPUT_ACCEPT.replace('RELATED,ESTABLISHED', 'ESTABLISHED')],
            [KEENETIC_INPUT_ACCEPT.replace('-j ACCEPT', '-j RETURN')],
        ]
        for anchors in variants:
            with self.subTest(anchors=anchors):
                before = keenetic_input_stock()
                index = before.index(KEENETIC_INPUT_ACCEPT)
                before[index:index+1] = anchors
                self.f.save(before)
                self.f.run_helper(family='iptables')
                self.assertIn(REPLY_TAG, self.input_rules()[-1])
                self.assertEqual(self.clean(self.f.read()), before)

    def test_removed_input_anchor_returns_owned_hook_to_conservative_append(self):
        self.f.save(keenetic_input_stock())
        self.f.run_helper(family='iptables')
        lines = self.f.read()
        lines.remove(KEENETIC_INPUT_ACCEPT)
        self.f.save(lines)
        self.f.run_helper(family='iptables')
        self.assertIn(REPLY_TAG, self.input_rules()[-1])
        self.assertEqual(self.clean(self.f.read()), self.clean(lines))
        restores = (self.f.root / 'restores').read_text()
        self.f.run_helper(family='iptables')
        self.assertEqual((self.f.root / 'restores').read_text(), restores)

    def test_lossy_entware_ndm_rendering_never_creates_postnat_rules(self):
        before = [x.replace('connndmmark ! --mark 0x20/0x20',
                            'connndmmark --mark 0x20/0x0') for x in keenetic_input_stock()]
        self.f.save(before)
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())
        self.assertEqual(self.clean(self.f.read()), before)
        self.assertEqual(len(self.f.ours()), 2)

    def test_input_move_failure_keeps_previous_hook_and_all_native_rules(self):
        self.f.save(keenetic_input_stock())
        self.f.run_helper(family='iptables')
        lines = self.f.read()
        hook = next(x for x in self.input_rules() if REPLY_TAG in x)
        lines.remove(hook)
        self.f.save(lines)
        (self.f.root / 'fail-restore').touch()
        self.f.run_helper(family='iptables', expected=1)
        self.assertEqual(self.f.read(), lines)

    def test_known_input_anchor_is_independent_for_each_family(self):
        self.f.save(keenetic_input_stock(), 'ip6tables')
        self.f.run_helper(family='ip6tables')
        self.assert_input_anchor('ip6tables')
        self.assertEqual(self.clean(self.f.read('ip6tables')), keenetic_input_stock())
        self.assertEqual(self.f.read(), stock())

    def test_ndm_pre_post_hooks_are_family_scoped_and_nonfatal(self):
        hooks = ROOT / 'packages/keenetic/keen-pbr/files/opt/etc/ndm/netfilter.d'
        runtime_path = '/opt/usr/lib/keen-pbr/nfqws-tcp-window.sh'
        # The IPK Makefile uses INSTALL_BIN. A source checkout (especially
        # Windows/Docker vs Linux CI) need not expose the same executable bits.
        installed_helper = self.f.bin / 'nfqws-tcp-window.sh'
        shutil.copyfile(LIB / 'nfqws-tcp-window.sh', installed_helper)
        installed_helper.chmod(0o755)
        for name in ('099-keen-pbr-nfqws-tcp.sh', '110-keen-pbr-nfqws-tcp.sh'):
            # Relocate only the fixed installed path in this isolated fixture.
            script = self.f.bin / name
            script.write_text((hooks / name).read_text().replace(runtime_path, str(installed_helper)))
        def event(name, table='mangle'):
            result = subprocess.run(['sh', str(self.f.bin / name)],
                                    env={**self.f.env, 'table': table, 'type': 'iptables'}, timeout=8)
            self.assertEqual(result.returncode, 0)
        self.f.run_helper()
        ipv6 = self.f.read('ip6tables')
        event('099-keen-pbr-nfqws-tcp.sh', 'filter')
        self.assertTrue(self.reply_rules())
        event('099-keen-pbr-nfqws-tcp.sh')
        self.assertEqual(self.f.read(), stock())
        self.assertEqual(self.f.read('ip6tables'), ipv6)
        self.f.save(stock(queue=301, interface='wan4'))
        self.f.argv(reply=True, queue=301)
        self.f.queues(301)
        event('110-keen-pbr-nfqws-tcp.sh')
        self.assertTrue(any('--queue-num 301' in x for x in self.reply_rules()))
        before = self.f.read()
        (self.f.root / 'fail-restore').touch()
        event('099-keen-pbr-nfqws-tcp.sh')
        self.assertEqual(self.f.read(), before)

    def test_remove_restores_exact_vendor_rules_without_process(self):
        before = self.f.read()
        self.f.run_helper()
        (self.f.root / 'opt/var/run/nfqws2.pid').unlink()
        self.f.run_helper('remove')
        self.assertEqual(self.f.read(), before)

    def test_old_profile_rolls_back_only_reply_change_but_keeps_window(self):
        self.f.run_helper()
        self.f.argv(reply=False)
        self.f.run_helper()
        self.assertFalse(self.reply_rules())
        self.assertEqual(len(self.f.ours()), 2)
        self.assertEqual(self.clean(self.f.read()), stock())

    def test_future_policy_side_effect_is_not_cloned_or_bypassed(self):
        self.f.run_helper()
        new = '-A nfqws_pre -i eth3 -j CONNMARK --set-xmark 0x10/0x10'
        lines = self.f.read()
        lines.insert(-1, new)
        self.f.save(lines)
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())
        self.assertIn(new, self.f.read())
        self.assertEqual(len(self.f.ours()), 2)

    def test_address_based_policy_is_not_silently_moved_past_dnat(self):
        lines = stock()
        lines.insert(-1, '-A nfqws_pre -d 198.51.100.1 -j RETURN')
        self.f.save(lines)
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())
        self.assertEqual(self.clean(self.f.read()), lines)

    def test_unknown_control_match_keeps_original_hook(self):
        self.f.save([x.replace('--tcp-flags FIN FIN', '--tcp-flags FIN FIN -m length --length 0:1500') for x in stock()])
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())

    def test_noncanonical_vendor_parent_is_not_suppressed(self):
        self.f.save([x.replace('-A PREROUTING -j nfqws_pre', '-A PREROUTING -i eth3 -j nfqws_pre') for x in stock()])
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())

    def test_chain_name_collision_does_not_claim_foreign_chain(self):
        foreign = [':KpbrNfqTcpReply - [0:0]', '-A KpbrNfqTcpReply -j RETURN']
        self.f.save(stock()[:-1] + foreign + ['COMMIT'])
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())
        self.assertTrue(all(x in self.f.read() for x in foreign))

    def test_foreign_rule_added_to_our_chain_is_not_deleted(self):
        self.f.run_helper()
        foreign = '-A KpbrNfqTcpReply -j RETURN'
        self.f.save(self.f.read()[:-1] + [foreign, 'COMMIT'])
        self.f.run_helper(family='iptables')
        self.assertFalse(self.reply_rules())
        self.assertIn(foreign, self.f.read())
        self.assertIn(':KpbrNfqTcpReply - [0:0]', self.f.read())

    def test_vendor_restart_rebuilds_current_queue_interface_and_policy(self):
        self.f.run_helper()
        remaining = [x for x in self.f.read() if not x.startswith(('-A nfqws_pre ', '-A nfqws_post '))]
        refill = [x for x in stock(limit=32, queue=301, interface='wan4') if x.startswith(('-A nfqws_pre ', '-A nfqws_post '))]
        self.f.save(remaining[:-1] + refill + ['COMMIT'])
        self.f.argv(reply=True, queue=301)
        self.f.queues(301)
        self.f.run_helper(family='iptables')
        queues = [x for x in self.reply_rules() if '-j NFQUEUE' in x]
        self.assertTrue(queues)
        self.assertTrue(all('wan4' in x and '--queue-num 301' in x for x in queues))
        self.assertTrue(any('--connbytes 33:96' in x for x in queues))

    def test_multiple_vendor_interfaces_keep_their_own_matches(self):
        extra = [x for x in stock(interface='wan4') if x.startswith(('-A nfqws_pre ', '-A nfqws_post '))]
        self.f.save(stock()[:-1] + extra + ['COMMIT'])
        self.f.run_helper(family='iptables')
        queues = [x for x in self.reply_rules() if '-j NFQUEUE' in x]
        self.assertEqual(sum('-i eth3 ' in x for x in queues), 5)
        self.assertEqual(sum('-i wan4 ' in x for x in queues), 5)

    def test_restore_failure_is_atomic_and_does_not_disable_vendor(self):
        (self.f.root / 'fail-restore').touch()
        self.f.run_helper(expected=1)
        self.assertEqual(self.f.read(), stock())

    def test_ipv6_uses_same_directional_contract_without_ipv4_mutation(self):
        self.f.run_helper(family='ip6tables')
        self.assertTrue(self.reply_rules('ip6tables'))
        self.assertEqual(self.f.read(), stock())

    def test_vendor_packet_window_above_extension_is_preserved(self):
        self.f.save(stock(limit=128))
        self.f.run_helper(family='iptables')
        self.assertTrue(any('--connbytes 1:128' in x for x in self.reply_rules()))
        self.assertFalse(any('--connbytes 129:' in x for x in self.reply_rules()))

    def test_misplaced_suppression_is_repaired_without_vendor_edits(self):
        self.f.run_helper()
        lines = self.f.read()
        skip = next(x for x in lines if x.startswith('-A nfqws_pre ') and REPLY_TAG in x)
        lines.remove(skip); lines.insert(-1, skip)
        self.f.save(lines)
        self.f.run_helper(family='iptables')
        self.assertEqual(next(x for x in self.f.read() if x.startswith('-A nfqws_pre ')), skip)
        self.assertEqual(self.clean(self.f.read()), stock())


@unittest.skipUnless(os.environ.get('KPBR_NFQWS_NATIVE_TEST') == '1', 'isolated NET_ADMIN container required')
class NativeWindowTest(unittest.TestCase):
    def test_real_iptables_restore_syntax_order_idempotence_and_vendor_restart(self):
        fixture = WindowTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.env['PATH'] = os.environ['PATH']
        subprocess.run(['iptables-restore', '--noflush'],
                       input='\n'.join(stock()) + '\n', text=True, check=True)
        def snapshot():
            return subprocess.check_output(['iptables-save', '-t', 'mangle'], text=True)
        before = snapshot()
        fixture.run_helper(family='iptables')
        after = snapshot()
        self.assertEqual(sum(TAG in x for x in after.splitlines()), 2, after)
        # Ignore generated timestamp comments, but compare every original rule.
        clean = lambda text: [x for x in text.splitlines() if not x.startswith('#') and TAG not in x]
        self.assertEqual(clean(before), clean(after))
        plan = subprocess.check_output(['awk', '-v', 'mode=apply', '-v', 'queue=300',
                                        '-v', 'budget=96', '-f', str(LIB / 'nfqws-tcp-window.awk')],
                                       input=after, text=True)
        self.assertEqual(plan, '', 'real iptables-save must be canonical and idempotent')
        fixture.run_helper('remove', family='iptables')
        self.assertEqual(clean(before), clean(snapshot()))
        self.assertNotIn(TAG, snapshot())
        # Simulate the real upstream firewall stop/start (without replacing
        # any package): its own chain flush discards only the attached rules.
        fixture.run_helper(family='iptables')
        subprocess.run(['iptables', '-t', 'mangle', '-F', 'nfqws_pre'], check=True)
        subprocess.run(['iptables', '-t', 'mangle', '-F', 'nfqws_post'], check=True)
        refill = ['*mangle'] + [x for x in stock() if x.startswith(('-A nfqws_pre ', '-A nfqws_post '))] + ['COMMIT']
        subprocess.run(['iptables-restore', '--noflush'], input='\n'.join(refill) + '\n', text=True, check=True)
        fixture.run_helper(family='iptables')
        self.assertEqual(sum(TAG in x for x in snapshot().splitlines()), 2)

    def test_reply_chain_restore_is_native_atomic_idempotent_and_reversible(self):
        fixture = WindowTest()
        fixture.setUp()
        self.addCleanup(fixture.doCleanups)
        fixture.argv(reply=True)
        fixture.env['PATH'] = os.environ['PATH']
        subprocess.run(['iptables-restore'], input='\n'.join(stock()) + '\n', text=True, check=True)
        snapshot = lambda: subprocess.check_output(['iptables-save', '-t', 'mangle'], text=True)
        before = snapshot()
        fixture.run_helper(family='iptables')
        after = snapshot()
        self.assertIn(REPLY_TAG, after)
        plan = subprocess.check_output(['awk', '-v', 'mode=apply', '-v', 'queue=300',
                                        '-v', 'budget=96', '-v', 'reply=postnat_v1', '-f', str(LIB / 'nfqws-tcp-window.awk')], input=after, text=True)
        self.assertEqual(plan, '', 'real canonical reply chain must be idempotent')
        fixture.run_helper('remove', family='iptables')
        clean = lambda text: [x for x in text.splitlines() if not x.startswith('#')]
        self.assertEqual(clean(before), clean(snapshot()))


if __name__ == '__main__':
    unittest.main()
