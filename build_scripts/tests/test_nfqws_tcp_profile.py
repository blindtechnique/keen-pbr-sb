"""General TCP observation must not be filtered down to ClientHello only."""
from __future__ import annotations

import re
import runpy
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


class TcpProfileTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.gen = runpy.run_path(str(ROOT / 'build_scripts/build-nfqws-strategies.py'))
        cls.parse = staticmethod(runpy.run_path(str(ROOT / 'build_scripts/check-nfqws-assets.py'))['parse_shell_assignments'])

    def values(self, profile):
        text, required = self.gen['build'](profile, self.gen['PROFILES'][profile])
        return self.parse(text), required

    def test_general_observes_replies_empty_rst_and_data_retries_before_actions(self):
        for profile in self.gen['PROFILES']:
            tokens = self.values(profile)[0]['NFQWS_ARGS'].split()
            pos = next(i for i, t in enumerate(tokens) if t.startswith('--lua-desync=circular:'))
            observation = next(t for t in tokens[:pos] if t.startswith('--payload=')).split('=', 1)[1].split(',')
            self.assertTrue({'tls_client_hello', 'tls_server_hello', 'unknown', 'empty', 'mtproto_initial'} <= set(observation), profile)
            self.assertNotIn('http_req', observation, profile)
            self.assertIn('--in-range=-s27460', tokens[:pos], profile)
            self.assertIn('--out-range=-s66996', tokens[:pos], profile)
            self.assertIn(':inseq=26000:', tokens[pos], profile)
            self.assertIn(':retrans=2:', tokens[pos], profile)
            self.assertNotIn(':reset=', tokens[pos], profile)
            self.assertEqual(tokens[pos+1:pos+3], ['--in-range=x', '--payload=tls_client_hello,mtproto_initial'], profile)

    def test_http_is_outside_circular_and_keeps_unbounded_original_action_window(self):
        for profile in self.gen['PROFILES']:
            tokens = self.values(profile)[0]['NFQWS_ARGS'].split()
            pos = tokens.index('--payload=http_req')
            self.assertEqual(tokens[pos-1], '--out-range=a')
            self.assertEqual(tokens[-1], '--lua-desync=http_methodeol:badsum')
            actions = tokens[pos+1:]
            self.assertFalse(any(':strategy=' in t for t in actions))
            self.assertEqual(len(actions), 2 if profile == '03 max' else 1)

    def test_autohostlist_observes_late_tcp_stalls_before_strategy_selection(self):
        for profile in ('02 balanced', '03 max'):
            values = self.values(profile)[0]
            tokens = values['NFQWS_ARGS'].split()
            circular = next(t for t in tokens if t.startswith('--lua-desync=circular:'))
            incoming = int(re.search(r':inseq=(\d+)', circular)[1])
            outgoing = int(re.search(r':maxseq=(\d+)', circular)[1])
            self.assertEqual(incoming, 26000)
            self.assertEqual(outgoing, 65536)
            self.assertIn(f'--hostlist-auto-incoming-maxseq={incoming}', tokens)
            self.assertIn(f'--hostlist-auto-retrans-maxseq={outgoing}', tokens)
            # These are C-engine profile options, not Lua arguments. The
            # engine must see them even before a host qualifies for circular.
            self.assertNotIn('hostlist-auto', circular)

    def test_late_auto_detection_is_tcp_only_and_does_not_force_bypass(self):
        for profile in self.gen['PROFILES']:
            values = self.values(profile)[0]
            for name, value in values.items():
                if name != 'NFQWS_ARGS' or profile == '01 safe':
                    self.assertNotIn('--hostlist-auto-incoming-maxseq', value, (profile, name))
                    self.assertNotIn('--hostlist-auto-retrans-maxseq', value, (profile, name))
                self.assertNotIn('--hostlist-auto-retrans-reset', value)
                self.assertNotIn('--hostlist-auto-fail-threshold', value)
                self.assertNotIn('--hostlist-auto-fail-time', value)
                self.assertNotIn('pvvstream', value)
            self.assertEqual(values['NFQWS_EXTRA_ARGS'], '$MODE_AUTO')
            self.assertTrue(values['MODE_AUTO'].startswith('$MODE_LIST '))
            self.assertIn('--hostlist-exclude=', values['MODE_LIST'])
            self.assertNotIn('--hostlist-auto', values['MODE_LIST'])
            self.assertNotIn('--hostlist-auto', values['MODE_ALL'])

    def test_ip_selected_mtproto_observes_both_directions_without_a_host_requirement(self):
        for profile in self.gen['PROFILES']:
            custom = self.values(profile)[0]['NFQWS_ARGS_CUSTOM']
            block = re.split(r'--new(?:=[^\s]+)?\s+', custom)[-1].split()
            pos = next(i for i, t in enumerate(block) if t.startswith('--lua-desync=circular:'))
            self.assertIn('--payload=all', block[:pos])
            self.assertIn('--in-range=-s27460', block[:pos])
            self.assertIn('--out-range=-s66996', block[:pos])
            self.assertNotIn('--hostlist', ' '.join(block))
            self.assertEqual(block[pos+1:pos+3], ['--in-range=x', '--payload=mtproto_initial'])

    def test_syn_only_action_is_reachable_only_as_max_slot_12_and_bounded(self):
        text, required = self.gen['build']('03 max', self.gen['PROFILES']['03 max'])
        self.assertIn('syn_packet.bin', required)
        values = self.parse(text)
        self.assertIn('--ipcache-hostname', values['NFQWS_BASE_ARGS'].split())
        tokens = values['NFQWS_ARGS'].split()
        self.assertIn('--filter-l7=unknown,http,tls,mtproto', tokens)
        circular = next(t for t in tokens if t.startswith('--lua-desync=circular:'))
        self.assertIn(':failure_detector=keen_pbr_syn_failure_detector', circular)
        self.assertIn(':hostkey=keen_pbr_tcp_endpoint', circular)
        syn = '--lua-desync=keen_pbr_syndata:blob=syn_data:optional:strategy=12'
        pos = tokens.index(syn)
        self.assertEqual(tokens[pos-2:pos], ['--payload=empty', '--out-range=-n1'])
        self.assertEqual(tokens[pos+1:pos+3], ['--out-range=-s66996', '--payload=tls_client_hello,mtproto_initial'])
        last = [t for t in tokens if t.endswith(':strategy=12')]
        self.assertEqual(last, [syn, '--lua-desync=multisplit:pos=1,sld+1,endsld-2:seqovl=1:strategy=12'])
        self.assertNotIn('syndata', values['NFQWS_ARGS_CUSTOM'])
        for profile in ('01 safe', '02 balanced'):
            other = self.values(profile)[0]
            self.assertNotIn('--ipcache-hostname', other['NFQWS_BASE_ARGS'])
            self.assertNotIn('syndata', other['NFQWS_ARGS'])
            self.assertNotIn('keen_pbr_syndata', other['NFQWS_ARGS'])
            self.assertNotIn('keen_pbr_syn_failure_detector', other['NFQWS_ARGS'])

    def test_tcp_revisions_invalidate_old_unconfirmed_success_but_quic_is_unchanged(self):
        expected = {
            'gv_tcp': '3d44fb947f2c3e68', 'yt_tcp': '980cd30b4955075e',
            'yt_quic': '91b4ca6d3577b68d', 'discord_tcp_exp': '36eac54ab3a123bd',
            'discord_media_tcp_exp': 'e36dc1043f95a89c', 'discord_udp_exp': 'f91ba7ce218c3974',
        }
        for profile in ('02 balanced', '03 max'):
            custom = self.values(profile)[0]['NFQWS_ARGS_CUSTOM']
            found = dict(re.findall(r':key=([^:\s]+):kpbr_rev=([a-f0-9]+)', custom))
            selected = {k: v for k, v in expected.items() if profile == '03 max' or not k.startswith('discord_')}
            self.assertEqual(found.keys(), selected.keys())
            for key, previous in selected.items():
                if 'tcp' in key:
                    self.assertNotEqual(found[key], previous, key)
                else:
                    self.assertEqual(found[key], previous, key)

    def test_tcp_success_is_confirmed_and_window_capability_is_explicit(self):
        for profile in self.gen['PROFILES']:
            values = self.values(profile)[0]
            self.assertIn(':success_detector=keen_pbr_tcp_success_detector', values['NFQWS_ARGS'])
            self.assertEqual(':kpbr_tcp_window=96' in values['NFQWS_ARGS'], profile != '01 safe')
            self.assertEqual(':kpbr_tcp_reply=postnat_v1' in values['NFQWS_ARGS'], profile != '01 safe')
            self.assertNotIn('kpbr_tcp_window', values['NFQWS_ARGS_QUIC'])
            self.assertNotIn('kpbr_tcp_window', values['NFQWS_ARGS_UDP'])
            self.assertNotIn('kpbr_tcp_reply', values['NFQWS_ARGS_QUIC'])
            self.assertNotIn('kpbr_tcp_reply', values['NFQWS_ARGS_UDP'])

    def test_builtin_actions_do_not_rely_on_ignored_nfqwsv1_arguments(self):
        # Build-time check for our three generated presets only. Never reject
        # user Lua functions or stop a live service based on this small list.
        ignored = {'badseq', 'badseq_increment', 'repeat', 'tcp_ttl'}
        for profile in self.gen['PROFILES']:
            for value in self.values(profile)[0].values():
                for token in value.split():
                    if token.startswith('--lua-desync='):
                        keys = {item.split('=', 1)[0] for item in token.split(':')[1:]}
                        self.assertFalse(keys & ignored, (profile, token))

    def test_migrated_fake_candidates_use_native_sequence_and_ack_offsets(self):
        candidates = [self.gen['TCP_TIERS'][i][0] for i in (8, 9)]
        candidates += [self.gen['YT_TCP_TIERS'][i][0] for i in (2, 3)]
        for action in candidates:
            self.assertTrue(action.startswith('fake:'), action)
            self.assertIn(':tcp_seq=-10000:', action)
            self.assertIn(':tcp_ack=-66000:', action)
            self.assertIn('badsum', action.split(':'))
        # Changing a persisted YouTube candidate must invalidate its learned
        # slot; unrelated Googlevideo and QUIC pools retain their revisions.
        for profile in ('02 balanced', '03 max'):
            custom = self.values(profile)[0]['NFQWS_ARGS_CUSTOM']
            revisions = dict(re.findall(r':key=([^:\s]+):kpbr_rev=([a-f0-9]+)', custom))
            self.assertNotEqual(revisions['yt_tcp'], '161bbe1332063a42')
            self.assertEqual(revisions['gv_tcp'], '4b9e6ce0a92975fd')
            self.assertEqual(revisions['yt_quic'], '91b4ca6d3577b68d')

    def test_standalone_fakes_preserve_keenetic_tls_without_valid_stream_injection(self):
        # The real Keenetic probe repeatedly failed TLS with negative seq/ack;
        # +10000 with badsum delivered the complete CSS. A positive offset
        # WITHOUT this checksum guard is valid out-of-order data: do not
        # regress to the old unguarded fake, or mistake autottl for a guard.
        for slot in (0, 4, 6):
            action = self.gen['TCP_TIERS'][slot][0]
            fields = dict(item.split('=', 1) for item in action.split(':')[1:] if '=' in item)
            self.assertEqual(fields.get('tcp_seq'), '10000', (slot + 1, action))
            self.assertNotIn('tcp_ack', fields, (slot + 1, action))
            self.assertIn('badsum', action.split(':'), (slot + 1, action))
        self.assertIn(':ip_autottl=1,3-12', self.gen['TCP_TIERS'][4][0])
        # The Discord experiment reuses the first general candidate. It must
        # inherit the checksum guard, not keep an unsafe positive offset.
        self.assertEqual(self.gen['DISCORD_EXPERIMENT_TCP_TIERS'][0], self.gen['TCP_TIERS'][0])


if __name__ == '__main__':
    unittest.main()
