import unittest
from unittest.mock import Mock, patch

from build_scripts.tests.nfqws_tcp_reply_native import retry_budget, verify_observation_count, wait_for_fin_ack


class PacketCountTest(unittest.TestCase):
    def test_one_observation_per_connection(self):
        verify_observation_count(3, 3, 0, 'hello')
        verify_observation_count(0, 0, 0, 'excluded')

    def test_kernel_evidence_allows_a_real_retry(self):
        verify_observation_count(4, 3, 1, 'hello')

    def test_missing_or_unproven_extra_observation_fails(self):
        for observed, connections, retries in ((2, 3, 0), (4, 3, 0), (5, 3, 1)):
            with self.subTest(observed=observed), self.assertRaises(AssertionError):
                verify_observation_count(observed, connections, retries, 'reply')

    def test_retry_budget_requires_every_socket(self):
        self.assertEqual(retry_budget('TCP_RETRANSMISSIONS=1\nTCP_RETRANSMISSIONS=0\n', 2), 1)
        for output in ('', 'TCP_RETRANSMISSIONS=0\n', 'TCP_RETRANSMISSIONS=-1\nTCP_RETRANSMISSIONS=0\n'):
            with self.subTest(output=output), self.assertRaises(AssertionError):
                retry_budget(output, 2)

    def test_fin_measurement_waits_for_ack(self):
        conn = Mock()
        conn.getsockopt.side_effect = [bytes([9]), bytes([7])]
        with patch('build_scripts.tests.nfqws_tcp_reply_native.time.sleep'):
            wait_for_fin_ack(conn)
        self.assertEqual(conn.getsockopt.call_count, 2)

    def test_unacknowledged_fin_is_not_silently_accepted(self):
        conn = Mock()
        conn.getsockopt.return_value = bytes([9])
        with patch('build_scripts.tests.nfqws_tcp_reply_native.time.monotonic', side_effect=[0, 3]):
            with self.assertRaises(RuntimeError):
                wait_for_fin_ack(conn)


if __name__ == '__main__':
    unittest.main()
