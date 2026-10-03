"""Six real bdk_wallet full scans against the honeypot: plain Electrum gives the attacker everything."""
import os
import unittest

from attack.scoring import per_round
from attack.observe import check_plain, load_capture, load_honeypot

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")


class PlainCaptureTest(unittest.TestCase):
    def setUp(self):
        self.obs = load_honeypot(os.path.join(FIXTURES, "bdk-honeypot-log.json"))
        self.truth = load_capture(os.path.join(FIXTURES, "bdk-capture-truth.json"))

    def test_server_log_equals_the_wallets_own_derivation(self):
        for r in check_plain(self.obs, self.truth):
            self.assertEqual((r["unexpected"], r["missing"]), (0, 0), r)

    def test_reads_zero_bits_in_every_round(self):
        n = min(len(self.obs.rounds), len(self.truth.rounds))
        for s in per_round(self.obs, [self.truth.real(t) for t in range(n)]):
            self.assertEqual(s.precision, 1.0)
            self.assertEqual(s.precision_bits, 0.0)


if __name__ == "__main__":
    unittest.main()
