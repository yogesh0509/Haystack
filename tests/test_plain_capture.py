"""Six real bdk_wallet full scans against the honeypot: plain Electrum gives the attacker everything."""
import os
import unittest

from attack.scoring import attack, knowledge, per_round, view
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

    def test_view_marks_every_scripthash_real_and_certain(self):
        # The demo's grid for a plain sync: every square is the wallet's, and the attacker is sure.
        last, real = self.obs.upto(0), self.truth.real(0)
        rows = view(attack(last, knowledge(last, real)), last.rounds[-1], real)
        self.assertEqual(len(rows), len(last.rounds[-1].order))
        self.assertTrue(all(p == 1.0 and is_real == 1 for p, is_real, _ in rows))


if __name__ == "__main__":
    unittest.main()
