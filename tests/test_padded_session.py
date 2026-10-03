"""The first score on real padded traffic: six haystack-electrum scans at padding 10, against the honeypot.

The three fixtures come from one run of `capture/ --padding 10 --session …` against
`scripts/honeypot_electrum.py`, the same pipeline and demo wallet as the plain capture fixtures:
what the server received, what the wallet's own `inspect` callback saw it send, and the client's
session log. The honeypot answers "nothing found" to everything, so this wallet is never paid: the
session exercises the many-rounds attack, not activation or the structural attack.
"""
import json
import math
import os
import unittest

from attack.scoring import per_round
from attack.observe import check_plain, check_session, load_capture, load_honeypot, load_session

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
LOG = os.path.join(FIXTURES, "haystack-honeypot-log.json")
TRUTH = os.path.join(FIXTURES, "haystack-capture-truth.json")
SESSION = os.path.join(FIXTURES, "haystack-session.jsonl")


class PaddedSessionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.obs, cls.truth = load_honeypot(LOG), load_capture(TRUTH)
        with open(TRUTH) as fh:
            cls.decoys = [frozenset(r["decoys"]) for r in json.load(fh)["rounds"]]

    def test_server_received_exactly_the_reals_and_the_ledgers_decoys(self):
        self.assertEqual(len(self.obs.rounds), 6)
        for t, r in enumerate(check_plain(self.obs, self.truth)):
            self.assertEqual((r["server"], r["wallet"], r["missing"]), (1000, 100, 0), f"round {t}")
            self.assertEqual(
                self.obs.rounds[t].members, self.truth.real(t) | self.decoys[t], f"round {t}"
            )

    def test_every_round_sends_the_same_set(self):
        first = self.obs.rounds[0].members
        self.assertTrue(all(r.members == first for r in self.obs.rounds))

    def test_session_log_matches_the_server_and_the_wallet(self):
        session, session_truth = load_session(SESSION)
        for r in check_session(session, self.obs):
            self.assertTrue(r["same_order"], r)
        for t in range(6):
            self.assertEqual(session_truth.real(t), self.truth.real(t), f"round {t}")
            self.assertEqual(session.rounds[t].members - session_truth.real(t), self.decoys[t])
            # Every answer arrived and every one is empty, so no script type is visible.
            self.assertEqual(len(session.rounds[t].facts), 1000)
            self.assertTrue(all(f == (0, None) for f in map(tuple_fact, session.rounds[t].facts.values())))

    def test_many_rounds_attack_learns_nothing(self):
        real = [self.truth.real(t) for t in range(6)]
        for tier in ("T0", "T1"):
            for t, s in enumerate(per_round(self.obs, real, tier)):
                self.assertAlmostEqual(s.precision_bits, math.log2(10), places=9, msg=f"{tier} {t}")


def tuple_fact(f):
    return (f.tx_count, f.script_type)


if __name__ == "__main__":
    unittest.main()
