"""The first score on real padded traffic: six haystack-electrum scans at padding 10, against the honeypot.

The two fixtures are six padded syncs of the public-seed demo wallet against
`scripts/honeypot_electrum.py`: what the server received, and the client's own session log. The test
checks the two against each other, which is the same cross-check `score --session --honeypot` runs.
The honeypot answers "nothing found" to everything, so this wallet is never paid: the session
exercises the many-rounds attack, not activation or the structural attack.
"""
import contextlib
import io
import json
import math
import os
import unittest

from attack.__main__ import main
from attack.scoring import per_round
from attack.observe import check_plain, check_session, load_honeypot, load_session

FIXTURES = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures")
LOG = os.path.join(FIXTURES, "haystack-honeypot-log.json")
SESSION = os.path.join(FIXTURES, "haystack-session.jsonl")


class PaddedSessionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.obs = load_honeypot(LOG)
        cls.session, cls.truth = load_session(SESSION)
        cls.decoys = [r.members - cls.truth.real(t) for t, r in enumerate(cls.session.rounds)]

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
        for r in check_session(self.session, self.obs):
            self.assertTrue(r["same_order"], r)
        for t in range(6):
            self.assertEqual(len(self.truth.real(t)), 100, f"round {t}")
            self.assertEqual(len(self.decoys[t]), 900, f"round {t}")
            # Every answer arrived and every one is empty, so no script type is visible.
            self.assertEqual(len(self.session.rounds[t].facts), 1000)
            self.assertTrue(
                all(f == (0, None) for f in map(tuple_fact, self.session.rounds[t].facts.values()))
            )

    def test_many_rounds_attack_learns_nothing(self):
        real = [self.truth.real(t) for t in range(6)]
        for tier in ("T0", "T1"):
            for t, s in enumerate(per_round(self.obs, real, tier)):
                self.assertAlmostEqual(s.precision_bits, math.log2(10), places=9, msg=f"{tier} {t}")

    def test_view_is_the_last_round_in_arrival_order(self):
        # What the demo's grid draws: `score --last --json --view` on the client's own session log.
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.assertEqual(main(["score", "--session", SESSION, "--last", "--json", "--view"]), 0)
        line = json.loads(out.getvalue().splitlines()[-1])
        session, session_truth = load_session(SESSION)
        rows = line["view"]
        self.assertEqual(len(rows), line["n_query"])
        self.assertEqual(len(rows), len(session.rounds[-1].order))
        # Real flags follow the arrival order, and nobody is told more than chance: 100 of 1000.
        self.assertEqual([r[1] for r in rows],
                         [int(s in session_truth.real(5)) for s in session.rounds[-1].order])
        self.assertAlmostEqual(sum(r[0] for r in rows), line["n_real"], places=6)
        self.assertTrue(all(r[0] == 0.1 and r[2] == 0 for r in rows))

    def test_view_needs_last_and_json(self):
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            main(["score", "--session", SESSION, "--json", "--view"])


def tuple_fact(f):
    return (f.tx_count, f.script_type)


if __name__ == "__main__":
    unittest.main()
