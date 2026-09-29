"""attack/observe.py's reading of haystack-session/1, the log haystack-electrum writes."""
import json
import os
import tempfile
import unittest

from attack.observe import Fact, check_session, load_session, Observation, Round


def query(sh, j=None, tx=0, kind="p2wpkh"):
    return {"sh": sh, "stage": 0, "batch": 0, "kc": "external", "i": 0, "j": j, "tx": tx, "type": kind}


def write(lines):
    fd, path = tempfile.mkstemp(suffix=".jsonl")
    with os.fdopen(fd, "w") as fh:
        for queries in lines:
            fh.write(json.dumps({"format": "haystack-session/1", "started": 0, "padding": 2,
                                 "stop_gap": 1, "batch_size": 2, "error": None,
                                 "queries": queries}) + "\n")
    return path


class LoadSessionTest(unittest.TestCase):
    def test_reals_and_decoys_and_order(self):
        path = write([[query("d0", j=0), query("r"), query("d1", j=1)]])
        obs, truth = load_session(path)
        self.assertEqual(obs.rounds[0].order, ["d0", "r", "d1"])
        self.assertEqual(truth.real(0), {"r"})

    def test_script_type_is_hidden_until_used(self):
        path = write([[query("unused"), query("used", tx=3, kind="p2tr")]])
        facts = load_session(path)[0].rounds[0].facts
        self.assertEqual(facts["unused"], Fact(0, None))
        self.assertEqual(facts["used"], Fact(3, "p2tr"))

    def test_unanswered_query_is_observed_but_has_no_fact(self):
        path = write([[query("lost", tx=None)]])
        rnd = load_session(path)[0].rounds[0]
        self.assertEqual(rnd.order, ["lost"])
        self.assertNotIn("lost", rnd.facts)

    def test_one_round_per_line(self):
        path = write([[query("a")], [query("a"), query("b", j=0)]])
        obs, truth = load_session(path)
        self.assertEqual(len(obs.rounds), 2)
        self.assertEqual(truth.real(1), {"a"})

    def test_rejects_another_format(self):
        fd, path = tempfile.mkstemp()
        with os.fdopen(fd, "w") as fh:
            fh.write(json.dumps({"format": "haystack-capture/1"}) + "\n")
        with self.assertRaises(ValueError):
            load_session(path)

    def test_check_session_notices_a_reordering(self):
        logged = Observation([Round(["a", "b"])])
        self.assertTrue(check_session(logged, Observation([Round(["a", "b"])]))[0]["same_order"])
        swapped = check_session(logged, Observation([Round(["b", "a"])]))[0]
        self.assertEqual((swapped["same_set"], swapped["same_order"]), (True, False))


if __name__ == "__main__":
    unittest.main()
