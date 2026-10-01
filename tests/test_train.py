"""Option B's safeguards (docs/04-roadmap.md, Week 3): provenance and no training on the answer."""
import json
import tempfile
import unittest
from pathlib import Path

from attack.train import TrainingRefused, fit, session_clients

CLIENT = {"name": "haystack-electrum", "version": "0.1.0", "source": "a" * 32}


def write(folder, name, reals, decoys, client=CLIENT, funded=(), chain_share=None):
    queries = [{"sh": s, "stage": 0, "batch": 0, "kc": "external", "i": i, "j": None,
                "tx": 1 if s in funded else 0, "type": "p2wpkh"} for i, s in enumerate(reals)]
    queries += [{"sh": s, "stage": 0, "batch": 0, "kc": "external", "i": 0, "j": j,
                 "tx": 0, "type": "p2wpkh"} for j, s in enumerate(decoys)]
    line = {"format": "haystack-session/1", "started": 0, "padding": 2, "stop_gap": 2,
            "batch_size": 10, "error": None, "queries": queries}
    if client is not None:
        line["client"] = client
    if chain_share is not None:
        line["chain_share"] = chain_share
    path = Path(folder) / f"{name}.jsonl"
    path.write_text(json.dumps(line) + "\n")
    return path


class SafeguardTest(unittest.TestCase):
    def setUp(self):
        self.dir = tempfile.TemporaryDirectory()
        self.scored = write(self.dir.name, "scored", ["r1", "r2"], ["d1", "d2"], funded={"r1"})

    def tearDown(self):
        self.dir.cleanup()

    def test_fits_on_sessions_from_the_same_client(self):
        train = write(self.dir.name, "other", ["x1", "x2"], ["y1", "y2"], funded={"x1"})
        model, n = fit(self.scored, [train])
        self.assertEqual(n, 1)
        self.assertEqual(sum(model.act[True].values()), 2)

    def test_refuses_a_different_client(self):
        other = dict(CLIENT, source="b" * 32)
        train = write(self.dir.name, "other", ["x1"], ["y1"], client=other)
        with self.assertRaisesRegex(TrainingRefused, "came from client"):
            fit(self.scored, [train])

    def test_refuses_a_session_without_provenance(self):
        train = write(self.dir.name, "old", ["x1"], ["y1"], client=None)
        self.assertEqual(session_clients(train), {None})
        with self.assertRaisesRegex(TrainingRefused, "came from client"):
            fit(self.scored, [train])

    def test_refuses_training_on_the_answer(self):
        train = write(self.dir.name, "leaky", ["x1", "r2"], ["y1"])
        with self.assertRaisesRegex(TrainingRefused, "real scripthashes as reals"):
            fit(self.scored, [train])

    def test_a_scored_real_may_be_someone_elses_decoy(self):
        # Chain-sourced decoys are other people's addresses, the scored wallet's included.
        train = write(self.dir.name, "neighbour", ["x1"], ["r1", "y1"])
        model, n = fit(self.scored, [train])
        self.assertEqual(n, 1)

    def test_refuses_another_chain_share(self):
        train = write(self.dir.name, "other", ["x1"], ["y1"], chain_share=0.3)
        with self.assertRaisesRegex(TrainingRefused, "recorded at"):
            fit(self.scored, [train])

    def test_the_scored_session_is_never_its_own_training_set(self):
        with self.assertRaisesRegex(TrainingRefused, "no training sessions"):
            fit(self.scored, [self.scored])
