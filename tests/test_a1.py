import unittest

from attack.a1_many_rounds import analyse
from attack.scoring import run
from attack.observe import Fact, Observation, Round


class PersistenceTest(unittest.TestCase):
    def test_first_seen_and_withdrawn(self):
        obs = Observation([Round(["a", "b", "c"]), Round(["a", "b"]), Round(["a", "b", "d", "c"])])
        first, withdrawn, activated = analyse(obs)
        self.assertEqual(first, {"a": 0, "b": 0, "c": 0, "d": 2})
        self.assertEqual(withdrawn, {"c"})
        self.assertEqual(activated, set())

    def test_activation_needs_an_unused_sighting_first(self):
        obs = Observation([
            Round(["a", "b"], {"a": Fact(0), "b": Fact(3, "p2wpkh")}),
            Round(["a", "b"], {"a": Fact(1, "p2wpkh"), "b": Fact(4, "p2wpkh")}),
        ])
        self.assertEqual(analyse(obs)[2], {"a"})


class DeltaCorollaryTest(unittest.TestCase):
    decoys = [f"d{i}" for i in range(18)]

    def test_unpadded_increment_is_exposed(self):
        obs = Observation([Round(["r1"] + self.decoys[:9]), Round(["r1", "r2"] + self.decoys[:9])])
        s = run(obs, {"r1", "r2"})
        # r2 arrived alone, so it is certain; r1 is one of ten.
        self.assertAlmostEqual(s.precision, (1 + 0.1) / 2)

    def test_padded_increment_keeps_its_cohort_ratio(self):
        obs = Observation([Round(["r1"] + self.decoys[:9]), Round(["r1", "r2"] + self.decoys)])
        self.assertAlmostEqual(run(obs, {"r1", "r2"}).precision, 0.1)

    def test_activation_exposes_a_paid_address(self):
        rounds = [Round(["r1"] + self.decoys[:9], {s: Fact(0) for s in ["r1"] + self.decoys[:9]}),
                  Round(["r1"] + self.decoys[:9], {"r1": Fact(1, "p2wpkh"), **{d: Fact(0) for d in self.decoys[:9]}})]
        obs = Observation(rounds)
        self.assertEqual(run(obs, {"r1"}).precision, 1.0)
        self.assertAlmostEqual(run(obs, {"r1"}, activation=False).precision, 0.1)


if __name__ == "__main__":
    unittest.main()
