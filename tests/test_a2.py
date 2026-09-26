import unittest

from attack.a2 import StructuralModel
from attack.calibrate import run
from attack.synth import world

PADDING = 10


def mean_precision(kind, order, tier, seeds=4):
    model = StructuralModel().fit(
        (obs.rounds[0], r) for obs, r in (world(10_000 + i, kind, PADDING, order) for i in range(30)))
    return sum(run(*world(s, kind, PADDING, order), tier=tier, model=model).precision
               for s in range(seeds)) / seeds


class StructuralTest(unittest.TestCase):
    def test_careless_chain_decoys_fall_to_a2_not_a1(self):
        self.assertAlmostEqual(mean_precision("chain", "shuffle", "T1"), 1 / PADDING, places=2)
        self.assertGreater(mean_precision("chain", "shuffle", "T2"), 0.6)

    def test_same_shape_decoy_wallets_leave_a2_near_chance(self):
        self.assertLess(mean_precision("wallets", "shuffle", "T2"), 0.2)

    def test_reals_first_order_leaks_even_with_perfect_decoys(self):
        self.assertGreater(mean_precision("wallets", "reals-first", "T2"), 0.5)


if __name__ == "__main__":
    unittest.main()
