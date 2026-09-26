"""Known-broken schemes must stay broken under the metric (docs/03-metric.md, 'Guarding against a flattering result')."""
import math
import unittest

from attack.calibrate import per_round
from attack.synth import extend, observe, pad, random_pool

REAL = [random_pool(100, seed="regression")]
POOL = random_pool(100_000)
PADDING = 10
TOP = math.log2(PADDING)


def scores(strategy, rounds, seed):
    real = extend(REAL, rounds)
    return per_round(observe(pad(real, strategy, PADDING, POOL, seed)), real)


class KnownBrokenTest(unittest.TestCase):
    def test_fresh_random_collapses_by_round_three(self):
        for seed in range(5):
            s = scores("fresh", 6, seed)
            self.assertAlmostEqual(s[0].precision_bits, TOP, places=9)
            for later in s[2:]:
                self.assertLessEqual(later.precision_bits, 0.1)
                self.assertLessEqual(later.proxy_bits, 0.1)

    def test_epoch_rotation_collapses_once_a_third_epoch_is_seen(self):
        for seed in range(5):
            s = scores("epoch", 9, seed)
            self.assertAlmostEqual(s[2].precision_bits, TOP, places=9)
            self.assertLessEqual(s[3].precision_bits, 0.25)
            self.assertLessEqual(s[8].precision_bits, 0.1)


class HoldsTest(unittest.TestCase):
    def test_fixed_decoys_stay_at_the_ceiling(self):
        for s in scores("fixed", 6, 0):
            self.assertAlmostEqual(s.precision_bits, TOP, places=9)
            self.assertAlmostEqual(s.proxy_bits, TOP, places=9)


if __name__ == "__main__":
    unittest.main()
