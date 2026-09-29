import math
import unittest

from attack.calibrate import ceiling, run
from attack.metrics import expected_precision, score
from attack.observe import Round
from attack.posterior import Block, Posterior
from attack.synth import observe, random_pool


def perfect(n_real, padding):
    reals = random_pool(n_real, seed="reals")
    decoys = random_pool(round((padding - 1) * n_real), seed="decoys")
    return run(observe([reals + decoys]), reals)


class CalibrationPointTest(unittest.TestCase):
    def test_plain_electrum_is_zero_everywhere(self):
        reals = random_pool(70, seed="plain")
        s = run(observe([reals, reals, reals]), reals)
        for v in (s.precision_bits, s.joint_bits, s.truth_bits):
            self.assertEqual(v, 0.0)
        self.assertEqual(s.precision, 1.0)

    def test_perfect_scheme_hits_the_analytic_ceiling(self):
        s = perfect(70, 10)
        want = ceiling(70, 10)
        got = [s.precision_bits, 100 * s.precision, 100 * s.chance,
               s.per_real(s.joint_bits), s.per_real(s.truth_bits), s.advantage]
        for g, w in zip(got, want):
            self.assertAlmostEqual(g, w, places=9)

    def test_advantage_cannot_tell_plain_from_perfect(self):
        reals = random_pool(70, seed="plain")
        plain = run(observe([reals]), reals)
        self.assertAlmostEqual(plain.advantage, 0.0)
        self.assertAlmostEqual(perfect(70, 10).advantage, 0.0)

    def test_headline_metrics_rise_with_padding(self):
        scores = [perfect(40, p) for p in (2, 5, 10, 20)]
        for f in (lambda s: s.precision_bits, lambda s: s.per_real(s.joint_bits)):
            vals = [f(s) for s in scores]
            self.assertEqual(vals, sorted(vals))


class WorseThanChanceTest(unittest.TestCase):
    def test_a_wrong_adversary_never_scores_above_guessing(self):
        items = [f"s{i}" for i in range(10)]
        post = Posterior([Block(items, [-5.0] * 2 + [3.0] * 8, 2)])
        s = score(post, Round(items), {"s0", "s1"})
        top = ceiling(2, 5)
        self.assertLess(s.precision, s.chance)
        self.assertAlmostEqual(s.precision_bits, top[0], places=9)
        self.assertLessEqual(s.per_real(s.truth_bits), top[4] + 1e-9)


class PrecisionTest(unittest.TestCase):
    def test_ties_are_broken_in_expectation(self):
        self.assertAlmostEqual(expected_precision({"a": 0.5, "b": 0.5, "c": 0.0}, {"a"}, 1), 0.5)
        self.assertAlmostEqual(expected_precision({"a": 0.9, "b": 0.5, "c": 0.5}, {"a", "c"}, 2), 0.75)
        self.assertAlmostEqual(expected_precision({"a": 1.0, "b": 0.0}, {"b"}, 1), 0.0)


if __name__ == "__main__":
    unittest.main()
