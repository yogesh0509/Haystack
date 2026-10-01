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


class FundedPrecisionTest(unittest.TestCase):
    """The regtest worked example of docs/02-design.md: 133 reals, 8 funded, padding 10."""

    def session(self, chain_decoys):
        from attack.observe import Fact
        reals = random_pool(133, seed="reals")
        decoys = random_pool(1197, seed="decoys")
        facts = {s: Fact(1 if i < 8 else 0, "p2wpkh") for i, s in enumerate(reals)}
        facts.update({s: Fact(1 if i < chain_decoys else 0, "p2wpkh") for i, s in enumerate(decoys)})
        return observe([reals + decoys], [facts]), reals

    def test_hmac_only_exposes_every_funded_address_while_the_headline_stays_high(self):
        obs, reals = self.session(chain_decoys=0)
        s = run(obs, reals)
        self.assertEqual((s.funded, s.with_history), (8, 8))
        self.assertEqual(s.funded_precision, 1.0)
        self.assertEqual(s.funded_bits, 0.0)
        self.assertGreater(s.precision_bits, 3.0)

    def test_matched_chain_decoys_put_funded_addresses_at_chance(self):
        obs, reals = self.session(chain_decoys=72)
        s = run(obs, reals)
        self.assertEqual((s.funded, s.with_history), (8, 80))
        self.assertAlmostEqual(s.funded_precision, 0.1)
        self.assertAlmostEqual(s.funded_bits, math.log2(10))

    def test_no_funded_address_means_no_funded_score(self):
        reals = random_pool(70, seed="plain")
        s = run(observe([reals]), reals)
        self.assertIsNone(s.funded_precision)
        self.assertIsNone(s.funded_bits)
