import itertools
import math
import random
import unittest

from attack.posterior import NEG_INF, Block, Infeasible, Mixture, Posterior, log_comb


def brute(items, logw, k, forced):
    weights = {}
    for subset in itertools.combinations(items, k):
        if set(forced) <= set(subset) and all(logw[s] != NEG_INF for s in subset):
            weights[frozenset(subset)] = math.exp(sum(logw[s] for s in subset))
    if not weights:
        return None
    z = sum(weights.values())
    probs = {t: w / z for t, w in weights.items()}
    marginal = {s: sum(p for t, p in probs.items() if s in t) for s in items}
    entropy = -sum(p * math.log(p) for p in probs.values() if p > 0)
    return probs, marginal, entropy, math.log(z)


class BlockTest(unittest.TestCase):
    def test_matches_brute_force(self):
        rng = random.Random(7)
        for _ in range(300):
            n = rng.randint(1, 8)
            k = rng.randint(0, n)
            items = [f"s{i}" for i in range(n)]
            lw = [rng.choice([NEG_INF, 0.0, 1.5, rng.uniform(-6, 6), rng.uniform(-6, 6)]) for _ in items]
            logw = dict(zip(items, lw))
            forced = [s for s in items if logw[s] != NEG_INF and rng.random() < 0.15]
            expected = brute(items, logw, k, forced)
            if expected is None:
                with self.assertRaises(Infeasible):
                    Block(items, lw, k, forced)
                continue
            probs, marginal, entropy, log_z = expected
            b = Block(items, lw, k, forced)
            for s in items:
                self.assertAlmostEqual(b.marginal[s], marginal[s], places=9)
            self.assertAlmostEqual(b.entropy_nats, entropy, places=9)
            self.assertAlmostEqual(b.log_evidence, log_z, places=9)
            for subset, p in probs.items():
                self.assertAlmostEqual(b.log_prob(subset), math.log(p), places=9)

    def test_dp_agrees_with_closed_form_at_scale(self):
        n, k = 400, 40
        items = [f"s{i}" for i in range(n)]
        uniform = Block(items, [0.3] * n, k)
        perturbed = Block(items, [0.3 + 1e-9 * (i % 2) for i in range(n)], k)
        self.assertAlmostEqual(uniform.entropy_nats, log_comb(n, k), places=9)
        self.assertAlmostEqual(perturbed.entropy_nats, uniform.entropy_nats, places=5)
        for s in items[:5]:
            self.assertAlmostEqual(perturbed.marginal[s], k / n, places=6)

    def test_all_real_and_none_real(self):
        self.assertEqual(Block(["a", "b"], [0.0, 2.0], 2).marginal, {"a": 1.0, "b": 1.0})
        self.assertEqual(Block(["a", "b"], [0.0, 2.0], 0).marginal, {"a": 0.0, "b": 0.0})

    def test_forced_and_ruled_out_is_infeasible(self):
        with self.assertRaises(Infeasible):
            Block(["a", "b"], [NEG_INF, 0.0], 1, forced=["a"])


class PosteriorTest(unittest.TestCase):
    def test_blocks_compose_independently(self):
        b1 = Block(["a", "b", "c"], [0.0, 1.0, -1.0], 1)
        b2 = Block(["d", "e"], [0.5, 0.5], 1)
        post = Posterior([b1, b2])
        truth = {"b", "d"}
        self.assertAlmostEqual(post.log2_prob(truth) * math.log(2),
                               b1.log_prob(truth) + b2.log_prob(truth), places=12)
        self.assertAlmostEqual(post.entropy_bits * math.log(2), b1.entropy_nats + b2.entropy_nats, places=12)
        self.assertEqual(post.log2_prob({"b", "z"}), NEG_INF)

    def test_mixture_weights_bounds_and_truth(self):
        items = ["a", "b", "c", "d"]
        p1 = Posterior([Block(items, [2.0, 0.0, 0.0, 0.0], 2)])
        p2 = Posterior([Block(items, [0.0, 0.0, 0.0, 2.0], 2)])
        mix = Mixture([(math.log(0.7), p1), (math.log(0.3), p2)])
        self.assertAlmostEqual(sum(mix.weights), 1.0, places=12)
        self.assertLessEqual(mix.entropy_bits, mix.entropy_upper_bits)
        truth = {"a", "b"}
        manual = sum(w * 2 ** p.log2_prob(truth) for w, p in zip(mix.weights, mix.posteriors))
        self.assertAlmostEqual(2 ** mix.log2_prob(truth), manual, places=12)
        for s in items:
            self.assertAlmostEqual(mix.marginal[s], sum(w * p.marginal[s] for w, p in
                                                        zip(mix.weights, mix.posteriors)), places=12)


if __name__ == "__main__":
    unittest.main()
