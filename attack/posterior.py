"""Exact conditional-Bernoulli posterior over the real subset: P(T) ∝ Π_{s∈T} w(s), fixed count per block."""
import math

NEG_INF = float("-inf")


class Infeasible(ValueError):
    """The attack's constraints admit no real subset of the required size."""


def log_comb(n, k):
    return math.lgamma(n + 1) - math.lgamma(k + 1) - math.lgamma(n - k + 1)


def _logadd(a, b):
    if a == NEG_INF:
        return b
    if b == NEG_INF:
        return a
    if a >= b:
        return a + math.log1p(math.exp(b - a))
    return b + math.log1p(math.exp(a - b))


def _esp_rows(logw, k):
    """rows[i][j] = log e_j(w[0..i-1]), the elementary symmetric polynomials, for j <= k."""
    row = [0.0] + [NEG_INF] * k
    rows = [row]
    for lw in logw:
        row = [0.0] + [_logadd(row[j], lw + row[j - 1]) for j in range(1, k + 1)]
        rows.append(row)
    return rows


class Block:
    """Exactly k of `items` are real; forced items are real with certainty, -inf weight rules one out."""

    def __init__(self, items, logw, k, forced=()):
        self.items = list(items)
        if len(set(self.items)) != len(self.items):
            raise ValueError("duplicate items in block")
        self.logw = dict(zip(self.items, logw))
        self.k = k
        self.forced = frozenset(forced)
        if not self.forced <= self.logw.keys():
            raise ValueError("forced item is not in the block")
        if any(self.logw[s] == NEG_INF for s in self.forced):
            raise Infeasible("an item is both ruled out and certain")
        free = [s for s in self.items if s not in self.forced and self.logw[s] != NEG_INF]
        k_free = k - len(self.forced)
        if not 0 <= k_free <= len(free):
            raise Infeasible(f"{k} reals required; {len(self.forced)} certain, {len(free)} possible")

        self.marginal = dict.fromkeys(self.items, 0.0)
        for s in self.forced:
            self.marginal[s] = 1.0
        lw = [self.logw[s] for s in free]
        if k_free == 0:
            log_e = 0.0
        elif k_free == len(free):
            log_e = math.fsum(lw)
            for s in free:
                self.marginal[s] = 1.0
        elif max(lw) - min(lw) < 1e-12:
            log_e = log_comb(len(free), k_free) + k_free * lw[0]
            for s in free:
                self.marginal[s] = k_free / len(free)
        else:
            log_e = self._solve(free, lw, k_free)
        self.log_evidence = log_e + math.fsum(self.logw[s] for s in self.forced)

    def _solve(self, free, lw, k):
        n = len(free)
        fwd, bwd = _esp_rows(lw, k), _esp_rows(lw[::-1], k)
        log_e = fwd[n][k]
        for i, s in enumerate(free):
            pre, suf = fwd[i], bwd[n - 1 - i]
            loo = NEG_INF
            for j in range(k):
                loo = _logadd(loo, pre[j] + suf[k - 1 - j])
            p = 0.0 if loo == NEG_INF else min(1.0, math.exp(lw[i] + loo - log_e))
            self.marginal[s] = p
        return log_e


class Posterior:
    """Independent blocks, one per first-seen cohort."""

    def __init__(self, blocks):
        self.blocks = list(blocks)
        self.marginal = {}
        for b in self.blocks:
            self.marginal.update(b.marginal)
        self.log_evidence = sum(b.log_evidence for b in self.blocks)


class Mixture:
    """Posteriors mixed over hypotheses h (the wallet's script type), weighted by how well each fits."""

    def __init__(self, components):
        logs = [lp + post.log_evidence for lp, post in components]
        top = max(logs)
        w = [math.exp(x - top) for x in logs]
        z = math.fsum(w)
        self.weights = [x / z for x in w]
        self.posteriors = [post for _, post in components]
        self.marginal = {
            s: math.fsum(wt * p.marginal[s] for wt, p in zip(self.weights, self.posteriors))
            for s in self.posteriors[0].marginal
        }
        self.log_evidence = top + math.log(z)
