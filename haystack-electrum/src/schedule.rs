//! When the next automatic sync happens.
//!
//! The rule: the moment a sync finishes, the delay until the next one is drawn and committed, and
//! nothing the wallet does afterwards moves it. A sync whose timing never depends on wallet events
//! gives a timing attack nothing to correlate.
//!
//! The delay is exponential with mean `mean`, drawn as `-mean · ln(U)` for `U` uniform on (0, 1].
//! Unlike a fixed interval with bounded jitter, it has no deadline: however long it has been since
//! the last sync, the chance of one in the next `t` is `1 − e^(−t/mean)`.
//!
//! A manual sync is a separate, disclosed path and can't move the automatic timer. A failed
//! automatic sync is treated like a finished one — the next attempt is a fresh draw — because a
//! fixed retry interval would be a cadence, and a cadence identifies a wallet across IP changes.

use std::time::{Duration, Instant};

use rand::Rng;

/// Draw one delay from the exponential distribution with mean `mean`.
pub fn exponential_delay(mean: Duration, rng: &mut impl Rng) -> Duration {
    let u = 1.0 - rng.gen::<f64>();
    mean.mul_f64(-u.ln())
}

/// The automatic-sync timer.
#[derive(Debug, Clone)]
pub struct SyncTimer {
    mean: Duration,
    due: Instant,
}

impl SyncTimer {
    /// First sync due one draw after `now`.
    pub fn start(mean: Duration, now: Instant, rng: &mut impl Rng) -> Self {
        Self {
            mean,
            due: now + exponential_delay(mean, rng),
        }
    }

    pub fn due(&self) -> Instant {
        self.due
    }

    pub fn is_due(&self, now: Instant) -> bool {
        now >= self.due
    }

    /// An automatic sync finished, or failed, at `now`: commit to the next one.
    pub fn finished(&mut self, now: Instant, rng: &mut impl Rng) {
        self.due = now + exponential_delay(self.mean, rng);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rand::rngs::StdRng;
    use rand::SeedableRng;

    const MEAN: Duration = Duration::from_secs(30 * 60);
    const N: usize = 200_000;

    fn samples() -> Vec<f64> {
        let mut rng = StdRng::seed_from_u64(7);
        (0..N)
            .map(|_| exponential_delay(MEAN, &mut rng).as_secs_f64() / 60.0)
            .collect()
    }

    fn share(xs: &[f64], keep: impl Fn(f64) -> bool) -> f64 {
        xs.iter().filter(|&&x| keep(x)).count() as f64 / xs.len() as f64
    }

    #[test]
    fn mean_is_the_configured_mean() {
        let mean = samples().iter().sum::<f64>() / N as f64;
        assert!((mean - 30.0).abs() < 0.3, "mean {mean:.2} minutes");
    }

    #[test]
    fn next_five_minutes_carry_the_same_chance_however_long_it_has_been() {
        // 1 − e^(−5/30) = 0.1535, the number in docs/02-design.md.
        let expected = 1.0 - (-5.0f64 / 30.0).exp();
        let xs = samples();
        for waited in [0.0, 1.0, 39.0, 90.0] {
            let still_waiting: Vec<f64> = xs.iter().copied().filter(|&x| x > waited).collect();
            let within_five = share(&still_waiting, |x| x <= waited + 5.0);
            assert!(
                (within_five - expected).abs() < 0.01,
                "after {waited} min: {within_five:.4} vs {expected:.4}"
            );
        }
    }

    #[test]
    fn there_is_no_deadline() {
        // Bounded jitter of 30 ± 10 minutes would never exceed 40; here e^(−5) ≈ 0.67% of delays
        // are longer than five means.
        let beyond = share(&samples(), |x| x > 150.0);
        assert!((beyond - (-5.0f64).exp()).abs() < 0.001, "{beyond:.4}");
    }

    #[test]
    fn only_a_finished_sync_moves_the_timer() {
        let mut rng = StdRng::seed_from_u64(1);
        let t0 = Instant::now();
        let mut timer = SyncTimer::start(MEAN, t0, &mut rng);
        let first = timer.due();
        assert!(first > t0 && !timer.is_due(t0) && timer.is_due(first));
        let done = first + Duration::from_secs(12);
        timer.finished(done, &mut rng);
        assert!(timer.due() > done);
    }
}
