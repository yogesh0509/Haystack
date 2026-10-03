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
//!
//! A sync that came due while the process couldn't run is skipped, never fired late. A phone that
//! freezes a background app keeps its clock running, so when the app returns the timer is already
//! past due, and firing then would tie the sync to the moment the user looked. Instead the loop
//! notices it woke more than `LATE` after the due time and calls `skip`, which draws a fresh delay
//! from now. Because the delay is memoryless, the time from that moment to the next sync has the
//! same distribution as for a timer that was never frozen, so the skip itself shows nothing. The
//! same rule covers a timer that comes due while a manual sync is still running.
//!
//! The product default is `DEFAULT_MEAN`, 30 minutes. A demo can pass a shorter mean so automatic
//! syncs happen while people watch; that is a presentation setting, not a recommendation.

use std::time::{Duration, Instant};

use rand::Rng;

/// The mean delay between automatic syncs, unless the app chooses another: 48 syncs a day on
/// average, and the balance is 30 minutes old on average (`docs/02-design.md`, "Sync scheduling").
pub const DEFAULT_MEAN: Duration = Duration::from_secs(30 * 60);

/// How late a wake-up may be and still count as on time. Later than this, the process wasn't
/// running when the sync came due, and the sync is skipped rather than fired.
pub const LATE: Duration = Duration::from_secs(5);

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

    /// Whether a wake-up at `now` is too late to fire: the sync came due more than `LATE` ago, so
    /// the process wasn't running then. Call `skip`, not a sync.
    pub fn missed(&self, now: Instant) -> bool {
        now > self.due + LATE
    }

    /// The due sync is not run, because the process was frozen or a sync was already running: draw
    /// a fresh delay from `now`, exactly as after a finished sync.
    pub fn skip(&mut self, now: Instant, rng: &mut impl Rng) {
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
    fn a_late_wake_up_is_missed_and_skipped_from_now() {
        let mut rng = StdRng::seed_from_u64(2);
        let t0 = Instant::now();
        let mut timer = SyncTimer::start(MEAN, t0, &mut rng);
        let due = timer.due();
        assert!(!timer.missed(due) && !timer.missed(due + LATE));
        // Frozen for an hour past the due time: the wake-up is missed, and the next sync is drawn
        // from the moment of waking, not from the old due time.
        let woke = due + Duration::from_secs(3600);
        assert!(timer.missed(woke));
        timer.skip(woke, &mut rng);
        assert!(timer.due() > woke && !timer.missed(woke));
    }

    #[test]
    fn after_a_skip_the_next_five_minutes_carry_the_usual_chance() {
        // The point of skipping: the next sync after the app comes back is as likely within five
        // minutes as in any other five-minute window, 1 − e^(−5/30).
        let expected = 1.0 - (-5.0f64 / 30.0).exp();
        let mut rng = StdRng::seed_from_u64(3);
        let t0 = Instant::now();
        let mut timer = SyncTimer::start(MEAN, t0, &mut rng);
        let woke = t0 + Duration::from_secs(10 * 3600);
        let within = (0..N)
            .filter(|_| {
                timer.skip(woke, &mut rng);
                timer.due() <= woke + Duration::from_secs(5 * 60)
            })
            .count() as f64
            / N as f64;
        assert!((within - expected).abs() < 0.01, "{within:.4} vs {expected:.4}");
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
