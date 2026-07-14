// SPDX-License-Identifier: Apache-2.0
// Small, dependency-free statistics for the gate. Deterministic: the
// permutation test uses a fixed-seed PRNG so a given input always yields the
// same p-value (a gate must be reproducible).

/// SplitMix64: tiny, fast, good enough for shuffling. Seeded for determinism.
pub struct SplitMix64 {
    state: u64,
}

impl SplitMix64 {
    pub fn new(seed: u64) -> Self {
        SplitMix64 { state: seed }
    }
    pub fn next_u64(&mut self) -> u64 {
        self.state = self.state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = self.state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^ (z >> 31)
    }
    /// Uniform in [0, n).
    fn below(&mut self, n: usize) -> usize {
        (self.next_u64() % (n as u64)) as usize
    }
}

pub fn mean(xs: &[f64]) -> f64 {
    if xs.is_empty() {
        return 0.0;
    }
    xs.iter().sum::<f64>() / xs.len() as f64
}

/// Sample variance (n-1). Returns 0 for fewer than two points.
pub fn variance(xs: &[f64]) -> f64 {
    let n = xs.len();
    if n < 2 {
        return 0.0;
    }
    let m = mean(xs);
    let ss: f64 = xs.iter().map(|x| (x - m) * (x - m)).sum();
    ss / (n as f64 - 1.0)
}

pub fn stddev(xs: &[f64]) -> f64 {
    variance(xs).sqrt()
}

/// Coefficient of variation of a single group. 0 if mean is 0.
pub fn cov(xs: &[f64]) -> f64 {
    let m = mean(xs);
    if m == 0.0 {
        return 0.0;
    }
    stddev(xs) / m.abs()
}

/// Noise estimate for an A/B comparison: the larger of the two within-group
/// CoVs. Deliberately NOT the pooled CoV: pooling A and B folds the real
/// between-group effect into the spread, so a genuine regression would masquerade
/// as noise. Within-group CoV measures measurement noise only.
pub fn within_cov(a: &[f64], b: &[f64]) -> f64 {
    cov(a).max(cov(b))
}

/// Two-sided permutation test on difference of means. Returns a p-value with
/// add-one smoothing so it is never exactly 0. Deterministic given `seed`.
pub fn permutation_p(a: &[f64], b: &[f64], resamples: usize, seed: u64) -> f64 {
    let na = a.len();
    let mut pool: Vec<f64> = Vec::with_capacity(na + b.len());
    pool.extend_from_slice(a);
    pool.extend_from_slice(b);
    let n = pool.len();
    if na == 0 || b.is_empty() {
        return 1.0;
    }
    let observed = (mean(b) - mean(a)).abs();
    // A tiny epsilon guards floating equality when values are identical.
    let eps = 1e-12;

    let mut rng = SplitMix64::new(seed);
    let mut count = 0usize;
    for _ in 0..resamples {
        // Fisher-Yates shuffle.
        for i in (1..n).rev() {
            let j = rng.below(i + 1);
            pool.swap(i, j);
        }
        let ma = mean(&pool[..na]);
        let mb = mean(&pool[na..]);
        if (mb - ma).abs() + eps >= observed {
            count += 1;
        }
    }
    (count as f64 + 1.0) / (resamples as f64 + 1.0)
}

/// Percentile estimate from a log2 histogram. Bucket i covers [2^i, 2^(i+1));
/// the estimate returns the bucket midpoint (1.5 * 2^i).
pub fn log2_percentile(buckets: &[u64], q: f64) -> f64 {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = q * total as f64;
    let mut cum = 0u64;
    for (i, &b) in buckets.iter().enumerate() {
        cum += b;
        if cum as f64 >= target {
            return 1.5 * (1u64 << i) as f64;
        }
    }
    let last = buckets.len().saturating_sub(1);
    1.5 * (1u64 << last) as f64
}

/// Mean estimate from a log2 histogram (bucket midpoints).
pub fn log2_mean(buckets: &[u64]) -> f64 {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let mut acc = 0.0;
    for (i, &b) in buckets.iter().enumerate() {
        acc += b as f64 * 1.5 * (1u64 << i) as f64;
    }
    acc / total as f64
}

/// Percentile from an explicit-bounds histogram. `bounds` are upper edges;
/// there is one more bucket than bounds (the overflow bucket). Midpoint est.
pub fn explicit_percentile(buckets: &[u64], bounds: &[f64], q: f64) -> f64 {
    let total: u64 = buckets.iter().sum();
    if total == 0 {
        return 0.0;
    }
    let target = q * total as f64;
    let mut cum = 0u64;
    for (i, &b) in buckets.iter().enumerate() {
        cum += b;
        if cum as f64 >= target {
            let lo = if i == 0 { 0.0 } else { bounds[i - 1] };
            let hi = if i < bounds.len() { bounds[i] } else { lo * 2.0 };
            return (lo + hi) / 2.0;
        }
    }
    *bounds.last().unwrap_or(&0.0)
}

/// Ordinary least squares slope and its standard error, for a y-series indexed
/// by 0..n. Used to detect drift trends.
pub fn linreg_slope_stderr(ys: &[f64]) -> (f64, f64) {
    let n = ys.len();
    if n < 3 {
        return (0.0, 0.0);
    }
    let nf = n as f64;
    let xs: Vec<f64> = (0..n).map(|i| i as f64).collect();
    let mx = mean(&xs);
    let my = mean(ys);
    let mut sxx = 0.0;
    let mut sxy = 0.0;
    for i in 0..n {
        sxx += (xs[i] - mx) * (xs[i] - mx);
        sxy += (xs[i] - mx) * (ys[i] - my);
    }
    if sxx == 0.0 {
        return (0.0, 0.0);
    }
    let slope = sxy / sxx;
    let intercept = my - slope * mx;
    let mut sse = 0.0;
    for i in 0..n {
        let pred = intercept + slope * xs[i];
        sse += (ys[i] - pred) * (ys[i] - pred);
    }
    let resid_var = sse / (nf - 2.0);
    let stderr = (resid_var / sxx).sqrt();
    (slope, stderr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn permutation_separates_clear_effect() {
        let a = vec![100.0, 101.0, 99.0, 100.5, 100.2, 99.8];
        let b = vec![140.0, 141.0, 139.0, 140.5, 140.2, 139.8];
        let p = permutation_p(&a, &b, 10000, 42);
        assert!(p < 0.01, "clear effect should be significant, got p={p}");
    }

    #[test]
    fn permutation_finds_no_effect_when_identical_distributions() {
        let a = vec![100.0, 101.0, 99.0, 100.5, 100.2, 99.8];
        let b = vec![100.1, 100.9, 99.1, 100.4, 100.3, 99.7];
        let p = permutation_p(&a, &b, 10000, 42);
        assert!(p > 0.05, "no real effect should not be significant, got p={p}");
    }

    #[test]
    fn within_cov_ignores_between_group_shift() {
        // Two tight groups with very different means: within-group CoV must be
        // small even though the pooled spread is large.
        let a = vec![100.0, 101.0, 99.0, 100.5];
        let b = vec![200.0, 201.0, 199.0, 200.5];
        assert!(within_cov(&a, &b) < 0.02);
    }

    #[test]
    fn permutation_is_deterministic() {
        let a = vec![1.0, 2.0, 3.0, 4.0];
        let b = vec![5.0, 6.0, 7.0, 8.0];
        assert_eq!(
            permutation_p(&a, &b, 5000, 7),
            permutation_p(&a, &b, 5000, 7)
        );
    }

    #[test]
    fn log2_percentile_monotone() {
        // 8 items in bucket 10 ([1024,2048)); median ~ 1.5*1024.
        let mut buckets = vec![0u64; 40];
        buckets[10] = 8;
        assert_eq!(log2_percentile(&buckets, 0.5), 1.5 * 1024.0);
    }
}
