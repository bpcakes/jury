//! Sampling and reporting for J25's paired authentication-failure measurements.
//!
//! The caller supplies the real operations; this module owns warmup, alternating
//! sampling, sample statistics, and the predeclared gross-divergence threshold.

use std::time::Instant;

use super::TestResult;

fn sample_mean(samples: &[f64]) -> f64 {
    samples.iter().sum::<f64>() / samples.len() as f64
}

fn sample_variance(samples: &[f64], mean: f64) -> f64 {
    samples
        .iter()
        .map(|sample| {
            let delta = sample - mean;
            delta * delta
        })
        .sum::<f64>()
        / (samples.len() - 1) as f64
}

fn absolute_welch_t(
    mean_a: f64,
    variance_a: f64,
    mean_b: f64,
    variance_b: f64,
    samples_per_class: usize,
) -> f64 {
    let standard_error =
        (variance_a / samples_per_class as f64 + variance_b / samples_per_class as f64).sqrt();
    if standard_error == 0.0 {
        if mean_a == mean_b { 0.0 } else { f64::MAX }
    } else {
        ((mean_a - mean_b) / standard_error).abs()
    }
}

pub(super) fn compare_failures(
    case: &str,
    class_a: &str,
    class_b: &str,
    samples_per_class: usize,
    mut operation_a: impl FnMut() -> TestResult,
    mut operation_b: impl FnMut() -> TestResult,
) -> TestResult {
    const WARMUPS_PER_CLASS: usize = 16;
    const GROSS_DIVERGENCE_ABS_WELCH_T: f64 = 10.0;

    for _ in 0..WARMUPS_PER_CLASS {
        operation_a()?;
        operation_b()?;
    }

    let mut samples_a = Vec::with_capacity(samples_per_class);
    let mut samples_b = Vec::with_capacity(samples_per_class);
    let all_started = Instant::now();
    for index in 0..samples_per_class {
        let sample = |operation: &mut dyn FnMut() -> TestResult| -> TestResult<f64> {
            let started = Instant::now();
            operation()?;
            let nanos = u64::try_from(started.elapsed().as_nanos())?;
            Ok(nanos as f64)
        };
        if index % 2 == 0 {
            samples_a.push(sample(&mut operation_a)?);
            samples_b.push(sample(&mut operation_b)?);
        } else {
            samples_b.push(sample(&mut operation_b)?);
            samples_a.push(sample(&mut operation_a)?);
        }
    }
    let operation_ns = all_started.elapsed().as_nanos();
    let mean_a = sample_mean(&samples_a);
    let mean_b = sample_mean(&samples_b);
    let variance_a = sample_variance(&samples_a, mean_a);
    let variance_b = sample_variance(&samples_b, mean_b);
    let abs_welch_t = absolute_welch_t(mean_a, variance_a, mean_b, variance_b, samples_per_class);
    let record = serde_json::json!({
        "schema": 1,
        "case": case,
        "count": samples_per_class * 2,
        "operation_ns": operation_ns,
        "artifact_bytes": null,
        "outcome": "accepted",
        "operation_result": "authentication-failed",
        "samples_per_class": samples_per_class,
        "warmups_per_class": WARMUPS_PER_CLASS,
        "class_a": class_a,
        "class_b": class_b,
        "class_a_mean_ns": mean_a,
        "class_b_mean_ns": mean_b,
        "abs_welch_t": abs_welch_t,
        "gross_divergence_abs_welch_t": GROSS_DIVERGENCE_ABS_WELCH_T,
        "interpretation": "gross wrapper timing regression smoke; not constant-time proof",
    });
    println!("J25_MEASUREMENT={record}");
    if abs_welch_t >= GROSS_DIVERGENCE_ABS_WELCH_T {
        return Err(format!("{case} exceeded the predeclared gross timing threshold").into());
    }
    Ok(())
}

#[test]
fn zero_variance_distinguishes_equal_and_different_classes() {
    assert_eq!(absolute_welch_t(10.0, 0.0, 10.0, 0.0, 4), 0.0);
    assert_eq!(absolute_welch_t(10.0, 0.0, 11.0, 0.0, 4), f64::MAX);
}

#[test]
fn paired_sample_statistics_use_sample_variance_and_absolute_difference() {
    let a = [1.0, 2.0, 3.0];
    let b = [3.0, 4.0, 5.0];
    let mean_a = sample_mean(&a);
    let mean_b = sample_mean(&b);
    let variance_a = sample_variance(&a, mean_a);
    let variance_b = sample_variance(&b, mean_b);
    assert_eq!(mean_a, 2.0);
    assert_eq!(mean_b, 4.0);
    assert_eq!(variance_a, 1.0);
    assert_eq!(variance_b, 1.0);
    let expected = 6.0_f64.sqrt();
    let forward = absolute_welch_t(mean_a, variance_a, mean_b, variance_b, a.len());
    let reversed = absolute_welch_t(mean_b, variance_b, mean_a, variance_a, b.len());
    assert!((forward - expected).abs() < 1e-12);
    assert_eq!(forward, reversed);
}
