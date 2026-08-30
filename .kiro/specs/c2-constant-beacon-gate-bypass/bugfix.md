# Bugfix Requirements Document

## Introduction

The C2 beacon detection system contains a critical vulnerability where perfectly periodic beacons (constant-interval traffic) bypass detection and are incorrectly classified as benign. This occurs because the FFT-based periodicity gate computes features on mean-removed inter-arrival times (IATs). When IATs are constant (e.g., [30, 30, 30, ...]), mean removal produces an all-zero signal, resulting in zero FFT magnitudes and zero periodicity scores. These metronome-like beacons represent the most common and dangerous type of C2 traffic, yet they slip through undetected.

The bug is documented in `test_constant_interval_beacon_is_degenerate`, which confirms that constant-interval beacons score as benign while jittered beacons are correctly detected.

## Bug Analysis

### Current Behavior (Defect)

1.1 WHEN a C2 beacon has perfectly constant inter-arrival times (e.g., exactly 30s between all packets) THEN the system computes FFT features on the mean-removed IAT sequence which becomes all zeros

1.2 WHEN the FFT is computed on an all-zero signal THEN the system produces zero magnitudes and zero periodicity scores (fft_score=0, spectral_entropy=0, peak_prominence=0)

1.3 WHEN periodicity scores are all zero THEN the system evaluates the periodicity gate as `(0 > 0.15) and (0 < 0.85) and (0 > 3.0)` which returns False

1.4 WHEN the periodicity gate returns False for constant-interval beacons THEN the system classifies them as benign and does not flag them as threats

### Expected Behavior (Correct)

2.1 WHEN a C2 beacon has perfectly constant inter-arrival times THEN the system SHALL detect the constant periodicity pattern and recognize it as a strong indicator of beaconing behavior

2.2 WHEN IATs have zero or near-zero variance (indicating constant intervals) THEN the system SHALL flag this as a high-confidence periodic signal rather than treating it as a degenerate case

2.3 WHEN the periodicity gate evaluates constant-interval traffic THEN the system SHALL return True to indicate strong periodicity

2.4 WHEN constant-interval beacons are processed THEN the system SHALL classify them as threats and report them with appropriate confidence scores

### Unchanged Behavior (Regression Prevention)

3.1 WHEN a beacon has jittered intervals (e.g., alternating 30s/5s pattern) THEN the system SHALL CONTINUE TO detect it using the existing FFT-based periodicity features

3.2 WHEN traffic has random inter-arrival times (e.g., exponentially distributed IATs) THEN the system SHALL CONTINUE TO classify it as non-periodic and benign

3.3 WHEN a beacon has moderate jitter around a mean interval THEN the system SHALL CONTINUE TO detect it based on the dominant frequency peak in the FFT spectrum

3.4 WHEN FFT features are computed for varying IAT sequences THEN the system SHALL CONTINUE TO use the mean-removed signal and compute fft_score, spectral_entropy, and peak_prominence as before
