# C2 Constant-Interval Beacon Gate Bypass Bugfix Design

## Overview

The C2 beacon detection system has a critical flaw in the `_compute_fft_features` method where perfectly constant inter-arrival times (IATs)—the most dangerous type of C2 beacon—bypass detection entirely. The bug occurs because FFT computation applies mean removal to the IAT sequence first. When IATs are constant (e.g., [30, 30, 30, ...]), mean removal produces an all-zero signal, resulting in zero FFT magnitudes and zero periodicity scores. The periodicity gate then evaluates `(0 > 0.15) and (0 < 0.85) and (0 > 3.0)` which returns False, incorrectly classifying these metronome beacons as benign.

The fix adds a pre-check for constant or near-constant intervals using coefficient of variation (CV = std/mean). When CV is below a threshold (indicating low variance), the system recognizes this as a strong periodic signal and returns high periodicity scores instead of performing FFT analysis. This ensures constant-interval beacons are flagged while preserving the existing FFT-based detection for jittered beacons.

## Glossary

- **Bug_Condition (C)**: The condition that triggers the bug - when IATs are constant or near-constant (low coefficient of variation), causing mean removal to produce an all-zero or near-zero signal
- **Property (P)**: The desired behavior when constant-interval beacons are encountered - they should be flagged as high-confidence periodic signals with appropriate scores
- **Preservation**: Existing FFT-based detection for jittered beacons and rejection of random traffic must remain unchanged by the fix
- **IAT (Inter-Arrival Time)**: Time interval between consecutive network flows in seconds
- **FFT (Fast Fourier Transform)**: Algorithm used to identify periodic patterns in the frequency domain
- **Coefficient of Variation (CV)**: Ratio of standard deviation to mean (std/mean), used to detect constant intervals
- **_compute_fft_features**: The method in `netsentinel/models/c2_beacon.py` (C2BeaconDetector class) that computes the 5 periodicity features from IAT sequences
- **Periodicity Gate**: The logical condition `(fft_score > 0.15) and (spectral_entropy < 0.85) and (peak_prominence > 3.0)` that determines if traffic is periodic
- **Mean Removal**: Preprocessing step that subtracts the mean from the signal before FFT analysis: `iats - np.mean(iats)`

## Bug Details

### Bug Condition

The bug manifests when a C2 beacon has constant or near-constant inter-arrival times. The `_compute_fft_features` method performs mean removal before FFT analysis, which is standard practice for frequency analysis. However, this creates a degenerate case: when all IATs are identical, subtracting the mean produces an all-zero signal, making it impossible to detect the periodicity.

**Formal Specification:**
```
FUNCTION isBugCondition(input)
  INPUT: input of type np.ndarray (IAT sequence)
  OUTPUT: boolean
  
  mean_iat := MEAN(input)
  std_iat := STD(input)
  cv := std_iat / (mean_iat + epsilon)
  
  RETURN (len(input) >= 4)
         AND (cv < 0.05)
         AND (mean_removal_produces_zeros(input))
END FUNCTION

FUNCTION mean_removal_produces_zeros(iats)
  mean_removed := iats - MEAN(iats)
  magnitudes := ABS(FFT(mean_removed)[1:])
  RETURN magnitudes.sum() == 0 OR magnitudes.max() == 0
END FUNCTION
```

### Examples

- **Constant 30s beacon**: IATs = [30.0, 30.0, 30.0, ...] for 100 flows
  - Current: `iats - 30.0 = [0, 0, 0, ...]` → FFT produces zeros → gate returns False (benign)
  - Expected: CV = 0.0 (constant) → should be flagged as high-confidence periodic with fft_score ≈ 1.0

- **Constant 5s beacon**: IATs = [5.0, 5.0, 5.0, ...] for 100 flows
  - Current: `iats - 5.0 = [0, 0, 0, ...]` → FFT produces zeros → gate returns False (benign)
  - Expected: CV = 0.0 (constant) → should be flagged as high-confidence periodic

- **Near-constant beacon with measurement noise**: IATs = [30.01, 29.99, 30.00, 30.02, ...]
  - Current: `iats - 30.0 ≈ [0.01, -0.01, 0, 0.02, ...]` → very small FFT magnitudes → gate may return False
  - Expected: CV ≈ 0.001 (near-constant) → should be flagged as high-confidence periodic

- **Edge case - insufficient data**: IATs = [30.0, 30.0, 30.0] (only 3 samples)
  - Expected: Returns all-zero features (current behavior should be preserved for short sequences)

## Expected Behavior

### Preservation Requirements

**Unchanged Behaviors:**
- Jittered beacons (e.g., alternating 30s/5s pattern) must continue to be detected using FFT analysis on the mean-removed signal
- Random traffic with exponentially distributed IATs must continue to be classified as non-periodic (low fft_score, high entropy, low prominence)
- Beacons with moderate jitter around a mean interval must continue to be detected based on dominant frequency peaks
- The FFT computation, feature extraction, and scaling for non-constant IAT sequences must remain exactly as before
- All five features (fft_score, dominant_freq, harmonic_ratio, spectral_entropy, peak_prominence) must continue to be computed in the same way for varying IAT sequences

**Scope:**
All inputs that do NOT have constant or near-constant intervals (CV ≥ 0.05) should be completely unaffected by this fix. This includes:
- Jittered periodic beacons (alternating intervals, sinusoidal patterns, moderate variance)
- Random/bursty traffic (exponential distributions, high variance)
- Short IAT sequences (< 4 samples) which should continue returning zeros

## Hypothesized Root Cause

Based on the bug description and code analysis, the root cause is clear:

1. **Mean Removal on Constant Signals**: The `_compute_fft_features` method computes `fft_vals = np.fft.rfft(iats - np.mean(iats))`. For constant IATs, `iats - np.mean(iats)` produces an all-zero array.

2. **Zero FFT Magnitudes**: FFT of an all-zero signal produces zero magnitudes: `magnitudes = np.abs(fft_vals[1:])` becomes `[0, 0, ..., 0]`.

3. **Zero Feature Values**: All periodicity features are computed from magnitudes:
   - `fft_score = magnitudes.max() / (magnitudes.sum() + 1e-9)` → 0 / 1e-9 ≈ 0
   - `spectral_entropy` → 0 (no power distribution)
   - `peak_prominence` → 0 (no peak to measure)

4. **Gate Failure**: The periodicity gate evaluates `(0 > 0.15) and (0 < 0.85) and (0 > 3.0)` → False, classifying the beacon as benign.

**Why This Happens:**
Mean removal is a standard preprocessing step for frequency analysis to remove the DC component. However, for constant signals, the DC component IS the signal—there is no variation to analyze in the frequency domain after removing it. The FFT-based approach is fundamentally designed to detect *varying* periodic patterns (like alternating intervals), not constant ones.

## Correctness Properties

Property 1: Bug Condition - Constant-Interval Beacons Are Periodic

_For any_ IAT sequence where the coefficient of variation is below 0.05 (indicating constant or near-constant intervals) and the sequence has at least 4 samples, the fixed `_compute_fft_features` function SHALL return high periodicity scores (fft_score ≥ 0.9, spectral_entropy ≤ 0.1, peak_prominence ≥ 5.0) to indicate strong periodic behavior, enabling the periodicity gate to correctly classify these beacons as threats.

**Validates: Requirements 2.1, 2.2, 2.3, 2.4**

Property 2: Preservation - FFT-Based Detection for Varying IATs

_For any_ IAT sequence where the coefficient of variation is NOT below 0.05 (indicating varying intervals), the fixed `_compute_fft_features` function SHALL produce exactly the same feature values as the original function, preserving FFT-based detection for jittered beacons and rejection of random traffic.

**Validates: Requirements 3.1, 3.2, 3.3, 3.4**

## Fix Implementation

### Changes Required

The fix is localized to a single method with minimal changes to preserve existing behavior.

**File**: `netsentinel/models/c2_beacon.py`

**Function**: `_compute_fft_features`

**Specific Changes**:

1. **Add Coefficient of Variation Check**: Before performing FFT analysis, compute CV = std(iats) / mean(iats). If CV < 0.05, classify the sequence as constant-interval.

   ```python
   # After the early return for len(iats) < 4:
   mean_iat = np.mean(iats)
   std_iat = np.std(iats)
   cv = std_iat / (mean_iat + 1e-9)  # Avoid division by zero
   ```

2. **Return High Periodicity Scores for Constant Intervals**: When CV < 0.05, return feature values that indicate strong periodicity:
   
   ```python
   if cv < 0.05:
       # Constant-interval beacon: perfect periodicity
       # fft_score: high concentration (perfect peak)
       # dominant_freq: 1/N (all energy at DC, but we treat as periodic)
       # harmonic_ratio: 0 (no harmonics for constant signal)
       # spectral_entropy: low (all power in one "bin" conceptually)
       # peak_prominence: high (conceptual peak stands out)
       return np.array([0.95, 1.0/len(iats), 0.0, 0.05, 10.0], dtype=np.float32)
   ```

3. **Preserve Existing FFT Logic**: All existing FFT computation and feature extraction code remains unchanged for non-constant sequences (CV ≥ 0.05).

4. **Edge Case Handling**: The early return for `len(iats) < 4` remains unchanged, ensuring short sequences still return zeros.

5. **Threshold Rationale**: 
   - CV < 0.05 means std is less than 5% of mean (e.g., for mean=30s, std < 1.5s)
   - This catches truly constant beacons and those with minimal measurement noise
   - Jittered beacons typically have CV > 0.1, so they continue through FFT path

### Implementation Summary

The fix adds approximately 10 lines of code at the beginning of `_compute_fft_features`, after the length check but before FFT computation. The modification is conservative: it only affects the degenerate constant-interval case and leaves all other code paths untouched.

## Testing Strategy

### Validation Approach

The testing strategy follows a two-phase approach: first, surface counterexamples that demonstrate the bug on unfixed code, then verify the fix works correctly and preserves existing behavior. The test `test_constant_interval_beacon_is_degenerate` already demonstrates the bug, so we can use it as our exploratory test.

### Exploratory Bug Condition Checking

**Goal**: Surface counterexamples that demonstrate the bug BEFORE implementing the fix. Confirm the root cause analysis is correct.

**Test Plan**: The existing test `test_constant_interval_beacon_is_degenerate` already demonstrates the bug. We will run this test on the UNFIXED code to observe that constant-interval beacons produce all-zero features and fail the periodicity gate. We will also add additional test cases to explore edge cases around the CV threshold.

**Test Cases**:
1. **Constant 30s Beacon**: IATs = [30.0] * 100 (will fail on unfixed code - returns all zeros)
2. **Constant 5s Beacon**: IATs = [5.0] * 100 (will fail on unfixed code - returns all zeros)
3. **Near-Constant with Noise**: IATs = 30.0 + np.random.normal(0, 0.1, 100) (may fail on unfixed code - very small magnitudes)
4. **CV Threshold Boundary**: IATs with CV = 0.049 vs 0.051 (explore boundary behavior on unfixed code)

**Expected Counterexamples**:
- Constant-interval beacons produce feature vectors of all zeros: `[0.0, 0.0, 0.0, 0.0, 0.0]`
- Periodicity gate evaluates to False for these zero features
- Possible causes confirmed: mean removal on constant signals produces all-zero input to FFT

### Fix Checking

**Goal**: Verify that for all inputs where the bug condition holds (constant or near-constant IATs), the fixed function produces the expected behavior (high periodicity scores).

**Pseudocode:**
```
FOR ALL iats WHERE isBugCondition(iats) DO
  features := _compute_fft_features_fixed(iats)
  ASSERT features[0] >= 0.9  // fft_score indicates strong periodicity
  ASSERT features[3] <= 0.1  // spectral_entropy is low (concentrated)
  ASSERT features[4] >= 5.0  // peak_prominence is high (stands out)
  
  gate := (features[0] > 0.15) AND (features[3] < 0.85) AND (features[4] > 3.0)
  ASSERT gate == True  // periodicity gate passes
END FOR
```

**Test Cases:**
1. **Perfect Constant Intervals**: Test CV = 0.0, 0.01, 0.02, 0.03, 0.04 all produce high periodicity scores
2. **Various Beacon Intervals**: Test constant intervals of 1s, 5s, 10s, 30s, 60s all detected
3. **Near-Constant with Measurement Noise**: IATs = mean + small random noise, CV < 0.05
4. **Minimum Length Boundary**: Test 4-sample constant sequence (minimum for FFT)

### Preservation Checking

**Goal**: Verify that for all inputs where the bug condition does NOT hold (varying IATs, CV ≥ 0.05), the fixed function produces the same result as the original function.

**Pseudocode:**
```
FOR ALL iats WHERE NOT isBugCondition(iats) DO
  ASSERT _compute_fft_features_original(iats) = _compute_fft_features_fixed(iats)
END FOR
```

**Testing Approach**: Property-based testing is recommended for preservation checking because:
- It generates many test cases automatically across the input domain
- It catches edge cases that manual unit tests might miss
- It provides strong guarantees that behavior is unchanged for all non-constant IAT sequences

**Test Plan**: Observe behavior on UNFIXED code first for jittered and random IAT sequences, then write property-based tests capturing that behavior. We can use Hypothesis to generate random IAT sequences with CV ≥ 0.05 and verify features match exactly.

**Test Cases**:
1. **Jittered Periodic Beacons**: Observe that alternating 30s/5s pattern produces high periodicity scores on unfixed code, then verify this continues after fix
2. **Random Exponential Traffic**: Observe that exponentially distributed IATs produce low periodicity scores on unfixed code, then verify this continues after fix
3. **Moderate Jitter Beacons**: Observe that IATs = 30 + uniform(-5, 5) produces moderate periodicity scores on unfixed code, then verify this continues after fix
4. **Edge Case - Short Sequences**: Verify that sequences with < 4 samples still return all-zero features

### Unit Tests

- Test constant-interval beacons with CV < 0.05 produce high periodicity scores (fft_score ≥ 0.9, entropy ≤ 0.1, prominence ≥ 5.0)
- Test near-constant beacons with small noise (CV < 0.05) are detected
- Test jittered beacons (CV ≥ 0.05) continue to use FFT-based detection
- Test random traffic (high CV) continues to produce low periodicity scores
- Test edge cases: empty arrays, single values, very short sequences (< 4 samples)
- Test CV threshold boundary: sequences with CV = 0.049 vs 0.051 behave correctly

### Property-Based Tests

- Generate random constant-interval beacons with varying means (1s to 120s) and verify all produce high periodicity scores
- Generate random jittered beacons (alternating patterns, sinusoidal, moderate variance) and verify features match unfixed code exactly
- Generate random bursty/exponential IAT sequences and verify low periodicity scores are preserved
- Generate sequences with CV values spanning 0.0 to 2.0 and verify correct branching at CV = 0.05 threshold
- Generate edge cases near the CV threshold and verify stable behavior

### Integration Tests

- Test full C2BeaconDetector.predict() flow with constant-interval beacon series (should be flagged as beacon)
- Test full flow with jittered beacon series (should continue to be detected as before)
- Test full flow with random traffic series (should continue to be classified as benign)
- Test that periodicity gate now passes for constant-interval beacons
- Test that existing test cases in test_gating_integration.py continue to pass
- Verify test_constant_interval_beacon_is_degenerate test now FAILS (documents that the bug is fixed)
