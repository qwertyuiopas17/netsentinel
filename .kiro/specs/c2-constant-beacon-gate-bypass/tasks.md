# Implementation Plan

- [ ] 1. Write bug condition exploration test
  - **Property 1: Bug Condition** - Constant-Interval Beacons Bypass Detection
  - **CRITICAL**: This test MUST FAIL on unfixed code - failure confirms the bug exists
  - **DO NOT attempt to fix the test or the code when it fails**
  - **NOTE**: This test encodes the expected behavior - it will validate the fix when it passes after implementation
  - **GOAL**: Surface counterexamples that demonstrate the bug exists
  - **Scoped PBT Approach**: For constant-interval beacons (CV < 0.05), scope the property to concrete failing cases to ensure reproducibility
  - Test that `_compute_fft_features` on constant IAT sequences (e.g., [30.0, 30.0, 30.0, ...] * 100) produces all-zero features instead of high periodicity scores
  - Test that constant-interval beacons with CV < 0.05 fail the periodicity gate due to zero features
  - The test assertions should verify:
    - For constant IATs (CV < 0.05 with len >= 4): fft_score ≥ 0.9, spectral_entropy ≤ 0.1, peak_prominence ≥ 5.0
    - Periodicity gate evaluates to True: (fft_score > 0.15) AND (spectral_entropy < 0.85) AND (peak_prominence > 3.0)
  - Run test on UNFIXED code in `netsentinel/models/c2_beacon.py`
  - **EXPECTED OUTCOME**: Test FAILS (this is correct - it proves the bug exists)
  - Document counterexamples found:
    - Constant 30s beacon: IATs = [30.0] * 100 → expected high scores, actual [0.0, 0.0, 0.0, 0.0, 0.0]
    - Constant 5s beacon: IATs = [5.0] * 100 → expected high scores, actual [0.0, 0.0, 0.0, 0.0, 0.0]
    - Near-constant with noise: CV = 0.02 → expected high scores, actual near-zero or zero
  - Mark task complete when test is written, run, and failure is documented
  - _Requirements: 1.1, 1.2, 1.3, 1.4_

- [ ] 2. Write preservation property tests (BEFORE implementing fix)
  - **Property 2: Preservation** - FFT-Based Detection for Varying IATs
  - **IMPORTANT**: Follow observation-first methodology
  - Observe behavior on UNFIXED code for non-buggy inputs (IAT sequences with CV ≥ 0.05)
  - Write property-based tests capturing observed behavior patterns:
    - Jittered periodic beacons (e.g., alternating 30s/5s pattern) should produce high periodicity scores
    - Random exponential traffic should produce low periodicity scores (low fft_score, high entropy, low prominence)
    - Moderate jitter beacons (IATs = mean ± variance with CV ≥ 0.05) should continue FFT-based detection
    - Short sequences (< 4 samples) should return all-zero features
  - Use Hypothesis to generate random IAT sequences with CV ≥ 0.05 and verify features are computed correctly
  - Property-based testing generates many test cases for stronger guarantees
  - Run tests on UNFIXED code in `netsentinel/models/c2_beacon.py`
  - **EXPECTED OUTCOME**: Tests PASS (this confirms baseline behavior to preserve)
  - Mark task complete when tests are written, run, and passing on unfixed code
  - _Requirements: 3.1, 3.2, 3.3, 3.4_

- [ ] 3. Fix for C2 constant-interval beacon gate bypass

  - [ ] 3.1 Implement the fix in `_compute_fft_features` method
    - Open `netsentinel/models/c2_beacon.py` and locate the `_compute_fft_features` method in the `C2BeaconDetector` class
    - After the early return for `len(iats) < 4`, add coefficient of variation check:
      ```python
      mean_iat = np.mean(iats)
      std_iat = np.std(iats)
      cv = std_iat / (mean_iat + 1e-9)  # Avoid division by zero
      ```
    - Add condition to detect constant-interval beacons:
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
    - Preserve all existing FFT computation and feature extraction code for CV ≥ 0.05
    - _Bug_Condition: isBugCondition(input) where CV = std(iats) / (mean(iats) + epsilon) < 0.05 AND len(iats) >= 4_
    - _Expected_Behavior: For constant or near-constant IAT sequences (CV < 0.05), return high periodicity scores [fft_score ≥ 0.9, spectral_entropy ≤ 0.1, peak_prominence ≥ 5.0] that enable the periodicity gate to pass_
    - _Preservation: For all IAT sequences with CV ≥ 0.05, preserve exact FFT-based feature computation as before. Short sequences (< 4 samples) continue to return zeros._
    - _Requirements: 2.1, 2.2, 2.3, 2.4, 3.1, 3.2, 3.3, 3.4_

  - [ ] 3.2 Verify bug condition exploration test now passes
    - **Property 1: Expected Behavior** - Constant-Interval Beacons Detected
    - **IMPORTANT**: Re-run the SAME test from task 1 - do NOT write a new test
    - The test from task 1 encodes the expected behavior
    - When this test passes, it confirms the expected behavior is satisfied
    - Run bug condition exploration test from step 1 against the FIXED code
    - **EXPECTED OUTCOME**: Test PASSES (confirms bug is fixed)
    - Verify that constant-interval beacons now produce high periodicity scores:
      - fft_score ≥ 0.9
      - spectral_entropy ≤ 0.1
      - peak_prominence ≥ 5.0
    - Verify that periodicity gate now evaluates to True for constant beacons
    - _Requirements: 2.1, 2.2, 2.3, 2.4_

  - [ ] 3.3 Verify preservation tests still pass
    - **Property 2: Preservation** - FFT-Based Detection for Varying IATs
    - **IMPORTANT**: Re-run the SAME tests from task 2 - do NOT write new tests
    - Run preservation property tests from step 2 against the FIXED code
    - **EXPECTED OUTCOME**: Tests PASS (confirms no regressions)
    - Confirm all preservation behaviors:
      - Jittered beacons (CV ≥ 0.05) still detected using FFT analysis
      - Random traffic still classified as non-periodic
      - Moderate jitter beacons still detected based on dominant frequency peaks
      - Short sequences (< 4 samples) still return all-zero features
    - Verify features for CV ≥ 0.05 match exactly between unfixed and fixed versions

- [ ] 4. Run integration tests from test_gating_integration.py
  - Run the existing integration test suite: `pytest test_gating_integration.py -v`
  - Verify all existing tests continue to pass (no regressions)
  - Verify that `test_constant_interval_beacon_is_degenerate` now demonstrates the fix works
  - Confirm full C2BeaconDetector.predict() flow correctly flags constant-interval beacons
  - Confirm jittered beacons and random traffic classifications remain unchanged

- [ ] 5. Checkpoint - Ensure all tests pass
  - Ensure all tests pass, ask the user if questions arise
  - Verify bug condition exploration test passes (confirms fix works)
  - Verify preservation property tests pass (confirms no regressions)
  - Verify integration tests pass (confirms end-to-end behavior)
  - Document that constant-interval beacons are now correctly detected as high-confidence threats
