# Evaluation after fixes — October 14, 2026

> **Note, October 20, 2026.** The "unchanged flood detector" here is the original eight-frame rule, since replaced by a learned model (`ml/README.md`). These captures have not been re-run with the model.

## Measured false-positive rate

**0% observed on the tested benign sample:** 0 false-positive windows and 28 true-negative windows, using nonoverlapping five-second intervals. The whole capture also produced zero findings: 0 false-positive captures and 1 true-negative capture.

Formula: `FPR = FP / (FP + TN) = 0 / (0 + 28) = 0%` for window-level evaluation, and `0 / (0 + 1) = 0%` for capture-level evaluation. Informational findings are not alarms; any non-informational finding on this secure, author-designated benign recording would be counted as a false alarm. In fact there were no findings at any severity.

Source: [wpa3-sae-flood-anomaly-detection, normal traffic description](https://github.com/yigitcftcgl/wpa3-sae-flood-anomaly-detection/tree/c11bc98da2a0dfac4ac8468c076e416cbceff8b1), specifically `Auth_Normal_Traffic/normal_capture2-01.cap`. The author's README identifies it as traffic collected under normal conditions before the SAE flood attack. This is an author-designated benign label, not an independently audited guarantee about every nearby device.

| Benign sample property | Value |
| --- | ---: |
| Raw packet records | 6,261 |
| Loaded frames | 6,261 |
| Capture duration | 144.668 seconds |
| Reported parse errors | 0 |
| Whole-capture findings | 0 |
| Full five-second windows | 28 |
| Window frames evaluated | 6,165 |
| Windows with observed network advertisements | 25 |
| False-positive windows | 0 |
| True-negative windows | 28 |

All 28 complete windows were evaluated. The final 4.668-second partial interval was excluded from the window denominator but included in the whole-capture run. Packet timestamps were preserved, and no synthetic packets were inserted into the real capture. Windows were analyzed independently; no preceding network or handshake context was added.

**Scope:** this is one short WPA3 recording from one environment. The 28 windows are related samples, not 28 independent environments. It contains authentication and probe responses but no EAPOL handshakes, association requests, deauthentication, or disassociation frames. It therefore does not establish false-positive behavior during benign disconnects, roaming, handshakes, mixed-security deployments, or legitimate AP state conflicts. Three windows contain no network advertisements, further limiting configuration-check coverage. No confidence bound assuming independent windows is claimed. The original analyzer also returned zero findings on the whole benign capture; these fixes did not demonstrate an improvement to its benign-sample false-positive rate.

## Changes and attack regressions

- PMKID and complete-handshake observations no longer imply offline password guessing on SAE, enterprise, OWE, mixed, or unknown authentication. Elevated risk findings require exclusively PSK/PSK-SHA256 advertised AKMs. Mixed-mode stations whose actual selected authentication is not known receive informational observations; this deliberately reduces certainty and can miss a PSK exposure in transition mode.
- Generic handshake notes no longer make unconditional password-recovery claims. PMKID calculations are no longer described with one formula for every AKM.
- PMF-required findings no longer claim all unprotected deauthentication attempts are ineffective; connection setup can be vulnerable before key installation.
- A separate medium-severity association-disruption heuristic identifies at least two requests receiving an unprotected reason-6/7 disconnect followed by a successful association response from the same claimed AP within one second of each request. It ignores retry, suspect, protected, wrong-station, late and unsuccessful-response cases. It reports benign explanations and does not claim proof of spoofing. Association/reassociation response status parsing now covers both response types.

All 63 original attack-category files were rerun. The analyzer loaded 123,590 records with zero reported parse errors. The 205 former high-severity PMKID risk findings on SAE-advertising networks were removed; the metadata remains visible at informational severity. The new association-disruption check flags four capture files, including the independently documented low-rate attack that previously received no flood alert. The unchanged flood detector continues to flag 25 of the 29 files containing deauthentication frames. These file flagging counts are not attack recall estimates; the dataset's attack intervals have not been mapped to the evaluated files. The independent attack was used to develop the new heuristic, so it is a regression case rather than a held-out generalization result.

202 tests passed, including regression coverage for authentication-dependent risk assessment, the PMF wording, repeated conflicting AP responses, and benign association/disconnect cases. Original synthetic-scenario findings remain consistent with their assertions.

## Wording to quote

> After correcting authentication-dependent risk reporting and adding a check for conflicting association responses, Airlock produced no false alarms on a public normal-WPA3 capture containing 6,261 frames over 144.668 seconds. Its observed window-level false-positive rate was 0% (0 of 28 complete five-second windows). This result is limited to one short benign recording and does not establish a general real-world false-positive rate.

## Reproduction

```sh
cmake -S . -B build-benchmark -DAIRLOCK_BUILD_TESTS=ON
cmake --build build-benchmark -j 4
ctest --test-dir build-benchmark --output-on-failure
python3 benchmarks/wifi-2026-10-14/evaluate_fixed.py
```

`summary.json` contains the denominator, all window results and whole-capture evidence. `benign-manifest.json` pins the source revision and capture blob hash. `attack-results.json` contains per-file post-fix results; `reports/` retains the original JSON outputs. `metadata.json` identifies the analyzer base revision, binary hash and source-diff hash, with `source-changes.patch` retaining the evaluated source changes. The baseline remains in the parent directory.
