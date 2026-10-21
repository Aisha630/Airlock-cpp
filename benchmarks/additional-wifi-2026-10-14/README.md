# Additional Wi-Fi evaluation — October 14, 2026

**AWID2 exposes benchmark false alarms.** The unchanged flood detector raises alerts in three Normal-labeled windows in AWID2's original reduced training recording. The observed false-positive rate is 3/477 = **0.63%** on that recording. The separate original reduced test recording produces 0/152 = **0%**.

| Evaluation | Benign five-second windows | False-positive windows | Observed FPR |
| --- | ---: | ---: | ---: |
| AWID2 CLS-R training recording | 477 | 3 | 0.63% |
| AWID2 CLS-R test recording | 152 | 0 | 0% |
| Both AWID2 recordings | 629 | 3 | 0.48% |
| Earlier AWID3 Deauth/Disas evaluation | 164 | 0 | 0% |

Both AWID2 files were evaluated with the existing C++ `detect_deauth_flood` function and its unchanged eight-frame/five-second/source-destination threshold. Neither recording was used to train or tune the detector. "Training" and "test" here are the dataset's original filenames, not stages of fitting this heuristic.

The mirror contains 1,795,575 rows in CLS-R-Trn and 575,643 in CLS-R-Tst, matching the original published recording sizes. Normal-label totals are 1,633,190 and 530,785. The training recording spans approximately 3,599.57 seconds and the test recording 1,200.29 seconds. All 2,371,218 rows were read; malformed rows, unexpected labels, invalid timestamps and incorrect column counts are rejected.

## False alarms and what they mean

The three false-positive windows contain 1,108, 142 and 565 disconnect frames respectively, all labeled Normal in this mirror. They produce one, two and one flood findings. The addresses and reason codes identify repeated Class-3/non-associated and Class-2/non-authenticated disconnect patterns. The detector cannot distinguish the intention behind a high-rate burst from frame rate alone.

These are **false positives against the benchmark's labels**, not independently audited proof that every transmission was benign. The packet-level label is accepted as the benchmark ground truth. The original raw PCAPs were not retrieved. We do not relabel these cases as attacks to improve the score.

This recording provides more relevant negative traffic than the earlier AWID3 subset: the scored AWID2 benign windows contain 1,841 disconnect frames across 25 windows. However, only 25 of the 629 benign windows exercise disconnect handling. The remaining benign windows are easier negatives for this detector.

The AWID3 result remains correct for its evaluated recordings; it cannot support a general zero-false-positive or universally perfect-precision claim. This additional evaluation demonstrates that the default heuristic can flag dataset-labeled normal traffic.

## Scope and method

This is a **CSV metadata replay of the flood detector**, not an end-to-end benchmark of all analyzer findings. It uses the original 155-column AWID schema. The required field positions are retained in `awid2-columns.json` and `awid2-summary.json`; the schema reference's revision and hash are in `schema-source.json`. Type/subtype encoding consistency is checked for replayed disconnect frames. Hexadecimal reason codes are converted to decimal for the adapter.

Every complete populated epoch-aligned five-second window is scored. Partial first/last windows are excluded. A window is a negative only when all rows are labeled Normal. Any other label makes it non-benign, and mixed windows are excluded from the FPR denominator. Relevant disconnect-frame timestamps and source/destination addresses are passed to the actual C++ detector through the previously published replay adapter. Other rows still contribute to labels and window counts.

AWID2's CLS labels also cover injection and impersonation and do not locate individual deauthentication attacks. Consequently, the report records the number of non-benign windows flagged but does **not** describe missed non-benign windows as missed deauthentication attacks, or claim attack-specific precision/recall. The mirror's attack-class counts/names differ from some published tables; this evaluation uses only the Normal-versus-non-Normal distinction for FPR and preserves the mirror's labels unchanged.

AWID2's SOHO/WEP testbed differs from AWID3's enterprise/PMF testbed. The original AWID2 documentation describes mobile clients joining and leaving the network. These are still a small number of lab recordings, not independent samples of hundreds of deployed networks. No universal rate or independence-based confidence bound is claimed.

## Other sources checked

- **Mendeley WPA3 Attacks Dataset, version 3:** the current release includes raw Deauth.pcap and labeled-feature CSV downloads. Direct requests returned HTTP 403; the browser download redirected to a storage page blocked by Chrome (`ERR_BLOCKED_BY_CLIENT`). It was not downloaded or scored. No browser security restriction was bypassed.
- **Wi-Fi Association_Disassociation Dataset:** its authors provide labeled AP association-status logs with device identities and timestamps. Those are connection state transitions, not captured deauthentication/disassociation frames, and omit the transmitter/receiver inputs required by this detector. Converting each log entry into a packet would invent inputs, so it was not scored as a packet-level benchmark.

## Wording to quote

> Additional evaluation on AWID2 showed that Airlock's default deauthentication/disassociation flood heuristic is not universally free of false alarms. Its observed false-positive rate was 0.63% (3/477 benign five-second windows) on the original reduced training recording and 0% (0/152) on the separate test recording, or 0.48% across both. These rates are based on labeled CSV metadata replay of the flood detector and do not describe the entire analyzer.

## Reproduction

```sh
cmake -S . -B build-benchmark -DAIRLOCK_BUILD_TESTS=ON
cmake --build build-benchmark -j 4
python3 benchmarks/additional-wifi-2026-10-14/awid2.py
```

The script downloads mirror version 1 if it is not cached, compiles the existing adapter against the production library, and evaluates both files. `awid2-summary.json` records the archive SHA-256, analyzer revision, adapter hash and script hash. Per-window results and original adapter output are retained in the corresponding JSON/TSV files. `awid2-false-positive-windows.json` isolates the three false-alarm windows. Downloaded source data remains under the ignored `.cache/awid2-benchmark/` directory.

Sources:

- [Original AWID2 testbed and recording description](https://icsdweb.aegean.gr/awid/awid2)
- [CLS-R mirror evaluated here](https://www.kaggle.com/datasets/zhiqingcui/awidclsr)
- [155-column schema reference](https://github.com/krishanuskr/AWID-Intrusion-Detection-System-2020/blob/main/AWID_Implementation.ipynb)
- [Association-status dataset documentation](https://github.com/samsonkg/Wi-Fi-Association_Disassociation-Dataset)
- [Mendeley WPA3 dataset version 3](https://data.mendeley.com/datasets/cxx5t5nw7z/3)
