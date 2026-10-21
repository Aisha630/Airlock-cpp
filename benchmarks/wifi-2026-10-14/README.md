# External Wi-Fi capture evaluation — October 14, 2026

> **Note, October 20, 2026.** This evaluates the original eight-frame flood rule, which has since been replaced by a learned model (`ml/README.md`). These captures have not been re-run with the model.

This document records the original baseline. The subsequent fixes and measured benign-sample false-positive rate are documented in [post-fix/README.md](post-fix/README.md). The baseline results below are retained unchanged for comparison.

The unmodified analyzer at revision `5f0da54995adc2c2439d112b3e9b967ff4b4e781` was built from source and run on 63 public deauthentication-category capture files from two research repositories. All 62 files in the first repository's deauthentication folder were included; the second repository provides one such capture. No files were selected based on their results, and no detector thresholds were tuned.

## Results

| Measure | WPA3-dataset | WPA3-Attacks-IDS | Total |
| --- | ---: | ---: | ---: |
| Capture files | 62 | 1 | 63 |
| Input packet records, independently counted | 122,306 | 1,284 | 123,590 |
| Frames loaded by analyzer | 122,306 | 1,284 | 123,590 |
| Reported parse errors | 0 | 0 | 0 |
| Deauthentication frames reported | 6,751 | 12 | 6,763 |
| Disassociation frames reported | 39 | 0 | 39 |
| Files containing deauthentication frames | 28 | 1 | 29 |
| Files receiving a flood alert | 25 | 0 | 25 |

The analyzer raised 63 flood findings across the 25 flagged files; findings are grouped by source/destination pair, so this is not 63 independent attack episodes. It identified 296 structurally suspect frames and excluded them from network discovery. Zero parse errors means the analyzer reported no parsing exceptions; it does not prove that every decoded field was correct.

Flood alerts appeared in 25/63 files overall (39.7%) and in 25/29 files containing deauthentication frames (86.2%). These are descriptive **file flagging rates**, not attack recall or overall accuracy. The 62 files are segments from a collection, not 62 independent experimental attacks. The folder label alone does not locate attack intervals within each file. In particular, 34 segments contained no deauthentication frames.

The default flood rule requires at least eight deauthentication/disassociation frames within five seconds for the same source/destination pair. The four files with deauthentication frames but no flood alert contained 1, 1, 7, and 12 such frames, respectively. The second repository documents a low-rate attack that rejects new connections; its entire capture did not trigger the flood detector. It did receive a low-severity unprotected-deauthentication finding, whose explanation incorrectly assumes that PMF makes this attack ineffective. The authors document disruption before the protected connection is established.

## Report quality findings

Across these captures the analyzer emitted 205 high-severity `PMKID disclosed in EAPOL message 1` findings, all attached to networks advertised as WPA3-Personal (SAE). The generic finding explanation claims the captured PMKID enables an offline dictionary attack. That claim is unsupported for SAE: its password-authenticated key exchange resists passive offline password guessing. Observing a PMKID alone does not establish the claimed vulnerability. These 205 outputs include repeats and must not be described as 205 independent vulnerable networks or a statistically measured false-positive rate.

References for this interpretation:

- [Wi-Fi Alliance, WPA3 Security Considerations, November 2019, Password Strength](https://wpa3.mathyvanhoef.com/WPA3_Security_Considerations_201911.pdf)
- [Independent deauthentication attack description, including the documented connection failure](https://github.com/neildalal/WPA3-Attacks-IDS/blob/1e9abe17f8f2d595724c198a640544b81d72f5d1/Attacks/Deauthentication/README.md)

## Quotable result

> In an initial external-capture evaluation, Airlock loaded all 123,590 packet records from 63 public Wi-Fi capture files with zero reported parse errors. Its default deauthentication/disassociation flood detector flagged 25 of the 29 files containing deauthentication frames. This file-level result is not an attack-recall estimate: the captures include related segments and lack mapped attack intervals. The evaluation exposed a missed low-rate connection-disruption attack and unsupported WPA3-SAE PMKID risk claims. A false-positive rate has not yet been established.

This evaluation covers deauthentication-related behavior and parsing. It does not benchmark evil twins, all supported configuration checks, general intrusion detection, precision, or false alarms per hour. A defensible false-positive rate requires labeled benign wireless captures and an explicit evaluation unit, such as network/time windows. AWID3 requires access approval; Mendeley's dataset download endpoints returned HTTP 403 in this session; an additional COMNETS benign/attack dataset had restricted files. No access requests or external messages were submitted.

## Reproduction and evidence

```sh
cmake -S . -B build-benchmark -DAIRLOCK_BUILD_TESTS=OFF
cmake --build build-benchmark -j 4
python3 benchmarks/wifi-2026-10-14/run.py
```

`manifest.json` pins the repositories, revisions, paths, and Git blob hashes. `results.json` includes per-file results and SHA-256 checksums. `reports/` holds the analyzer's original JSON reports. `metadata.json` records the analyzer revision, executable checksum, commands, and default threshold. Downloaded captures are retained under the ignored `.cache/wifi-benchmark/` directory. The script verifies each downloaded capture against its pinned Git blob hash and independently counts its packet-container records.

Sources:

- [Empirical Evaluation of Wi-Fi Handshake Attacks: The WPA3 Dataset repository](https://github.com/hsngccu/WPA3-dataset/tree/e07113327e2012a861f3e273e10ed9b02f0491f4)
- [A Wireless Intrusion Detection System for 802.11 WPA3 Networks repository](https://github.com/neildalal/WPA3-Attacks-IDS/tree/1e9abe17f8f2d595724c198a640544b81d72f5d1)
