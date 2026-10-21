# AWID3 flood-detector benchmark — October 14, 2026

**Observed false-positive rate: 0% (0 false-positive windows / 164 benign windows).**

This evaluates Airlock's existing C++ `detect_deauth_flood` function on labeled metadata from the complete AWID3 Deauth and Disas CSV recordings available through a public Kaggle mirror. It is a benchmark result for the deauthentication/disassociation flood detector, not an end-to-end false-positive rate for the whole Wi-Fi analyzer.

## Results

| Measure | Deauth recording | Disas recording | Combined |
| --- | ---: | ---: | ---: |
| CSV shards processed | 33 | 41 | 74 |
| Available packet rows processed | 1,626,469 | 2,013,716 | 3,640,185 |
| Benign windows (all rows labeled Normal) | 82 | 82 | 164 |
| False-positive windows | 0 | 0 | 0 |
| True-negative windows | 82 | 82 | 164 |
| Attack-labeled windows | 36 | 36 | 72 |
| True-positive windows | 36 | 36 | 72 |
| False-negative windows | 0 | 0 | 0 |
| Observed false-positive rate | 0% | 0% | 0% |
| Windows excluded for packet-number gaps | 2 | 2 | 4 |

The empirical confusion matrix is `FP=0, TN=164, TP=72, FN=0`. Thus `FPR = FP/(FP+TN) = 0/164 = 0%`. Attack-window detection was 72/72 in this evaluation, which confirms that the detector was not simply silent on all input. It is not a claim of detecting every Wi-Fi attack type or every attack episode.

The 164 benign windows cover 820 seconds (13 minutes 40 seconds) and contain 2,392,280 rows. Only three benign windows contain disconnect frames, with five such frames in total. This is an important limit: the benchmark's benign portions offer little evidence about legitimate disconnect bursts, AP restarts, load shedding or busy roaming networks.

## Method

1. Download every CSV shard in `CSV/1.Deauth/` and `CSV/2.Disas/` from mirror version 1. Files are selected by recording membership, not by results. The downloaded files remain under the ignored `.cache/awid3-benchmark/` directory.
2. Read every available row, its epoch timestamp and its inline `Label`. Reject malformed CSV rows, missing labels, invalid timestamps, duplicate frame numbers and reversed frame numbering. Record gaps in the packet numbers rather than invent missing packets.
3. Form epoch-aligned, nonoverlapping five-second windows. Exclude the partial start/end bins and any windows spanning packet-number gaps. The mirror omits six numbered records across these two recordings, affecting four otherwise eligible windows. Every other complete, populated window is scored.
4. Label a window positive when any row has a non-Normal label. A window is benign only when every available row is Normal and it is not affected by a known numbering gap. All rows remain represented in the ground-truth/window counts; attack rows are not removed from the replay.
5. Replay relevant management-frame metadata through the actual production C++ function linked from `libairlock_wifi.a`. Its input uses `frame.time_epoch`, `wlan.ta`, `wlan.ra`, `wlan.fc.type`, `wlan.fc.subtype`, `wlan.fc.protected` and `wlan.fixed.reason_code`. Non-disconnect frames are omitted from the detector input because this particular production function ignores them. They still contribute to window labels and row counts.
6. Use the existing defaults: at least eight deauthentication/disassociation frames from one source/destination pair within five seconds. A window is predicted positive if the function returns one or more flood findings. No threshold was tuned on AWID3.

3,522,658 available packet rows fall within the 236 scored windows. Results for every window, including its label, row count, disconnect-frame count and number of flood findings, are retained in the per-recording JSON files.

The CSV mirror is a third-party distribution; the raw captures and exact equivalence to the authors' originals were not independently verified. It includes the expected AWID3 field schema and Normal/Deauth/Disas labels. The recorded gaps and checksums make the evaluated version explicit. The dataset's frame labels define the ground truth used here; they do not prove that every normal-labeled window was free of all possible attacks outside this detector's scope.

## What this establishes

It establishes an observed benchmark false-positive rate for the unchanged flood heuristic under the specified windowing and labels. The same function used by the analyzer produces the predictions; the benchmark does not reimplement the flood rule in Python.

It does **not** evaluate PCAP/radiotap parsing, configuration findings, PMKID reporting, the association-disruption heuristic or evil-twin detection. The downloadable CSV features do not contain all information needed to reconstruct those inputs faithfully. Security posture findings must also be distinguished from attack labels when evaluating the full analyzer.

The windows come from two related recordings in the AWID3 testbed; they are not 164 independent network environments. No confidence interval assuming independent windows is claimed. The result is not a universal zero false-positive guarantee. Per-window replay also differs from analyzing an entire capture at once: a burst spanning a five-second bin boundary can be split, even though the whole-capture detector uses sliding windows.

## Correction, October 20, 2026

The mirror stores `frame.time_epoch` rounded to whole seconds in 21 of the 33 Deauth shards and 24 of the 41 Disas shards. `frame.time_relative` keeps microsecond precision throughout. This evaluation used the epoch column, so frames in those shards were placed up to half a second from their true time. The windows were re-scored on exact timestamps (a per-corpus offset plus `frame.time_relative`, see `ml/prepare.py`). The rule's result is unchanged: 72/72 attack windows flagged and no false alarms. The Disas corpus has 117 scored windows rather than 118. The flood detector has since been replaced by a learned model; `ml/README.md` compares it with this rule on the corrected windows.

## Wording to quote

> On the AWID3 Deauth and Disas recordings, Airlock's default deauthentication/disassociation flood detector achieved an observed false-positive rate of 0%: zero false alarms across 164 benign five-second windows. It flagged all 72 attack-labeled windows evaluated. These results use labeled CSV metadata replay and apply to this detector, not to the complete Wi-Fi analyzer or every real-world deployment.

## Reproduction and evidence

```sh
cmake -S . -B build-benchmark -DAIRLOCK_BUILD_TESTS=ON
cmake --build build-benchmark -j 4
python3 benchmarks/awid3-2026-10-14/evaluate.py
```

- `manifest.json`: all 74 selected source files and expected byte sizes.
- `download-evidence.json`: source URLs pinned to mirror version 1, SHA-256 hashes, label counts, frame-number ranges and gaps for each shard.
- `1.Deauth-results.json` and `2.Disas-results.json`: every scored window and the confusion matrices.
- `1.Deauth-detector-output.tsv` and `2.Disas-detector-output.tsv`: original C++ replay outputs.
- `summary.json`: combined rates and denominators.
- `source-metadata.json`: source version, analyzer base revision, library and benchmark-source hashes, and detector defaults.
- `flood_replay.cpp`: a small adapter that constructs frame metadata and calls the production detector; it contains no replacement flood rule.

Sources:

- [AWID3 official description, features and attack filters](https://icsdweb.aegean.gr/awid/awid3)
- [Public CSV mirror used for this evaluation](https://www.kaggle.com/datasets/suumia/awid3-dataset)
- [Official raw-PCAP access request](https://icsdweb.aegean.gr/awid/download)
