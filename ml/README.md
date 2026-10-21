# Learned flood detector

The deauthentication / disassociation flood detector is a small neural
network trained in PyTorch, and PyTorch also runs it: the C++ analyzer
computes features and hands them to a Python scorer. It replaces a
fixed rule: eight disconnect frames from one source to one destination
inside five seconds.

**On held-out data it matches the rule but does not beat it.** On the AWID3
corpus it never trained on, the model flags all 36 attack windows and none of
the 81 benign windows, the same as the rule. On AWID2's test recording it
raises no false alarms on the 18 benign sender/receiver groups, where the
rule raises 4. It also flags fewer attack groups (14/63 against 33/63). The
model is more conservative than the rule. It is not more capable.

## How it works

- **Unit of prediction.** Disconnect frames are grouped by (transmitter,
  receiver), and the densest five-second span of each group is scored. Spans
  of fewer than 9 frames are never reported. One unacknowledged frame plus its
  7 retransmissions (`dot11ShortRetryLimit`) can account for 8.
- **Features.** Ten header-derived features: frame count, peak rate in any
  1 s, protected share, group-addressed target, missing transmitter, distinct
  reason codes, missing-reason share, median gap, gap irregularity and span
  occupancy. They are defined once, in `src/wifi/flood_model.cpp`. Training
  reads them through the C++ library (`ml/flood_features.cpp`), so training
  and inference cannot disagree.
- **Model.** MLP 10-16-1 with ReLU and a sigmoid output, 193 parameters.
- **Inference in PyTorch.** `ml/train.py` saves the model, its
  standardisation constants and threshold to `ml/flood-model.pt`. It then
  reloads the file through the scorer and checks that it reproduces the
  in-memory model. When a capture contains a span of 9 or more disconnect
  frames, the analyzer starts `python3 -I ml/score.py ml/flood-model.pt` once
  for all such spans. It writes their features to the scorer's stdin and
  reads back probabilities and explanations. It starts the interpreter
  directly, never through a shell, and in isolated mode, so the environment's
  `PYTHONPATH` cannot change what runs. Captures without such spans never
  start Python. `AIRLOCK_PYTHON` and `AIRLOCK_FLOOD_MODEL` override the
  interpreter and the model file.
- **Safe model loading.** The scorer loads the model with
  `torch.load(weights_only=True)`. A full pickle load can execute arbitrary
  code embedded in the file, which is the wrong trust model for a security
  tool. The saved file holds only tensors, numbers and strings.
- **When PyTorch is missing.** If Python, PyTorch or the model file is
  unavailable, the report gains an info finding, "Flood detection skipped".
  It lists every burst that went unscored, so the capture never appears to
  have no floods when the question was never asked.
- **Explanations.** Each finding gives the model's probability and the
  features that pushed it furthest towards "attack". Each feature's push is
  measured by resetting it to its training mean.

## Training protocol

Labels come from AWID's per-frame labels. A group is an attack when at least
half of its frames carry a non-normal label.

| Fold | Trained on | Held out |
| --- | --- | --- |
| A (ships) | AWID2 CLS-R training recording + AWID3 Deauth | AWID3 Disas, AWID2 test recording |
| B (check) | AWID2 CLS-R training recording + AWID3 Disas | AWID3 Deauth, AWID2 test recording |

- **Weighting.** Each (dataset, class) cell carries equal total weight in the
  loss.
- **Threshold.** Every fourth 100-second block of the training data is held
  out to choose the threshold: the middle, in log-odds, of the band with the
  best balanced accuracy. The held-out corpus is never used for this.
- **Reproducibility.** Seed 0, deterministic algorithms, 600 full-batch Adam
  epochs. Retraining reproduces `ml/flood-model.pt` byte for byte.

The acceptance bar was fixed before the two-dataset protocol first ran. On
its held-out AWID3 corpus, the shipped fold must flag every attack window and
no benign window. It must also find both floods in the synthetic capture.
Fold A meets it. Fold B misses 1 of 36 windows.

## Results

Rule and model are scored on identical windows. The AWID3 windows use
corrected timestamps (see below).

| Held-out data | Rule windows (TP/FN/FP/TN) | Model windows | Rule groups (TP/FN/FP/TN) | Model groups |
| --- | --- | --- | --- | --- |
| AWID3 Disas (fold A) | 36/0/0/81 | **36/0/0/81** | 182/44/0/12 | 119/107/0/12 |
| AWID3 Deauth (fold B) | 36/0/0/82 | 35/1/0/82 | 92/19/0/23 | 76/35/0/23 |
| AWID2 test (fold A) | 15/72/0/152 | 7/80/0/152 | 33/30/4/14 | 14/49/0/18 |

AWID2's non-normal windows are mostly injection and impersonation, which no
disconnect detector can see, so window recall on AWID2 is low for both. On
AWID2's *training* recording the rule's three false-alarm windows fall to
zero, but that recording is in the training set, so this is not evidence.

## What the model learned that it should not have

Each of these was found by testing and fixed before the version above. They
are recorded because they are the main result of this exercise.

1. **AWID2 alone teaches that unicast floods are benign.** AWID2 labels a
   162,000-frame unicast reason-7 burst from its access point to one client
   as normal. Trained on AWID2 alone, the model learned that unicast
   disconnect bursts are benign. It missed the synthetic unicast flood, and
   on AWID3 it caught 34 of 72 attack windows where the rule caught 72.
   Adding AWID3, whose attacks are mostly unicast, removed the shortcut.
2. **The deauth/disassoc split identifies the corpus.** AWID3's Deauth
   attacks are about 90% deauthentication frames and its Disas attacks are
   mostly disassociation. With that share as a feature, the model learned
   which corpus it trained on, and fold A caught 15 of 36 held-out windows.
   The feature was removed. The two frames disconnect a client equally well.
3. **The AWID3 mirror rounds timestamps.** In 21 of 33 Deauth shards and 24
   of 41 Disas shards of the Kaggle mirror, `frame.time_epoch` is rounded to
   whole seconds. `frame.time_relative` keeps microseconds everywhere. Every
   timing feature had been measuring the CSV export: attack gaps came out as
   0 ms. `ml/prepare.py` rebuilds exact time as a per-corpus offset plus
   `time_relative`. It derives the offset from full-precision rows and
   checks every rounded row against it.
4. **Small groups.** AWID marks every frame during an attack, including
   two-frame exchanges, so the model learned that a few frames can be an
   attack. It called the three forged deauths in the synthetic
   association-disruption scenario a flood. The 9-frame floor was fixed from
   the standard before its effect was measured. It is applied when reporting
   only: training only on groups of 9 or more leaves a single benign event,
   AWID2's burst above, and that model caught 18 of 36 held-out windows.

Changes 2–4 were made after seeing held-out AWID3 results. AWID3 is
therefore not a pristine test set for the final model.

## Limits

- **Very little benign flood-sized traffic.** Among groups of 9 or more
  frames, the only benign examples in either dataset are AWID2's 78 groups
  from one access point and one client. The threshold was chosen on 22
  eligible held-out groups, 2 of them benign. False-positive behaviour on
  real access points shedding clients is essentially unmeasured.
- **The threshold is 0.987, so margins are small.** The synthetic unicast
  flood scores 0.988.
- **Protected frames are unseen.** Protected share, missing transmitter and
  missing reason never vary in the training data, so the model has learned
  nothing about them. AWID3's testbed uses PMF, but its disconnect frames are
  all unprotected.
- **Related recordings.** The AWID3 corpora are two recordings from one
  testbed, and AWID2 is a different testbed. These are a handful of lab
  recordings, not independent networks.

## Reproduction

```sh
cmake -S . -B build-benchmark -DAIRLOCK_BUILD_TESTS=ON
cmake --build build-benchmark -j 4
python3 benchmarks/additional-wifi-2026-10-14/awid2.py   # fetches AWID2 if not cached
python3 benchmarks/awid3-2026-10-14/evaluate.py         # fetches AWID3 if not cached
python3 ml/prepare.py
python3 ml/train.py        # rewrites ml/flood-model.pt and ml/flood-model.json
cmake --build build-benchmark -j 4 && ctest --test-dir build-benchmark
```

`ml/flood-model.json` records the per-fold training sizes, validation
results, held-out confusion matrices for model and rule at window and group
level, and SHA-256 hashes of every replay file trained or evaluated on.

## Wording to quote

> I replaced Airlock's fixed deauthentication-flood rule with a 193-parameter
> neural network trained in PyTorch on AWID2 and AWID3. The C++ analyzer
> computes the features and runs the model through PyTorch in a Python
> subprocess, loading the model with weights_only so the file cannot run code. On a held-out AWID3 corpus it flagged all 36 attack windows
> with no false alarms, matching the rule. On AWID2's test recording it
> removed the rule's 4 group-level false alarms, at the cost of lower group
> recall. Getting there meant finding and removing three dataset shortcuts:
> label noise that made unicast floods look benign, a feature that identified
> the training corpus, and rounded timestamps in the public AWID3 mirror.
