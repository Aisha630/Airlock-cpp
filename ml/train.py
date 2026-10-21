"""Train the flood model in PyTorch and compile it into the analyzer.

Run ml/prepare.py first. This script:

1. extracts features from the labeled AWID replay files through the
   production C++ library (ml/flood_features.cpp), so training and inference
   share one feature definition;
2. labels each (window, transmitter, receiver) group by its frames: attack
   when at least half of them carry a non-normal AWID label;
3. trains a one-hidden-layer network in two folds that each hold out one
   AWID3 corpus entirely, choosing the decision threshold on held-out blocks
   of the training data, never on the held-out corpus;
4. writes fold A's model to src/wifi/flood_model_weights.inc and both folds'
   results to ml/flood-model.json.

Why two datasets: a model trained on AWID2 alone learned that unicast floods
are benign, because AWID2 labels a 162,000-frame unicast deauth burst from its
access point as normal. AWID3's attacks are mostly unicast, which removes that
shortcut. Each source and class carries equal total weight in the loss, so
AWID2's larger group count cannot reassert it.

The acceptance bar was fixed before this protocol was first run: on its
held-out AWID3 corpus the shipped model must flag every attack window and no
benign window, matching the rule it replaces, and it must find both floods in
the synthetic capture (tests/test_analyze.cpp).
"""
import csv
import re
import hashlib
import json
from pathlib import Path
import subprocess

import numpy as np
import torch

ROOT = Path(__file__).resolve().parents[1]
CACHE = ROOT / '.cache/flood-model'
BUILD = ROOT / 'build-benchmark'
BINARY = BUILD / 'flood-features'
WEIGHTS = ROOT / 'src/wifi/flood_model_weights.inc'
CARD = ROOT / 'ml/flood-model.json'
HIDDEN = 16
EPOCHS = 600
SEED = 0
BLOCK_WINDOWS = 20  # 100 seconds of five-second windows
RULE_THRESHOLD = 8  # the frame-count rule this model replaces
# Spans below this size are never scored, in training or in the analyzer;
# read from the C++ header so the two cannot disagree.
MIN_FRAMES = int(re.search(r'FLOOD_MIN_FRAMES = (\d+);',
                           (ROOT / 'src/wifi/flood_model.hpp').read_text()).group(1))
SOURCES = {
    'awid2-train': 'AWID2 CLS-R training recording',
    'awid2-test': 'AWID2 CLS-R test recording',
    'awid3-deauth': 'AWID3 Deauth corpus',
    'awid3-disas': 'AWID3 Disas corpus',
}
# Fold A ships. Fold B swaps the AWID3 corpora to show the result is not an
# accident of which one was held out.
FOLDS = {
    'A': dict(train=['awid2-train', 'awid3-deauth'], held_out='awid3-disas'),
    'B': dict(train=['awid2-train', 'awid3-disas'], held_out='awid3-deauth'),
}
SHIPPED = 'A'


def load(source):
    """Group features (via the C++ library) and window labels for one source."""
    tsv = CACHE / f'{source}.tsv'
    output = subprocess.check_output([str(BINARY), str(tsv)], text=True)
    reader = csv.DictReader(output.splitlines(), delimiter='\t')
    names = reader.fieldnames[5:-1]
    rows = list(reader)
    frames = np.array([int(r['frames']) for r in rows])
    windows = {}
    with tsv.open() as lines:
        for line in lines:
            if line.startswith('WINDOW\t'):
                _, window, attack = line.split('\t')
                windows[int(window)] = attack.strip() == '1'
    return dict(
        name=source, names=names, frames=frames,
        x=np.array([[float(r[n]) for n in names] for r in rows], dtype=np.float32),
        y=np.array([int(r['attack_frames']) for r in rows]) * 2 >= frames,
        window=np.array([int(r['window']) for r in rows]),
        window_labels=windows,
        sha256=hashlib.sha256(tsv.read_bytes()).hexdigest())


def metrics(predicted, label):
    predicted, label = np.asarray(predicted, bool), np.asarray(label, bool)
    tp = int((predicted & label).sum())
    fp = int((predicted & ~label).sum())
    fn = int((~predicted & label).sum())
    tn = int((~predicted & ~label).sum())
    return dict(tp=tp, fp=fp, fn=fn, tn=tn,
                precision=tp / (tp + fp) if tp + fp else None,
                recall=tp / (tp + fn) if tp + fn else None,
                false_positive_rate=fp / (fp + tn) if fp + tn else None)


def windows(data, flagged):
    """Window-level confusion: a window alerts when any of its groups is flagged.

    This is what the production detector computes on the benchmark replays,
    where each window is analyzed on its own and every group fits in one span.
    """
    alerting = set(data['window'][flagged].tolist())
    ids = sorted(data['window_labels'])
    labels = [data['window_labels'][w] for w in ids]
    return metrics([w in alerting for w in ids], labels)


def evaluate(data, probability, threshold):
    flagged = (data['frames'] >= MIN_FRAMES) & (probability(data['x']) >= threshold)
    return dict(groups=len(data['y']),
                model=dict(groups=metrics(flagged, data['y']),
                           windows=windows(data, flagged)),
                rule=dict(groups=metrics(data['frames'] >= RULE_THRESHOLD, data['y']),
                          windows=windows(data, data['frames'] >= RULE_THRESHOLD)))


def train(parts):
    """Fit on `parts`' eligible groups, holding out every fourth 100-second block of each.

    Blocks rather than random groups, so that held-out groups are not
    near-copies of training groups from the same burst.
    """
    x, y, source, held, eligible = [], [], [], [], []
    for i, data in enumerate(parts):
        order = {w: k for k, w in enumerate(sorted(set(data['window'])))}
        x.append(data['x'])
        y.append(data['y'])
        source.append(np.full(len(data['y']), i))
        eligible.append(data['frames'] >= MIN_FRAMES)
        held.append(np.array([order[w] // BLOCK_WINDOWS % 4 == 3 for w in data['window']]))
    x, y, source, held, eligible = map(np.concatenate, (x, y, source, held, eligible))
    # Small groups are learned from, since they hold most of the benign
    # examples, but the threshold is chosen on spans the analyzer would score.
    fit = ~held
    held = held & eligible

    mean = x[fit].mean(axis=0)
    scale = x[fit].std(axis=0)
    scale[scale < 1e-6] = 1.0

    # Each (source, class) cell carries equal total weight.
    weight = np.zeros(len(y), dtype=np.float32)
    for s in np.unique(source):
        for c in (False, True):
            cell = fit & (source == s) & (y == c)
            if cell.any():
                weight[cell] = 1.0 / cell.sum()
    weight /= weight[fit].mean()

    torch.manual_seed(SEED)
    torch.use_deterministic_algorithms(True)
    model = torch.nn.Sequential(torch.nn.Linear(x.shape[1], HIDDEN), torch.nn.ReLU(),
                                torch.nn.Linear(HIDDEN, 1))
    inputs = torch.from_numpy((x[fit] - mean) / scale)
    targets = torch.from_numpy(y[fit].astype(np.float32))[:, None]
    weights = torch.from_numpy(weight[fit])[:, None]
    loss_fn = torch.nn.BCEWithLogitsLoss(weight=weights)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.01, weight_decay=1e-3)
    for _ in range(EPOCHS):
        optimizer.zero_grad()
        loss = loss_fn(model(inputs), targets)
        loss.backward()
        optimizer.step()

    def probability(data_x):
        with torch.no_grad():
            return torch.sigmoid(model(torch.from_numpy((data_x - mean) / scale))).numpy()[:, 0]

    # Best balanced accuracy on the held-out blocks. With few held-out groups a
    # wide band of thresholds ties; taking either edge of that band leaves no
    # margin on one side, so take its middle in log-odds.
    p_held = probability(x[held])
    def balanced(t):
        m = metrics(p_held >= t, y[held])
        return (1 - m['false_positive_rate']) + m['recall']
    candidates = np.unique(p_held)
    scores = np.array([balanced(t) for t in candidates])
    best = np.flatnonzero(scores == scores.max())
    lower = candidates[best[0] - 1] if best[0] > 0 else 0.0
    upper = candidates[best[-1]]
    logit = lambda p: np.log(np.clip(p, 1e-6, 1 - 1e-6) / (1 - np.clip(p, 1e-6, 1 - 1e-6)))
    threshold = float(1 / (1 + np.exp(-(logit(lower) + logit(upper)) / 2)))
    validation = dict(groups=int(held.sum()), model=metrics(p_held >= threshold, y[held]))
    return model, mean, scale, threshold, probability, dict(
        groups=int(fit.sum()), positive_groups=int(y[fit].sum()),
        final_loss=float(loss.detach()), validation=validation)


def floats(values):
    def literal(v):
        text = f'{float(v):.9g}'
        return text + ('f' if any(c in text for c in '.e') else '.0f')
    return ', '.join(literal(v) for v in values)


def export(model, mean, scale, threshold, probability, parity_x, trained_on):
    w1 = model[0].weight.detach().numpy()
    b1 = model[0].bias.detach().numpy()
    w2 = model[2].weight.detach().numpy()[0]
    b2 = model[2].bias.detach().numpy()
    lines = [
        '// Generated by ml/train.py. Do not edit by hand: retrain instead.',
        f'// Fold {SHIPPED}, trained on {trained_on}; seed {SEED}, torch {torch.__version__}.',
        'namespace flood_weights {',
        f'constexpr std::size_t INPUTS = {len(mean)};',
        f'constexpr std::size_t HIDDEN = {HIDDEN};',
        f'constexpr std::array<float, INPUTS> MEAN = {{{floats(mean)}}};',
        f'constexpr std::array<float, INPUTS> SCALE = {{{floats(scale)}}};',
        'constexpr float W1[HIDDEN][INPUTS] = {',
        *[f'    {{{floats(row)}}},' for row in w1],
        '};',
        f'constexpr float B1[HIDDEN] = {{{floats(b1)}}};',
        f'constexpr float W2[HIDDEN] = {{{floats(w2)}}};',
        f'constexpr float B2 = {floats(b2)};',
        f'constexpr double THRESHOLD = {threshold:.9g};',
        f'constexpr std::array<FloodParityCase, {len(parity_x)}> PARITY = {{{{',
        *[f'    {{{{{{{floats(x)}}}}}, {p:.9g}}},'
          for x, p in zip(parity_x, probability(parity_x))],
        '}};',
        '}  // namespace flood_weights',
    ]
    WEIGHTS.write_text('\n'.join(lines) + '\n')


def main():
    subprocess.run(['c++', '-std=c++20', '-O2', '-I', str(ROOT / 'src'),
                    str(ROOT / 'ml/flood_features.cpp'), str(BUILD / 'libairlock_wifi.a'),
                    '-o', str(BINARY)], check=True)
    data = {source: load(source) for source in SOURCES}
    names = data['awid2-train']['names']

    card = dict(model=f'MLP {len(names)}-{HIDDEN}-1, ReLU, sigmoid output', features=names,
                epochs=EPOCHS, seed=SEED, torch=torch.__version__, shipped_fold=SHIPPED,
                min_frames=MIN_FRAMES,
                group_label='attack when at least half its frames carry a non-normal label',
                replay_sha256={s: d['sha256'] for s, d in data.items()}, folds={})
    for fold, spec in FOLDS.items():
        model, mean, scale, threshold, probability, info = train([data[s] for s in spec['train']])
        evaluated = [s for s in SOURCES if s not in spec['train']]
        card['folds'][fold] = dict(
            trained_on=[SOURCES[s] for s in spec['train']], held_out=SOURCES[spec['held_out']],
            threshold=threshold, training=info,
            evaluation={SOURCES[s]: evaluate(data[s], probability, threshold) for s in evaluated})
        if fold == SHIPPED:
            held_out = data[spec['held_out']]['x']
            picks = np.linspace(0, len(held_out) - 1, 7).astype(int)
            parity_x = np.vstack([held_out[picks], np.zeros((1, len(names)), dtype=np.float32)])
            export(model, mean, scale, threshold, probability, parity_x,
                   ' + '.join(SOURCES[s] for s in spec['train']))
            card['threshold'] = threshold
    CARD.write_text(json.dumps(card, indent=2) + '\n')

    for fold, result in card['folds'].items():
        print(f"fold {fold}: trained on {' + '.join(result['trained_on'])}, "
              f"threshold {result['threshold']:.3f}")
        for source, e in result['evaluation'].items():
            for who in ('model', 'rule'):
                g, w = e[who]['groups'], e[who]['windows']
                print(f"  {source:32} {who:5}  windows TP {w['tp']:3} FN {w['fn']:3} "
                      f"FP {w['fp']:2} TN {w['tn']:3}   groups TP {g['tp']:3} FN {g['fn']:3} "
                      f"FP {g['fp']:2} TN {g['tn']:3}")


if __name__ == '__main__':
    main()
