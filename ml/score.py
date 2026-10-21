"""Score candidate flood spans with the trained PyTorch model.

The C++ analyzer runs this as `python3 -I ml/score.py MODEL` and writes one
line per span to stdin: the flood features, tab-separated, in the order of
flood_feature_names() in src/wifi/flood_model.cpp. It reads back

    threshold <TAB> t
    score <TAB> probability <TAB> attribution_1 ... attribution_n

with one score line per input line, in order. Each attribution is the drop
in probability when that feature alone is reset to its training mean: how
far it pushed this prediction towards "attack".

The model file is loaded with weights_only=True. A full pickle load can run
arbitrary code from the file, and a security tool should not hand that to
whoever can write its model.
"""
import sys

import torch


def load(path):
    """The network, its standardisation constants and its saved metadata."""
    saved = torch.load(path, weights_only=True)
    inputs, hidden = len(saved['features']), saved['hidden']
    model = torch.nn.Sequential(torch.nn.Linear(inputs, hidden), torch.nn.ReLU(),
                                torch.nn.Linear(hidden, 1))
    model.load_state_dict(saved['state_dict'])
    model.eval()
    return model, saved


def score(model, saved, features):
    """Probabilities and per-feature attributions for a (spans, features) tensor."""
    mean, scale = saved['mean'], saved['scale']
    with torch.no_grad():
        standardised = (features - mean) / scale
        probability = torch.sigmoid(model(standardised))[:, 0]
        attribution = torch.empty_like(features)
        for i in range(features.shape[1]):
            neutral = standardised.clone()
            neutral[:, i] = 0.0
            attribution[:, i] = probability - torch.sigmoid(model(neutral))[:, 0]
    return probability, attribution


def main():
    if len(sys.argv) != 2:
        sys.exit('usage: score.py MODEL < features.tsv')
    model, saved = load(sys.argv[1])
    rows = [line.split('\t') for line in sys.stdin.read().splitlines() if line]
    width = len(saved['features'])
    for row in rows:
        if len(row) != width:
            sys.exit(f'expected {width} features per line, got {len(row)}')
    features = torch.tensor([[float(v) for v in row] for row in rows],
                            dtype=torch.float32).reshape(len(rows), width)
    probability, attribution = score(model, saved, features)
    out = [f"threshold\t{saved['threshold']:.9g}"]
    for p, a in zip(probability.tolist(), attribution.tolist()):
        out.append('\t'.join(['score', f'{p:.9g}', *(f'{v:.9g}' for v in a)]))
    print('\n'.join(out))


if __name__ == '__main__':
    main()
