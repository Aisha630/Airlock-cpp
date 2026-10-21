"""Write AWID disconnect frames, each with its own attack label, for training.

The flood benchmarks' replay files carry one label per window. Training needs
finer ground truth: AWID labels every frame, so each (transmitter, receiver)
group in a window can be labeled by the frames it actually contains. Windows
are chosen exactly as in benchmarks/additional-wifi-2026-10-14/awid2.py and
benchmarks/awid3-2026-10-14/evaluate.py, whose caches this reads.
"""
import concurrent.futures
import csv
import io
import json
import math
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
ZIP = ROOT / '.cache/awid2-benchmark/awidclsr.zip'
AWID3 = ROOT / '.cache/awid3-benchmark'
AWID3_MANIFEST = ROOT / 'benchmarks/awid3-2026-10-14/manifest.json'
CACHE = ROOT / '.cache/flood-model'
COLS = {'timestamp': 3, 'type_subtype': 63, 'type': 65, 'subtype': 66,
        'protected': 72, 'ra': 75, 'ta': 77, 'reason': 109, 'label': 154}
SPLITS = [('train', 'AWID-CLS-R-Trn/AWID-CLS-R-Trn/1', 1795575),
          ('test', 'AWID-CLS-R-Tst/AWID-CLS-R-Tst/1', 575643)]


def prepare(source, name, expected):
    windows = {}
    rows = 0
    first = last = None
    for row in csv.reader(io.TextIOWrapper(source, encoding='utf-8')):
        assert len(row) == 155
        timestamp = float(row[COLS['timestamp']])
        assert math.isfinite(timestamp)
        first = timestamp if first is None else min(first, timestamp)
        last = timestamp if last is None else max(last, timestamp)
        rows += 1
        label = row[COLS['label']]
        assert label in ('normal', 'flooding', 'injection', 'impersonation')
        w = windows.setdefault(math.floor(timestamp / 5), dict(attacks=0, events=[]))
        w['attacks'] += label != 'normal'
        if row[COLS['type']] != '0' or row[COLS['subtype']] not in ('10', '12'):
            continue
        assert int(row[COLS['type_subtype']], 16) == int(row[COLS['subtype']])
        reason = row[COLS['reason']]
        w['events'].append([timestamp, row[COLS['ta']] if row[COLS['ta']] != '?' else '-',
            row[COLS['ra']] if row[COLS['ra']] != '?' else '-', row[COLS['subtype']],
            row[COLS['protected']], str(int(reason, 0)) if reason != '?' else '-',
            int(label != 'normal')])
    assert rows == expected, (rows, expected)
    bins = [i for i in range(math.ceil(first / 5), math.floor(last / 5)) if i in windows]
    out = CACHE / f'awid2-{name}.tsv'
    with out.open('w') as target:
        for i in bins:
            target.write(f"WINDOW\t{i}\t{int(windows[i]['attacks'] > 0)}\n")
            for event in sorted(windows[i]['events']):
                target.write('\t'.join(map(str, event)) + '\n')
    print(f'{name}: {rows} rows, {len(bins)} windows -> {out}')


def awid3_offset(names):
    """The epoch time of each corpus's frame.time_relative zero.

    The mirror stores frame.time_epoch at full precision in some shards and
    rounded to whole seconds in others, which would collapse a flood's timing
    into one-second steps. frame.time_relative keeps microseconds throughout,
    so exact time is this offset plus the relative time. The offset comes from
    the full-precision rows, and every rounded row is checked against it.
    """
    exact, rounded = [], []
    for name in names:
        with (AWID3 / name).open(newline='', encoding='utf-8') as source:
            reader = csv.reader(source)
            header = next(reader)
            epoch, relative = header.index('frame.time_epoch'), header.index('frame.time_relative')
            for _, row in zip(range(1000), reader):
                difference = float(row[epoch]) - float(row[relative])
                (exact if '.' in row[epoch] else rounded).append(difference)
    offset = sum(exact) / len(exact)
    assert max(abs(d - offset) for d in exact) < 1e-5, 'full-precision shards disagree'
    assert all(abs(d - offset) <= 0.5 + 1e-5 for d in rounded), 'rounded shards disagree'
    return offset


def awid3_shard(name, offset):
    """One AWID3 CSV shard on exact timestamps: windows, numbering gaps, and
    its labeled disconnect frames. Cached, since the shards total 4 GB."""
    cached = CACHE / 'awid3' / (Path(name).stem + '.json')
    if cached.exists():
        return json.loads(cached.read_text())
    shard = dict(windows={}, events=[], gaps=[], first=None, last=None)
    with (AWID3 / name).open(newline='', encoding='utf-8') as source:
        reader = csv.reader(source)
        header = next(reader)
        ix = {k: header.index(k) for k in ['frame.number', 'frame.time_relative', 'wlan.fc.type',
            'wlan.fc.subtype', 'wlan.ta', 'wlan.ra', 'wlan.fc.protected',
            'wlan.fixed.reason_code', 'Label']}
        for row in reader:
            timestamp = offset + float(row[ix['frame.time_relative']])
            frame = int(row[ix['frame.number']])
            if shard['last'] is not None and frame != shard['last'][0] + 1:
                assert frame > shard['last'][0], 'duplicate or out-of-order frame'
                shard['gaps'].append([shard['last'][1], timestamp])
            shard['first'] = shard['first'] or [frame, timestamp]
            shard['last'] = [frame, timestamp]
            label = row[ix['Label']]
            assert label, 'missing ground-truth label'
            bucket = math.floor(timestamp / 5)
            window = shard['windows'].setdefault(bucket, [0, 0])
            window[0] += 1
            window[1] += label != 'Normal'
            subtype = row[ix['wlan.fc.subtype']]
            if row[ix['wlan.fc.type']] not in ('0', '0.0') or subtype not in ('10', '12', '10.0', '12.0'):
                continue
            reason = row[ix['wlan.fixed.reason_code']]
            shard['events'].append([bucket, f'{timestamp:.6f}', row[ix['wlan.ta']] or '-',
                row[ix['wlan.ra']] or '-', str(int(float(subtype))),
                str(int(float(row[ix['wlan.fc.protected']]))),
                str(int(float(reason))) if reason else '-', int(label != 'Normal')])
    cached.write_text(json.dumps(shard) + '\n')
    return shard


def prepare_awid3(corpus, items, pool):
    """One labeled replay file per AWID3 corpus.

    Windows are selected by evaluate.py's rules (complete, populated, not
    spanning a frame-numbering gap), applied to exact timestamps.
    """
    names = [Path(item['path']).name for item in items]
    offset = awid3_offset(names)
    shards = list(pool.map(awid3_shard, names, [offset] * len(names)))
    windows, gaps, events = {}, [], {}
    previous = None
    for shard in shards:
        if previous is not None and shard['first'][0] != previous[0] + 1:
            gaps.append([previous[1], shard['first'][1]])
        previous = shard['last']
        gaps += shard['gaps']
        for key, (rows, attacks) in shard['windows'].items():
            windows[int(key)] = windows.get(int(key), 0) + attacks
        for event in shard['events']:
            events.setdefault(event[0], []).append(event[1:])
    first = min(s['first'][1] for s in shards)
    last = max(s['last'][1] for s in shards)
    excluded = set()
    for a, b in gaps:
        low, high = sorted((a, b))
        excluded.update(range(math.floor(low / 5), math.floor(high / 5) + 1))
    bins = [i for i in range(math.ceil(first / 5), math.floor(last / 5))
            if i in windows and i not in excluded]
    out = CACHE / f'awid3-{corpus}.tsv'
    with out.open('w') as target:
        for i in bins:
            target.write(f"WINDOW\t{i}\t{int(windows[i] > 0)}\n")
            for event in sorted(events.get(i, []), key=lambda e: float(e[0])):
                target.write('\t'.join(map(str, event)) + '\n')
    print(f'{corpus}: {len(shards)} shards, offset {offset:.6f}, {len(bins)} windows -> {out}')


if __name__ == '__main__':
    if not ZIP.exists():
        raise SystemExit(f'{ZIP} is missing: run benchmarks/additional-wifi-2026-10-14/awid2.py first')
    CACHE.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(ZIP) as archive:
        for name, path, expected in SPLITS:
            with archive.open(path) as source:
                prepare(source, name, expected)
    (CACHE / 'awid3').mkdir(exist_ok=True)
    manifest = json.loads(AWID3_MANIFEST.read_text())
    with concurrent.futures.ProcessPoolExecutor() as pool:
        for corpus, prefix in [('deauth', 'CSV/1.Deauth/'), ('disas', 'CSV/2.Disas/')]:
            prepare_awid3(corpus, [m for m in manifest if m['path'].startswith(prefix)], pool)
