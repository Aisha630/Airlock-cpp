"""Score the unchanged flood detector on AWID2's original CLS-R splits."""
import collections
import csv
import hashlib
import io
import json
import math
from pathlib import Path
import subprocess
import shutil
import urllib.request
import zipfile

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
ZIP = ROOT / '.cache/awid2-benchmark/awidclsr.zip'
BINARY = ROOT / 'build-benchmark/awid3-flood-replay'
# Original 155-column order, verified against published feature names and
# the original AWID notebook linked in the benchmark README.
COLS = {'timestamp': 3, 'type_subtype': 63, 'type': 65, 'subtype': 66,
        'protected': 72, 'ra': 75, 'ta': 77, 'reason': 109, 'label': 154}

def score(source, name):
    windows = {}
    labels = collections.Counter()
    rows = 0
    timestamps = []
    for row in csv.reader(io.TextIOWrapper(source, encoding='utf-8')):
        assert len(row) == 155
        timestamp = float(row[COLS['timestamp']])
        assert math.isfinite(timestamp)
        timestamps.append(timestamp)
        rows += 1
        label = row[COLS['label']]
        assert label in ('normal', 'flooding', 'injection', 'impersonation')
        labels[label] += 1
        bucket = math.floor(timestamp / 5)
        w = windows.setdefault(bucket, dict(rows=0, attacks=0, events=[]))
        w['rows'] += 1
        w['attacks'] += label != 'normal'
        kind, subtype = row[COLS['type']], row[COLS['subtype']]
        if kind != '0' or subtype not in ('10', '12'):
            continue
        assert int(row[COLS['type_subtype']], 16) == int(subtype)
        reason = row[COLS['reason']]
        w['events'].append([timestamp, row[COLS['ta']] if row[COLS['ta']] != '?' else '-',
            row[COLS['ra']] if row[COLS['ra']] != '?' else '-', subtype,
            row[COLS['protected']], str(int(reason, 0)) if reason != '?' else '-'])
    expected = 1795575 if name == 'train' else 575643
    assert rows == expected, (rows, expected)
    first, last = min(timestamps), max(timestamps)
    bins = [i for i in range(math.ceil(first / 5), math.floor(last / 5)) if i in windows]
    replay = ROOT / '.cache/awid2-benchmark' / (name + '.tsv')
    with replay.open('w') as target:
        for i in bins:
            target.write(f"WINDOW\t{i}\t{int(windows[i]['attacks'] > 0)}\n")
            for event in sorted(windows[i]['events']):
                target.write('\t'.join(map(str, event)) + '\n')
    output = subprocess.check_output([str(BINARY), str(replay)], text=True)
    (OUT / ('awid2-' + name + '-output.tsv')).write_text(output)
    records = []
    for line in output.splitlines():
        i, attack, alerts = map(int, line.split('\t'))
        records.append(dict(start_epoch=i * 5, benign=not bool(attack), alerts=alerts,
            rows=windows[i]['rows'], disconnect_frames=len(windows[i]['events'])))
    benign = [r for r in records if r['benign']]
    fp = sum(r['alerts'] > 0 for r in benign)
    result = dict(dataset='AWID2 CLS-R', split=name, packet_rows=rows, labels=dict(labels),
        duration_seconds=last - first, benign_windows=len(benign), false_positives=fp,
        true_negatives=len(benign) - fp, false_positive_rate=fp / len(benign),
        benign_windows_with_disconnects=sum(r['disconnect_frames'] > 0 for r in benign),
        benign_disconnect_frames=sum(r['disconnect_frames'] for r in benign),
        nonbenign_windows=len(records) - len(benign),
        nonbenign_windows_flagged=sum(not r['benign'] and r['alerts'] > 0 for r in records),
        windows=records)
    (OUT / ('awid2-' + name + '-results.json')).write_text(json.dumps(result, indent=2) + '\n')
    if name == 'train':
        (OUT / 'awid2-false-positive-windows.json').write_text(json.dumps(
            [r for r in records if r['benign'] and r['alerts']], indent=2) + '\n')
    print(json.dumps({k:v for k,v in result.items() if k != 'windows'}, indent=2), flush=True)
    return result

if __name__ == '__main__':
    ZIP.parent.mkdir(parents=True, exist_ok=True)
    if not ZIP.exists():
        temporary = ZIP.with_suffix('.part')
        with urllib.request.urlopen('https://www.kaggle.com/api/v1/datasets/download/'
                'zhiqingcui/awidclsr?datasetVersionNumber=1', timeout=120) as source, temporary.open('wb') as target:
            shutil.copyfileobj(source, target)
        temporary.rename(ZIP)
    subprocess.run(['c++', '-std=c++20', '-O2', '-I', str(ROOT / 'src'),
        str(ROOT / 'benchmarks/awid3-2026-10-14/flood_replay.cpp'),
        str(ROOT / 'build-benchmark/libairlock_wifi.a'), '-o', str(BINARY)], check=True)
    with zipfile.ZipFile(ZIP) as archive:
        results = []
        for name, path in [('train', 'AWID-CLS-R-Trn/AWID-CLS-R-Trn/1'),
                           ('test', 'AWID-CLS-R-Tst/AWID-CLS-R-Tst/1')]:
            with archive.open(path) as source:
                results.append(score(source, name))
    evidence = dict(source='https://www.kaggle.com/datasets/zhiqingcui/awidclsr', version=1,
        download_url='https://www.kaggle.com/api/v1/datasets/download/zhiqingcui/awidclsr?datasetVersionNumber=1',
        archive_sha256=hashlib.sha256(ZIP.read_bytes()).hexdigest(), columns=COLS,
        benchmark_script_sha256=hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        analyzer_revision=subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
        replay_binary_sha256=hashlib.sha256(BINARY.read_bytes()).hexdigest(),
        results=[{k:v for k,v in r.items() if k != 'windows'} for r in results])
    evidence['false_positive_rate_combined'] = sum(r['false_positives'] for r in results) / sum(r['benign_windows'] for r in results)
    (OUT / 'awid2-summary.json').write_text(json.dumps(evidence, indent=2) + '\n')
