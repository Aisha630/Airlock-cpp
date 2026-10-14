"""Score Airlock's actual C++ flood detector against labeled AWID3 metadata."""
import collections
import concurrent.futures
import csv
import hashlib
import json
import math
from pathlib import Path
import shutil
import subprocess
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
CACHE = ROOT / '.cache' / 'awid3-benchmark'
CACHE.mkdir(parents=True, exist_ok=True)
REFERENCE = 'suumia/awid3-dataset'
VERSION = 1
GROUPS = ['CSV/1.Deauth/', 'CSV/2.Disas/']

def get_json(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return json.load(response)

def inventory():
    manifest = OUT / 'manifest.json'
    if manifest.exists():
        return json.loads(manifest.read_text())
    all_files = []
    token = None
    while True:
        url = f'https://www.kaggle.com/api/v1/datasets/list/{REFERENCE}?pageSize=1000'
        if token:
            url += '&pageToken=' + urllib.parse.quote(token)
        page = get_json(url)
        all_files += page['datasetFiles']
        token = page.get('nextPageToken')
        if not token:
            break
    items = [dict(path=x['name'], bytes=x['totalBytes']) for x in all_files
             if any(x['name'].startswith(g) for g in GROUPS) and x['name'].endswith('.csv')]
    items.sort(key=lambda x: (x['path'].split('/')[1], int(Path(x['path']).stem.rsplit('_', 1)[1])))
    manifest.write_text(json.dumps(items, indent=2) + '\n')
    return items

def process(item):
    path = CACHE / Path(item['path']).name
    url = f'https://www.kaggle.com/api/v1/datasets/download/{REFERENCE}/' + urllib.parse.quote(item['path'], safe='') + '?datasetVersionNumber=1'
    if not path.exists():
        temporary = path.with_suffix('.part')
        with urllib.request.urlopen(url, timeout=120) as source, temporary.open('wb') as target:
            shutil.copyfileobj(source, target)
        assert temporary.stat().st_size == item['bytes']
        temporary.rename(path)
    assert path.stat().st_size == item['bytes']
    digest = hashlib.sha256()
    with path.open('rb') as source:
        while chunk := source.read(1024 * 1024):
            digest.update(chunk)
    reduced_path = path.with_suffix('.reduced-v2.json')
    if reduced_path.exists():
        reduced = json.loads(reduced_path.read_text())
        assert reduced['sha256'] == digest.hexdigest()
        return reduced
    reduced = dict(**item, url=url, sha256=digest.hexdigest(), labels={}, windows={}, events=[],
                   first_timestamp=None, last_timestamp=None, first_frame=None, last_frame=None, rows=0,
                   numbering_gaps=[])
    labels = collections.Counter()
    with path.open(newline='', encoding='utf-8') as source:
        reader = csv.reader(source)
        header = next(reader)
        ix = {k: header.index(k) for k in ['frame.number', 'frame.time_epoch', 'wlan.fc.type',
            'wlan.fc.subtype', 'wlan.ta', 'wlan.ra', 'wlan.fc.protected', 'wlan.fixed.reason_code', 'Label']}
        for row in reader:
            if len(row) != len(header):
                raise ValueError(f'Malformed CSV row in {path}: {len(row)} columns')
            timestamp = float(row[ix['frame.time_epoch']])
            frame = int(row[ix['frame.number']])
            if not math.isfinite(timestamp):
                raise ValueError('Invalid timestamp')
            if reduced['first_timestamp'] is None:
                reduced['first_timestamp'], reduced['first_frame'] = timestamp, frame
            if reduced['last_frame'] is not None and frame != reduced['last_frame'] + 1:
                if frame <= reduced['last_frame']:
                    raise ValueError(f'Duplicate or out-of-order frame in {path}: {frame}')
                reduced['numbering_gaps'].append(dict(previous_frame=reduced['last_frame'],
                    next_frame=frame, previous_timestamp=reduced['last_timestamp'], next_timestamp=timestamp,
                    missing_records=frame - reduced['last_frame'] - 1))
            reduced['last_timestamp'], reduced['last_frame'] = timestamp, frame
            reduced['rows'] += 1
            label = row[ix['Label']]
            if not label:
                raise ValueError('Missing ground-truth label')
            labels[label] += 1
            # Epoch-aligned bins allow shards to combine without choosing boundaries by result.
            bucket = math.floor(timestamp / 5)
            window = reduced['windows'].setdefault(str(bucket), dict(rows=0, attacks=0))
            window['rows'] += 1
            window['attacks'] += label != 'Normal'
            frame_type, subtype = row[ix['wlan.fc.type']], row[ix['wlan.fc.subtype']]
            if frame_type not in ('0', '0.0') or subtype not in ('10', '12', '10.0', '12.0'):
                continue
            reason = row[ix['wlan.fixed.reason_code']]
            reduced['events'].append([bucket, timestamp, row[ix['wlan.ta']] or '-',
                row[ix['wlan.ra']] or '-', str(int(float(subtype))),
                str(int(float(row[ix['wlan.fc.protected']]))), str(int(float(reason))) if reason else '-'])
    reduced['labels'] = dict(labels)
    reduced_path.write_text(json.dumps(reduced) + '\n')
    print('processed', item['path'], reduced['rows'], dict(labels), flush=True)
    return reduced

def evaluate_corpus(name, parts, binary):
    windows = {}
    events = collections.defaultdict(list)
    labels = collections.Counter()
    previous = None
    previous_timestamp = None
    gaps = []
    for part in parts:
        if previous is not None:
            assert part['first_frame'] > previous
            if part['first_frame'] != previous + 1:
                gaps.append(dict(previous_frame=previous, next_frame=part['first_frame'],
                    previous_timestamp=previous_timestamp, next_timestamp=part['first_timestamp'],
                    missing_records=part['first_frame'] - previous - 1))
        previous = part['last_frame']
        previous_timestamp = part['last_timestamp']
        gaps += part['numbering_gaps']
        labels.update(part['labels'])
        for key, value in part['windows'].items():
            window = windows.setdefault(int(key), dict(rows=0, attacks=0))
            window['rows'] += value['rows']
            window['attacks'] += value['attacks']
        for event in part['events']:
            events[event[0]].append(event[1:])
    first = min(p['first_timestamp'] for p in parts)
    last = max(p['last_timestamp'] for p in parts)
    first_full = math.ceil(first / 5)
    last_full = math.floor(last / 5) - 1
    # Include every complete, populated bin; all packets remain in their original bins.
    excluded = set()
    for gap in gaps:
        low, high = sorted((gap['previous_timestamp'], gap['next_timestamp']))
        excluded.update(range(math.floor(low / 5), math.floor(high / 5) + 1))
    populated = [i for i in range(first_full, last_full + 1) if i in windows]
    bins = [i for i in populated if i not in excluded]
    replay = CACHE / (name + '.tsv')
    with replay.open('w') as target:
        for bucket in bins:
            target.write(f"WINDOW\t{bucket}\t{int(windows[bucket]['attacks'] > 0)}\n")
            for event in sorted(events[bucket], key=lambda x: x[0]):
                target.write('\t'.join(map(str, event)) + '\n')
    output = subprocess.check_output([str(binary), str(replay)], text=True)
    (OUT / (name + '-detector-output.tsv')).write_text(output)
    counts = collections.Counter()
    records = []
    for line in output.splitlines():
        bucket, attack, alerts = map(int, line.split('\t'))
        predicted = alerts > 0
        outcome = ('TP' if predicted else 'FN') if attack else ('FP' if predicted else 'TN')
        counts[outcome] += 1
        records.append(dict(start_epoch=bucket * 5, end_epoch=(bucket + 1) * 5,
            attack_labeled=bool(attack), flood_findings=alerts, outcome=outcome,
            deauth_class_frames=len(events[bucket]), **windows[bucket]))
    assert len(records) == len(bins)
    result = dict(corpus=name, files=len(parts), total_rows=sum(p['rows'] for p in parts),
        label_counts=dict(labels), duration_seconds=last - first, complete_windows=len(bins),
        numbering_gaps=gaps, missing_records=sum(g['missing_records'] for g in gaps),
        excluded_windows_for_gaps=len(set(populated) & excluded),
        benign_windows_with_disconnects=sum(not r['attack_labeled'] and r['deauth_class_frames'] > 0 for r in records),
        confusion={k: counts[k] for k in ('FP', 'TN', 'TP', 'FN')},
        false_positive_rate=counts['FP'] / (counts['FP'] + counts['TN']), windows=records)
    (OUT / (name + '-results.json')).write_text(json.dumps(result, indent=2) + '\n')
    return result

if __name__ == '__main__':
    items = inventory()
    with concurrent.futures.ThreadPoolExecutor(max_workers=12) as pool:
        parts = list(pool.map(process, items))
    (OUT / 'download-evidence.json').write_text(json.dumps([
        {k: v for k, v in part.items() if k not in ('events', 'windows')} for part in parts], indent=2) + '\n')
    binary = ROOT / 'build-benchmark' / 'awid3-flood-replay'
    subprocess.run(['c++', '-std=c++20', '-O2', '-I', str(ROOT / 'src'), str(OUT / 'flood_replay.cpp'),
        str(ROOT / 'build-benchmark' / 'libairlock_wifi.a'), '-o', str(binary)], check=True)
    results = [evaluate_corpus(g.split('/')[1], [p for p in parts if p['path'].startswith(g)], binary) for g in GROUPS]
    counts = {key: sum(r['confusion'][key] for r in results) for key in ('FP', 'TN', 'TP', 'FN')}
    summary = dict(benchmark='AWID3, Deauth and Disas corpora, labeled CSV metadata replay',
        source=REFERENCE, version=VERSION, window_seconds=5, rows=sum(r['total_rows'] for r in results),
        confusion=counts, false_positive_rate=counts['FP'] / (counts['FP'] + counts['TN']),
        corpora=[{k: v for k, v in r.items() if k != 'windows'} for r in results],
        binary_sha256=hashlib.sha256(binary.read_bytes()).hexdigest())
    (OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
