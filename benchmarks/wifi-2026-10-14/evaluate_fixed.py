"""Evaluate fixes and measure false alarms on an author-designated benign capture."""
import concurrent.futures
import hashlib
import json
import math
from pathlib import Path
import struct
import subprocess

import run

BASE = Path(__file__).resolve().parent
run.OUT = BASE / 'post-fix'
run.OUT.mkdir(exist_ok=True)
(run.OUT / 'reports').mkdir(exist_ok=True)

if __name__ == '__main__':
    items = json.loads((BASE / 'manifest.json').read_text())
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        attack_results = list(pool.map(run.evaluate, items))
    (run.OUT / 'attack-results.json').write_text(json.dumps(attack_results, indent=2) + '\n')
    for item in attack_results:
        report = json.loads((run.OUT / 'reports' / item['report']).read_text())
        networks = {n['bssid']: n for n in report['networks']}
        for finding in report['findings']:
            if finding['title'] == 'PMKID disclosed in EAPOL message 1':
                ap = finding['detail'].split()[1]
                assert networks[ap]['security'] != 'WPA3-Personal (SAE)'
        if item['repo'] == 'neildalal/WPA3-Attacks-IDS':
            assert 'Possible association disruption: conflicting AP responses' in item['findings']

    benign_items = run.inventory('yigitcftcgl/wpa3-sae-flood-anomaly-detection',
        'c11bc98da2a0dfac4ac8468c076e416cbceff8b1', 'Auth_Normal_Traffic/')
    # This repository uses .cap, which is the ordinary PCAP container.
    if not benign_items:
        tree = json.loads(run.fetch('https://api.github.com/repos/yigitcftcgl/wpa3-sae-flood-anomaly-detection/'
            'git/trees/c11bc98da2a0dfac4ac8468c076e416cbceff8b1?recursive=1'))
        benign_items = [dict(repo='yigitcftcgl/wpa3-sae-flood-anomaly-detection',
            revision=tree['sha'], path=x['path'], blob=x['sha'], size=x['size'])
            for x in tree['tree'] if x['path'].startswith('Auth_Normal_Traffic/') and x['path'].endswith('.cap')]
    assert len(benign_items) == 1
    (run.OUT / 'benign-manifest.json').write_text(json.dumps(benign_items, indent=2) + '\n')
    benign = run.evaluate(benign_items[0])
    whole = json.loads((run.OUT / 'reports' / benign['report']).read_text())
    alarms = lambda report: [f for f in report['findings'] if f['severity'] != 'info']
    false_captures = int(bool(alarms(whole)))
    file_name = hashlib.sha256(benign['url'].encode()).hexdigest()[:16] + '.cap'
    data = (run.CACHE / file_name).read_bytes()
    assert data[:4] == b'\xd4\xc3\xb2\xa1'
    records = []
    offset = 24
    while offset < len(data):
        seconds, micros, size, _ = struct.unpack_from('<IIII', data, offset)
        records.append((seconds + micros / 1e6, data[offset:offset + 16 + size]))
        offset += 16 + size
    assert len(records) == benign['input_records']
    start = records[0][0]
    # Fixed nonoverlapping five-second windows chosen before examining their outputs.
    # Exclude only the final partial interval; all full windows are evaluated.
    full_windows = math.floor((records[-1][0] - start) / 5.0)
    windows = []
    for i in range(full_windows):
        selected = [b for timestamp, b in records if start + i * 5 <= timestamp < start + (i + 1) * 5]
        capture_path = run.CACHE / f'benign-window-{i:03d}.pcap'
        capture_path.write_bytes(data[:24] + b''.join(selected))
        report_path = run.OUT / 'reports' / f'benign-window-{i:03d}.json'
        subprocess.run([str(run.ROOT / 'build-benchmark' / 'wifi'), 'analyze', str(capture_path),
                        '--json', str(report_path)], check=True, stdout=subprocess.DEVNULL)
        report = json.loads(report_path.read_text())
        windows.append(dict(window=i, start_seconds=i * 5, end_seconds=(i + 1) * 5,
            input_records=len(selected), frames=report['capture']['frames'],
            parse_errors=len(report['capture']['parse_errors']),
            networks=len(report['networks']), alarms=len(alarms(report)),
            findings=report['findings']))
    false_windows = sum(x['alarms'] > 0 for x in windows)
    summary = dict(benign_capture=benign, window_seconds=5,
        capture_false_positives=false_captures, capture_true_negatives=1 - false_captures,
        capture_false_positive_rate=false_captures,
        full_windows=full_windows, window_false_positives=false_windows,
        window_true_negatives=full_windows - false_windows,
        window_false_positive_rate=false_windows / full_windows,
        window_results=windows,
        attack_files=len(attack_results),
        attack_input_records=sum(x['input_records'] for x in attack_results),
        attack_parse_errors=sum(x['parse_errors'] for x in attack_results),
        attack_files_with_disruption_alert=sum('Possible association disruption: conflicting AP responses'
                                             in x['findings'] for x in attack_results))
    (run.OUT / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({k: v for k, v in summary.items() if k not in ('window_results', 'benign_capture')}, indent=2))
    print('benign frames:', benign['frames'], 'seconds:', benign['seconds'],
          'whole-capture findings:', len(whole['findings']))
    patch = subprocess.check_output(['git', 'diff', '--', 'src', 'tests'])
    (run.OUT / 'source-changes.patch').write_bytes(patch)
    (run.OUT / 'metadata.json').write_text(json.dumps(dict(
        analyzer_base_revision=subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip(),
        source_diff_sha256=hashlib.sha256(patch).hexdigest(),
        binary_sha256=hashlib.sha256((run.ROOT / 'build-benchmark' / 'wifi').read_bytes()).hexdigest(),
        run_command='python3 benchmarks/wifi-2026-10-14/evaluate_fixed.py'), indent=2) + '\n')
