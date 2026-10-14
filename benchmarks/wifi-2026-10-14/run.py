"""Reproduce the external-capture evaluation; downloads only, no transmissions."""
import concurrent.futures
import hashlib
import json
from pathlib import Path
import subprocess
import struct
import urllib.parse
import urllib.request

ROOT = Path(__file__).resolve().parents[2]
OUT = Path(__file__).resolve().parent
CACHE = ROOT / '.cache' / 'wifi-benchmark'
CACHE.mkdir(parents=True, exist_ok=True)

def fetch(url):
    with urllib.request.urlopen(url, timeout=60) as response:
        return response.read()

def inventory(repo, revision, prefix):
    tree = json.loads(fetch(f'https://api.github.com/repos/{repo}/git/trees/{revision}?recursive=1'))
    return [dict(repo=repo, revision=revision, path=x['path'], blob=x['sha'], size=x['size'])
            for x in tree['tree'] if x['path'].startswith(prefix) and x['path'].endswith(('.pcap', '.pcapng'))]

def record_count(data):
    """Count container records independently of the analyzer's report."""
    count = 0
    if data[:4] == b'\xd4\xc3\xb2\xa1':
        offset = 24
        while offset < len(data):
            length = struct.unpack_from('<I', data, offset + 8)[0]
            offset += 16 + length
            count += 1
    elif data[:4] == b'\x0a\x0d\x0d\x0a':
        offset = 0
        endian = '<'
        while offset < len(data):
            if data[offset:offset + 4] == b'\x0a\x0d\x0d\x0a':
                endian = '<' if data[offset + 8:offset + 12] == b'\x4d\x3c\x2b\x1a' else '>'
            kind, length = struct.unpack_from(endian + 'II', data, offset)
            assert length >= 12
            assert struct.unpack_from(endian + 'I', data, offset + length - 4)[0] == length
            count += kind in (2, 3, 6)
            offset += length
    else:
        raise ValueError('Unexpected capture format')
    assert offset == len(data)
    return count

def evaluate(item):
    url = f"https://raw.githubusercontent.com/{item['repo']}/{item['revision']}/" + urllib.parse.quote(item['path'])
    name = hashlib.sha256(url.encode()).hexdigest()[:16]
    path = CACHE / (name + Path(item['path']).suffix)
    if not path.exists():
        path.write_bytes(fetch(url))
    data = path.read_bytes()
    assert len(data) == item['size']
    assert hashlib.sha1(b'blob ' + str(len(data)).encode() + b'\0' + data).hexdigest() == item['blob']
    report_path = OUT / 'reports' / (name + '.json')
    proc = subprocess.run([str(ROOT / 'build-benchmark' / 'wifi'), 'analyze', str(path), '--json', str(report_path)],
                          capture_output=True, text=True, timeout=120)
    if proc.returncode:
        raise RuntimeError(f"{item['path']}: {proc.stderr}")
    report = json.loads(report_path.read_text())
    flood = [f for f in report['findings'] if f['title'] == 'Deauthentication / disassociation flood']
    return dict(**item, url=url, sha256=hashlib.sha256(data).hexdigest(), report=report_path.name,
                input_records=record_count(data),
                frames=report['capture']['frames'], seconds=report['capture']['duration_seconds'],
                parse_errors=len(report['capture']['parse_errors']), suspect_frames=report['capture']['suspect_frames'],
                deauth_frames=report['frame_subtypes'].get('deauthentication', 0),
                disassoc_frames=report['frame_subtypes'].get('disassociation', 0),
                flood_alerts=len(flood), findings=[f['title'] for f in report['findings']])

if __name__ == '__main__':
    # Pinned source revisions, and all files in the deauth category: no sampling by result.
    manifest = OUT / 'manifest.json'
    if manifest.exists():
        items = json.loads(manifest.read_text())
    else:
        items = inventory('hsngccu/WPA3-dataset', 'e07113327e2012a861f3e273e10ed9b02f0491f4', 'The_WPA3_Dataset/2. Deauth/')
        second = json.loads(fetch('https://api.github.com/repos/neildalal/WPA3-Attacks-IDS/commits/main'))['sha']
        items += inventory('neildalal/WPA3-Attacks-IDS', second, 'Attacks/Deauthentication/')
        manifest.write_text(json.dumps(items, indent=2) + '\n')
    (OUT / 'reports').mkdir(exist_ok=True)
    with concurrent.futures.ThreadPoolExecutor(max_workers=6) as pool:
        results = list(pool.map(evaluate, items))
    (OUT / 'results.json').write_text(json.dumps(results, indent=2) + '\n')
    for repo in sorted({x['repo'] for x in results}):
        rows = [x for x in results if x['repo'] == repo]
        print(repo, json.dumps(dict(files=len(rows), flood_flagged=sum(x['flood_alerts'] > 0 for x in rows),
              frames=sum(x['frames'] for x in rows), seconds=sum(x['seconds'] for x in rows),
              parse_errors=sum(x['parse_errors'] for x in rows), deauth_frames=sum(x['deauth_frames'] for x in rows),
              disassoc_frames=sum(x['disassoc_frames'] for x in rows))))
