#!/usr/bin/env python3
"""Real file ingestion through authenticated HTTP and the existing mock enforcer."""
import copy
import http.client
import json
import os
from pathlib import Path
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BINARY = Path(os.environ.get('EINBLICK_TEST_BINARY', ROOT / 'target/debug/einblick'))
ORIGIN = 'http://127.0.0.1:19082'

def request(path, method='GET', data=None, cookie=None, csrf=None):
    connection = http.client.HTTPConnection('127.0.0.1', 19082, timeout=10)
    headers = {'Origin': ORIGIN, 'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    connection.request(method, path, json.dumps(data) if data is not None else None, headers)
    response = connection.getresponse()
    status, headers, body = response.status, dict(response.getheaders()), response.read()
    connection.close()
    return status, headers, json.loads(body) if body else None

def until(operation, predicate=lambda value: bool(value), seconds=15):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            value = operation()
            if predicate(value):
                return value
        except (ConnectionError, OSError):
            pass
        time.sleep(.2)
    raise AssertionError('Timed out waiting for service state')

with tempfile.TemporaryDirectory(prefix='einblick-services-') as temporary:
    directory = Path(temporary)
    logs = directory / 'logs'
    logs.mkdir()
    log = logs / 'auth.log'
    log.write_text('Old entries are not ingested on creation\n')
    (directory / 'password').write_text('temporary service smoke password\n')
    (directory / 'config.toml').write_text(f'''bind = "127.0.0.1:19082"
public_origin = "{ORIGIN}"
mock = true
secure_cookies = false
database = "{directory}/history.sqlite"
password_file = "{directory}/password"
management_allowlist = ["192.0.2.24/32"]
[service_logs]
allowed_roots = ["{logs}"]
''')
    process = None
    try:
        def start():
            global process, cookie, csrf
            process = subprocess.Popen([str(BINARY), '--config', str(directory / 'config.toml')], cwd=ROOT, stdout=subprocess.DEVNULL)
            until(lambda: request('/healthz'), lambda value: value[0] == 200)
            status, headers, value = request('/api/v1/auth/login', 'POST', {'password': 'temporary service smoke password'})
            assert status == 200, value
            cookie, csrf = headers['set-cookie'].split(';')[0], value['csrf']
        def api(path, method='GET', value=None):
            status, _, data = request('/api/v1' + path, method, value, cookie, csrf)
            assert status in (200, 204), (path, status, data)
            return data
        def append(ip, count=4):
            with log.open('a') as stream:
                for _ in range(count):
                    stream.write(f'Failed password for invalid user bot from {ip} port 1234 ssh2\n')
        start()
        service = api('/services/templates')[0]['service']
        service['sources'][0]['input'] = {'kind': 'file', 'path': str(log)}
        service['policies'][0].update(threshold=2, window_seconds=4, ban_seconds=30, observe_only=False)
        second_policy = copy.deepcopy(service['policies'][0])
        second_policy.update(id='second-policy', name='Independent longer reason', ban_seconds=60)
        service['policies'].append(second_policy)
        service['observe_only'] = False
        service = api('/services', 'POST', service)
        assert service['observe_only'], 'New service must be observe-only'
        sid = service['id']
        def detail():
            return api(f'/services/{sid}')
        def ready():
            return until(detail, lambda v: v['source_health'].get('ssh-journal', {}).get('status') == 'healthy' and v['source_health']['ssh-journal']['revision'] == service['revision'])
        ready()
        append('192.0.2.40')
        value = until(detail, lambda v: len(v['events']) == 4 and len(v['decisions']) == 2)
        assert all(d['status'] == 'observe_only' and d['rule_id'] is None for d in value['decisions'])
        assert not api('/rules')
        simulation = api('/services/playground', 'POST', {'service': service, 'source_id': 'ssh-journal', 'input': ('Failed password for root from 192.0.2.40 port 44\n' * 300), 'spacing_seconds': 1})
        assert len(simulation['matches']) == 300 and simulation['decisions']
        assert not api('/rules'), 'Simulation mutated enforcement'
        replay = api(f'/services/{sid}/history-simulation', 'POST', service)
        assert replay['simulation']['potentially_preventable'] == 2
        assert replay['simulation']['source_counts']['ssh-journal'] == 4
        service['observe_only'] = False
        service = api(f'/services/{sid}', 'PUT', service)
        api('/mode', 'POST', {'automatic': True, 'blocking': True, 'acknowledged': True})
        until(detail, lambda v: v['source_health'].get('ssh-journal', {}).get('status') == 'warming' and v['source_health']['ssh-journal']['revision'] == service['revision'])
        append('192.0.2.50')
        until(detail, lambda v: any(d['status'] == 'incomplete_evidence' for d in v['decisions']))
        assert not any(r['actor'].startswith('service:') and r['enabled'] for r in api('/rules'))
        ready()
        append('192.0.2.24')
        until(detail, lambda v: any(d['status'] == 'allowlisted' for d in v['decisions']))
        assert not any(r['actor'].startswith('service:') and r['enabled'] and (r['expires'] is None or r['expires'] > time.time()) for r in api('/rules'))
        append('192.0.2.40')
        value = until(detail, lambda v: len([d for d in v['decisions'] if d['rule'] and d['rule']['applied']]) == 2)
        rules = [d['rule'] for d in value['decisions'] if d['rule']]
        assert len({r['actor'] for r in rules}) == 2
        rules.sort(key=lambda rule: rule['expires'])
        # Removing one reason leaves the independent longer rule active.
        api(f'/rules/{rules[0]["id"]}', 'DELETE')
        assert len([r for r in api('/rules') if r['actor'].startswith('service:') and r['enabled'] and (r['expires'] is None or r['expires'] > time.time())]) == 1
        # Durable cursors do not duplicate observations after restart.
        count = len(detail()['events'])
        process.terminate(); process.wait(timeout=10); process = None
        start(); ready()
        assert len(detail()['events']) == count
        assert len([r for r in api('/rules') if r['actor'].startswith('service:') and r['enabled'] and (r['expires'] is None or r['expires'] > time.time())]) == 1
        # Truncation is explicitly incomplete and clears evidence.
        log.write_text('truncated\n')
        until(detail, lambda v: v['source_health']['ssh-journal']['status'] == 'incomplete')
        ready()
        api('/emergency-disable', 'POST')
        assert not api('/snapshot')['blocking']
        service['enabled'] = False
        service = api(f'/services/{sid}', 'PUT', service)
        api(f'/services/{sid}', 'DELETE')
        assert not api('/services')
        assert len([r for r in api('/rules') if r['actor'].startswith('service:') and r['enabled'] and (r['expires'] is None or r['expires'] > time.time())]) == 1
        print('Service smoke passed: real file ingestion, shared parsing, two policies, observe/allowlist/enforcement, replay, independent removal, restart deduplication, truncation, emergency disable, deletion.')
    finally:
        if process is not None:
            process.terminate()
            process.wait(timeout=10)
