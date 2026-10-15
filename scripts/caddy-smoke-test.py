#!/usr/bin/env python3
"""Exercise the actual Caddy polling worker and authenticated API with file logs."""
import http.client
import json
import os
import pathlib
import signal
import socket
import subprocess
import tempfile
import time
import urllib.parse

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(os.environ.get('EINBLICK_TEST_BINARY', ROOT / 'target/debug/einblick'))


def main():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0))
        port = listener.getsockname()[1]
    origin = f'http://127.0.0.1:{port}'
    cookie = None

    def request(path, method='GET', data=None):
        conn = http.client.HTTPConnection('127.0.0.1', port, timeout=5)
        headers = {'Origin': origin, 'Content-Type': 'application/json'}
        if cookie:
            headers['Cookie'] = cookie
        conn.request(method, path, json.dumps(data) if data is not None else None, headers)
        response = conn.getresponse()
        body = response.read()
        result = response.status, dict(response.getheaders()), json.loads(body)
        conn.close()
        return result

    def api(path):
        status, _, body = request('/api/v1' + path)
        assert status == 200, (status, body)
        return body

    def eventually(check):
        for _ in range(100):
            try:
                result = check()
                if result:
                    return result
            except (ConnectionError, OSError):
                pass
            time.sleep(0.1)
        raise AssertionError('Timed out waiting for Caddy ingestion')

    def entry(ip, uri):
        return json.dumps({'logger': 'http.log.access.site', 'ts': time.time(),
                           'request': {'remote_ip': ip, 'client_ip': '198.51.100.123',
                                       'host': 'app.example.com', 'uri': uri, 'method': 'GET',
                                       'headers': {'Cookie': ['do-not-store']}}, 'status': 200})

    def login():
        status, headers, _ = request('/api/v1/auth/login', 'POST', {'password': 'temporary caddy smoke password'})
        assert status == 200
        return headers['set-cookie'].split(';')[0]

    with tempfile.TemporaryDirectory(prefix='einblick-caddy-smoke-') as directory:
        directory = pathlib.Path(directory)
        log = directory / 'access.json'
        log.write_text(entry('192.0.2.1', '/initial?token=secret') + '\n')
        (directory / 'password').write_text('temporary caddy smoke password\n')
        config = directory / 'config.toml'
        config.write_text(f'''bind = "127.0.0.1:{port}"
public_origin = "{origin}"
mock = true
secure_cookies = false
database = "{directory}/history.sqlite"
password_file = "{directory}/password"
[service_logs]
allowed_roots = ["{directory}"]
[caddy]
enabled = true
log_paths = ["{log}"]
poll_seconds = 1
''')
        proc = None

        def start():
            process = subprocess.Popen([str(BINARY), '--config', str(config)], cwd=ROOT,
                                       stdout=subprocess.DEVNULL)
            eventually(lambda: request('/healthz')[0] == 200)
            return process

        def rows(ip='192.0.2.1'):
            return api(f'/sources/{ip}/caddy')['rows']

        try:
            proc = start()
            for path in ['/caddy/status', '/sources/192.0.2.1/caddy']:
                assert request('/api/v1' + path)[0] == 401
            cookie = login()
            eventually(lambda: len(rows()) == 1)
            page = api('/sources/192.0.2.1/caddy')
            assert page['application'] == 'Caddy' and page['attribution'] == 'caddy_access_log'
            assert page['rows'][0]['path'] == '/initial', page
            assert not any(word in json.dumps(page) for word in ['secret', 'do-not-store', '"cursor"'])
            assert not rows('198.51.100.123'), 'Reassigned remote evidence to forwarded client'
            assert page['sources'][0]['last_success']
            for suffix in ['?limit=201', '?from=9&to=8', '?cursor=invalid', '?from=-1']:
                assert request('/api/v1/sources/192.0.2.1/caddy' + suffix)[0] == 400
            assert request('/api/v1/sources/not-ip/caddy')[0] == 400
            with log.open('a') as file:
                file.write('invalid json\n' + entry('2001:db8::1', '/ipv6') + '\n')
                file.write(entry('192.0.2.1', '/second') + '\n')
            eventually(lambda: len(rows()) == 2 and len(rows('2001:db8::1')) == 1)
            page = api('/sources/192.0.2.1/caddy?limit=1')
            following = api('/sources/192.0.2.1/caddy?limit=1&cursor=' + urllib.parse.quote(page['next_cursor']))
            assert page['rows'][0]['id'] != following['rows'][0]['id']
            assert following['next_cursor'] is None
            assert api('/caddy/status')['sources'][0]['skipped'] == 1
            log.rename(directory / 'access.json.1')
            log.write_text(entry('192.0.2.1', '/rotated') + '\n')
            eventually(lambda: len(rows()) == 3)
            log.write_text(entry('192.0.2.1', '/truncated') + '\n')
            eventually(lambda: len(rows()) == 4)
            assert api('/caddy/status')['sources'][0]['gaps'] >= 1
            before = rows()
            proc.send_signal(signal.SIGTERM)
            proc.wait(timeout=8)
            assert proc.returncode == 0
            cookie = None
            proc = start()
            cookie = login()
            time.sleep(1.2)
            assert rows() == before, 'Restart replayed or lost requests'
            with log.open('a') as file:
                file.write(entry('192.0.2.1', '/after-restart') + '\n')
            eventually(lambda: len(rows()) == 5)
            log.unlink()
            eventually(lambda: api('/caddy/status')['sources'][0]['error'])
            assert request('/healthz')[0] == 200, 'Log failure affected capture readiness'
            print('Caddy smoke test passed: polling, attribution, IPv4/IPv6, auth, paging, rotation, truncation, restart, errors')
        finally:
            if proc and proc.poll() is None:
                proc.send_signal(signal.SIGTERM)
                proc.wait(timeout=8)


if __name__ == '__main__':
    main()
