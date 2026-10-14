#!/usr/bin/env python3
"""Exercise the real system resolver and mock firewall in a private mount namespace.

Run after cargo build:
sudo unshare --mount --propagation private -- python3 scripts/management-dns-smoke-test.py
Only this namespace gets a temporary /etc/hosts; no DNS server or host setting changes.
"""
import http.client
import json
import os
import pathlib
import signal
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
BINARY = pathlib.Path(os.environ.get('EINBLICK_TEST_BINARY', ROOT / 'target/debug/einblick'))
HOSTNAME = 'home.management.invalid'
ORIGIN = 'http://127.0.0.1:19084'


def request(path, method='GET', data=None, cookie=None, csrf=None):
    conn = http.client.HTTPConnection('127.0.0.1', 19084, timeout=5)
    headers = {'Origin': ORIGIN, 'Content-Type': 'application/json'}
    if cookie:
        headers['Cookie'] = cookie
    if csrf:
        headers['X-CSRF-Token'] = csrf
    conn.request(method, path, None if data is None else json.dumps(data), headers)
    response = conn.getresponse()
    body = response.read()
    result = (response.status, dict(response.getheaders()), json.loads(body) if body else None)
    conn.close()
    return result


def until(get, predicate, seconds=18):
    end = time.monotonic() + seconds
    latest = None
    while time.monotonic() < end:
        latest = get()
        if predicate(latest):
            return latest
        time.sleep(.2)
    raise AssertionError(f'timed out waiting for DNS state: {latest}')


def main():
    if os.geteuid() != 0 or os.readlink('/proc/self/ns/mnt') == os.readlink('/proc/1/ns/mnt'):
        raise SystemExit('Run as root inside unshare --mount --propagation private, as documented above.')
    # Make bind mounts private even if invoked from another isolated namespace.
    subprocess.run(['mount', '--make-rprivate', '/'], check=True)
    with tempfile.TemporaryDirectory(prefix='einblick-management-dns-') as directory:
        directory = pathlib.Path(directory)
        hosts = directory / 'hosts'

        def addresses(ips):
            hosts.write_text('127.0.0.1 localhost\n::1 localhost\n' + ''.join(
                f'{ip} {HOSTNAME} {HOSTNAME}.\n' for ip in ips))

        addresses(['192.0.2.24', '2001:db8::12'])
        subprocess.run(['mount', '--bind', str(hosts), '/etc/hosts'], check=True)
        process = None
        try:
            (directory / 'password').write_text('management DNS smoke test password\n')
            config = directory / 'config.toml'
            config.write_text(f'''bind = "127.0.0.1:19084"
public_origin = "{ORIGIN}"
mock = true
secure_cookies = false
database = "{directory}/history.sqlite"
password_file = "{directory}/password"
management_allowlist = ["{HOSTNAME}"]
management_dns_refresh_seconds = 10
management_dns_stale_seconds = 20
''')
            process = subprocess.Popen([str(BINARY), '--config', str(config)], cwd=ROOT,
                                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            for _ in range(80):
                try:
                    if request('/healthz')[0] == 200:
                        break
                except OSError:
                    pass
                assert process.poll() is None, 'server exited at startup'
                time.sleep(.1)
            else:
                raise AssertionError('server did not start')
            status, headers, body = request('/api/v1/auth/login', 'POST',
                                           {'password': 'management DNS smoke test password'})
            assert status == 200, body
            cookie = headers['set-cookie'].split(';')[0]
            csrf = body['csrf']

            def api(path, method='GET', data=None):
                status, _, body = request('/api/v1' + path, method, data, cookie, csrf)
                assert status == 200, (status, path, body)
                return body

            def snapshot():
                return api('/snapshot')

            def counts(ip, name):
                return sum(row[name] for row in api(f'/sources/{ip}/traffic')['rows'])

            original = ['192.0.2.24/32', '2001:db8::12/128']
            assert sorted(snapshot()['management_allowlist']) == original
            assert snapshot()['health']['management_dns']['ready']
            for network in ['192.0.2.0/24', '2001:db8::/32', '198.51.100.0/24']:
                api('/rules', 'POST', {'network': network, 'kind': 'block',
                                      'reason': 'DNS override smoke test', 'seconds': None})
            api('/mode', 'POST', {'automatic': True, 'blocking': True, 'acknowledged': True})
            until(lambda: counts('192.0.2.24', 'passed'), lambda count: count > 0)
            until(lambda: counts('2001:db8::12', 'passed'), lambda count: count > 0)
            assert counts('192.0.2.24', 'dropped') == 0
            assert counts('2001:db8::12', 'dropped') == 0
            passed_before = counts('198.51.100.9', 'passed')
            dropped_before = counts('192.0.2.24', 'dropped')
            print('Startup hostname resolution and IPv4/IPv6 ban overrides passed.', flush=True)

            addresses(['198.51.100.9'])
            until(snapshot, lambda s: s['management_allowlist'] == ['198.51.100.9/32'])
            until(lambda: counts('198.51.100.9', 'passed'), lambda count: count > passed_before)
            until(lambda: counts('192.0.2.24', 'dropped'), lambda count: count > dropped_before)
            session = api('/auth/session')
            assert session['management_allowlist'] == ['198.51.100.9/32']
            assert session['management_allowlist_configured'] == [HOSTNAME]
            print('Runtime address replacement and session metadata passed.', flush=True)

            addresses([])
            failed = until(snapshot, lambda s: not s['health']['management_dns']['ready'])
            assert failed['management_allowlist'] == ['198.51.100.9/32']
            assert failed['automatic'] and failed['blocking']
            status, _, _ = request('/api/v1/mode', 'POST',
                                   {'automatic': True, 'blocking': True, 'acknowledged': True}, cookie, csrf)
            assert status != 200, 'automatic activation accepted an unresolved hostname'
            until(snapshot, lambda s: not s['management_allowlist'], seconds=25)
            print('Lookup failure, bounded grace, and stale-address expiry passed.', flush=True)

            addresses(['192.0.2.24', '2001:db8::12'])
            recovered = until(snapshot, lambda s: s['health']['management_dns']['ready'])
            assert sorted(recovered['management_allowlist']) == original
            assert recovered['automatic'] and recovered['blocking']
            assert len([rule for rule in recovered['rules'] if rule['actor'] == 'admin']) == 3
            api('/emergency-disable', 'POST')
            print('Management DNS smoke passed: recovery without restart and retained firewall rules.', flush=True)
        finally:
            if process and process.poll() is None:
                process.send_signal(signal.SIGTERM)
                try:
                    process.wait(timeout=10)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            subprocess.run(['umount', '/etc/hosts'], check=True)


if __name__ == '__main__':
    main()
