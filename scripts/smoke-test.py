#!/usr/bin/env python3
"""Run a temporary mock server; exercise HTTP, rules, history and restart."""
import http.client, json, os, pathlib, signal, subprocess, sys, tempfile, time
ROOT=pathlib.Path(__file__).resolve().parents[1]
BINARY=pathlib.Path(os.environ.get('EINBLICK_TEST_BINARY', ROOT/('target/release/einblick' if '--release' in sys.argv else 'target/debug/einblick')))
ORIGIN='http://127.0.0.1:19081'

def request(path, method='GET', data=None, cookie=None, csrf=None):
    conn=http.client.HTTPConnection('127.0.0.1',19081,timeout=5)
    headers={'Origin':ORIGIN,'Content-Type':'application/json'}
    if cookie: headers['Cookie']=cookie
    if csrf: headers['X-CSRF-Token']=csrf
    conn.request(method,path,None if data is None else json.dumps(data),headers)
    r=conn.getresponse();body=r.read();headers=dict(r.getheaders());status=r.status;conn.close()
    return status,headers,body

def wait():
    for _ in range(80):
        try:
            if request('/healthz')[0]==200:return
        except (ConnectionError,OSError):pass
        time.sleep(.1)
    raise AssertionError('server did not become healthy')

def login():
    status,headers,body=request('/api/v1/auth/login','POST',{'password':'temporary smoke test password'})
    assert status==200,(status,body)
    return headers['set-cookie'].split(';')[0],json.loads(body)['csrf']

with tempfile.TemporaryDirectory(prefix='einblick-smoke-') as d:
    d=pathlib.Path(d);(d/'password').write_text('temporary smoke test password\n')
    config=d/'config.toml'
    config.write_text(f'''bind = "127.0.0.1:19081"
public_origin = "{ORIGIN}"
mock = true
secure_cookies = false
database = "{d}/history.sqlite"
password_file = "{d}/password"
management_allowlist = ["192.0.2.24/32"]
''')
    proc=None
    try:
        proc=subprocess.Popen([str(BINARY),'--config',str(config)],cwd=ROOT,stdout=subprocess.DEVNULL)
        wait();assert request('/')[0]==200
        assert request('/api/v1/snapshot')[0]==401
        cookie,csrf=login()
        def api(path,method='GET',data=None):
            status,_,body=request('/api/v1'+path,method,data,cookie,csrf)
            assert status==200,(path,status,body)
            return json.loads(body)
        # IPv6 manual block enables blocking; protected source stays passed.
        api('/rules','POST',{'network':'2001:db8::/32','kind':'block','reason':'smoke test','seconds':600})
        time.sleep(2)
        memory=next((line for line in pathlib.Path(f'/proc/{proc.pid}/status').read_text().splitlines() if line.startswith('VmHWM:')), 'RSS unavailable')
        snapshot=api('/snapshot');assert snapshot['blocking'] and snapshot['totals']['dropped']>0,snapshot
        assert any(r['applied'] for r in snapshot['rules']),snapshot['rules']
        api('/mode','POST',{'automatic':True,'blocking':True,'acknowledged':True})
        # Hold a live SSE connection during shutdown to check graceful completion.
        live=http.client.HTTPConnection('127.0.0.1',19081,timeout=5)
        live.request('GET','/api/v1/stream',headers={'Cookie':cookie});response=live.getresponse()
        assert response.status==200
        proc.send_signal(signal.SIGTERM);proc.wait(timeout=8);assert proc.returncode==0
        live.close()
        proc=subprocess.Popen([str(BINARY),'--config',str(config)],cwd=ROOT,stdout=subprocess.DEVNULL)
        wait();cookie,csrf=login();snapshot=api('/snapshot')
        assert snapshot['automatic'] and snapshot['blocking'] and any(r['applied'] for r in snapshot['rules'])
        history=api('/history?from=0');assert history and sum(h['totals']['packets'] for h in history)>0
        assert any(e['kind']=='rule_created' for e in api('/events'))
        api('/emergency-disable','POST');time.sleep(1);assert not api('/snapshot')['blocking']
        proc.send_signal(signal.SIGTERM);proc.wait(timeout=8);assert proc.returncode==0
        print(f'Mock server peak RSS: {memory}')
        print('PASS: HTTP auth, embedded dashboard, IPv6 rule, enforcement mode, SSE shutdown, restart, history, audit, emergency disable')
    finally:
        if proc and proc.poll() is None:proc.kill();proc.wait()
