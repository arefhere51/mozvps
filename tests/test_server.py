#!/usr/bin/env python3
"""Offline integration tests; no Mozilla credentials or outbound requests are used."""
import http.cookiejar
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import time
import unittest
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parents[1]


def unused_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


class PanelTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.data = Path(self.temp.name)
        self.port = unused_port()
        (self.data / 'preferences.json').write_text(json.dumps({'panel_port': self.port, 'desired': False}))
        env = dict(os.environ, MOZVPS_DATA=str(self.data), MOZVPS_PANEL_HOST='127.0.0.1')
        self.p = subprocess.Popen([sys.executable, str(ROOT / 'server.py')], env=env,
                                  stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        for _ in range(100):
            if self.p.poll() is not None:
                self.fail('server exited during startup')
            try:
                self.req('/api/session')
                break
            except (OSError, urllib.error.URLError):
                time.sleep(.05)
        else:
            self.fail('server did not start')
        self.csrf = None

    def tearDown(self):
        self.p.terminate()
        try:
            self.p.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.p.kill()
            self.p.wait()
        self.temp.cleanup()

    def req(self, path, method='GET', payload=None, csrf=None):
        data = None if payload is None else json.dumps(payload).encode()
        headers = {'Content-Type': 'application/json'} if data is not None else {}
        if csrf:
            headers['X-CSRF-Token'] = csrf
        request = urllib.request.Request(f'http://127.0.0.1:{self.port}{path}', data=data,
                                         headers=headers, method=method)
        try:
            with self.opener.open(request, timeout=5) as r:
                return r.status, json.loads(r.read())
        except urllib.error.HTTPError as e:
            return e.code, json.loads(e.read())

    def login(self, password='admin'):
        status, body = self.req('/api/login', 'POST', {'password': password})
        self.assertEqual(status, 200, body)
        self.csrf = body['csrf']
        return body

    def test_session_password_csrf_and_logout(self):
        self.assertEqual(self.req('/api/status')[0], 401)
        self.assertEqual(self.req('/api/login', 'POST', {'password': 'wrong'})[0], 401)
        self.assertTrue(self.login()['default_password'])
        self.assertEqual(self.req('/api/status')[1]['service'], 'stopped')
        self.assertEqual(self.req('/api/service', 'POST', {'action': 'start'})[0], 403)
        status, _ = self.req('/api/password', 'POST', {'current_password': 'admin',
                                                       'new_password': 'new-secret-123'}, self.csrf)
        self.assertEqual(status, 200)
        self.assertEqual(self.req('/api/status')[0], 401)
        self.assertEqual(self.req('/api/login', 'POST', {'password': 'admin'})[0], 401)
        self.assertFalse(self.login('new-secret-123')['default_password'])
        self.assertEqual(self.req('/api/logout', 'POST', {}, self.csrf)[0], 200)
        self.assertEqual(self.req('/api/status')[0], 401)
        self.assertNotIn('new-secret-123', (self.data / 'panel-auth.json').read_text())

    def test_location_validation_and_persistence(self):
        self.login()
        loc = [{'id': 'US|nyc|0', 'label': 'USA/New York', 'port': 21000, 'enabled': True},
               {'id': 'DE|ber|0', 'label': 'Germany/Berlin', 'port': 21001, 'enabled': True}]
        (self.data / 'locations.json').write_text(json.dumps(loc))
        duplicate = [dict(loc[0], port=23000), dict(loc[1], port=23000)]
        self.assertEqual(self.req('/api/locations', 'POST', {'locations': duplicate}, self.csrf)[0], 400)
        unknown = [dict(loc[0], id='fake')]
        self.assertEqual(self.req('/api/locations', 'POST', {'locations': unknown}, self.csrf)[0], 400)
        valid = [dict(loc[0], port=23000, enabled=False), dict(loc[1], port=23001)]
        self.assertEqual(self.req('/api/locations', 'POST', {'locations': valid}, self.csrf)[0], 200)
        saved = json.loads((self.data / 'ports.json').read_text())
        self.assertEqual(saved['US|nyc|0'], {'port': 23000, 'enabled': False})
        self.assertEqual(saved['DE|ber|0']['port'], 23001)

    def test_panel_port_rebind(self):
        self.login()
        newport = unused_port()
        status, body = self.req('/api/panel-port', 'POST', {'port': newport}, self.csrf)
        self.assertEqual(status, 200, body)
        self.port = newport
        self.assertEqual(self.req('/api/status')[0], 200)
        self.assertEqual(json.loads((self.data / 'preferences.json').read_text())['panel_port'], newport)

    def test_mozilla_proxy_toggle_persists_and_is_returned_in_status(self):
        self.login()
        status, body = self.req('/api/mozilla-proxy', 'POST',
                                {'enabled': True, 'host': '127.0.0.1', 'port': 18080}, self.csrf)
        self.assertEqual(status, 200, body)
        status, body = self.req('/api/status')
        self.assertEqual(status, 200)
        self.assertEqual(body['mozilla_proxy'], {'enabled': True, 'host': '127.0.0.1', 'port': 18080})
        saved = json.loads((self.data / 'preferences.json').read_text())
        self.assertTrue(saved['mozilla_proxy_enabled'])
        self.assertEqual(saved['mozilla_proxy_port'], 18080)
        status, _ = self.req('/api/mozilla-proxy', 'POST',
                             {'enabled': False, 'host': '127.0.0.1', 'port': 18080}, self.csrf)
        self.assertEqual(status, 200)


if __name__ == '__main__':
    unittest.main()
