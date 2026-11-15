#!/usr/bin/env python3
"""Integration tests of the wrapper; Mozilla authentication is stubbed."""
import contextlib
import io
import json
import os
from pathlib import Path
import socket
import sys
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mozvpn
import worker
import auth_helper


class WorkerTests(unittest.TestCase):
    def test_port_override_reserved_before_generated_and_disabled_inventory(self):
        servers = [
            {'countryCode': 'US', 'countryName': 'United States', 'cityCode': 'nyc', 'cityName': 'New York',
             'serverIndex': 0, 'protocolHost': 'one.example', 'protocolPort': 443, 'protocol': 'connect'},
            {'countryCode': 'DE', 'countryName': 'Germany', 'cityCode': 'ber', 'cityName': 'Berlin',
             'serverIndex': 0, 'protocolHost': 'two.example', 'protocolPort': 443, 'protocol': 'connect'},
        ]
        reserved = worker._ORIGINAL_PORT_FOR_LOCATION('US|nyc|0', set())
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'MOZVPS_DATA': d}), \
             patch.object(mozvpn, 'port_for_location', worker._panel_port_for_location):
            Path(d, 'ports.json').write_text(json.dumps({'DE|ber|0': {'port': reserved, 'enabled': False}}))
            engine = mozvpn.BuiltinProxyEngine(SimpleNamespace(listen='127.0.0.1', max_proxies=0), mozvpn.TokenHolder())
            proxies = worker._panel_build_proxies(engine, [], servers)
            inventory = json.loads(Path(d, 'locations.json').read_text())
            self.assertEqual(len(proxies), 1)
            self.assertNotEqual(proxies[0]['port'], reserved)
            self.assertEqual(inventory[1]['port'], reserved)
            self.assertFalse(inventory[1]['enabled'])
            self.assertEqual(inventory[0]['id'], 'US|nyc|0')

    def test_duplicate_port_override_is_rejected(self):
        with tempfile.TemporaryDirectory() as d:
            p = Path(d, 'ports.json')
            p.write_text(json.dumps({'US|nyc|0': {'port': 23456, 'enabled': True},
                                     'DE|ber|0': {'port': 23456, 'enabled': True}}))
            with self.assertRaises(ValueError):
                worker._load_ports(p)

    def test_panel_port_cannot_be_allocated_to_a_location(self):
        server = {'countryCode': 'US', 'countryName': 'US', 'cityCode': 'nyc', 'cityName': 'NY',
                  'serverIndex': 0, 'protocolHost': 'example.test', 'protocolPort': 443, 'protocol': 'connect'}
        default = worker._ORIGINAL_PORT_FOR_LOCATION('US|nyc|0', set())
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'MOZVPS_DATA': d}), \
             patch.object(mozvpn, 'port_for_location', worker._panel_port_for_location):
            Path(d, 'preferences.json').write_text(json.dumps({'panel_port': default}))
            engine = mozvpn.BuiltinProxyEngine(SimpleNamespace(listen='127.0.0.1', max_proxies=0), mozvpn.TokenHolder())
            proxies = worker._panel_build_proxies(engine, [], [server])
            self.assertNotEqual(proxies[0]['port'], default)

    def test_reports_real_listener_binding(self):
        with socket.socket() as temp:
            temp.bind(('127.0.0.1', 0))
            port = temp.getsockname()[1]
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'MOZVPS_DATA': d}), \
             contextlib.redirect_stdout(io.StringIO()):
            location = {'id': 'US|nyc|0', 'label': 'US/NY', 'port': port, 'enabled': True, 'active': False}
            Path(d, 'locations.json').write_text(json.dumps([location]))
            args = SimpleNamespace(listen='127.0.0.1', dns_relay=False)
            engine = mozvpn.BuiltinProxyEngine(args, mozvpn.TokenHolder())
            engine.proxies = [{'port': port, 'label': 'US/NY', 'countryCode': 'US',
                               'host': 'example.test', 'upstreamPort': 443, 'protocol': 'connect'}]
            try:
                worker._panel_start_all(engine)
                self.assertTrue(json.loads(Path(d, 'locations.json').read_text())[0]['active'])
                with socket.create_connection(('127.0.0.1', port), timeout=2) as client:
                    client.sendall(b'\x05\x01\x00')
                    self.assertEqual(client.recv(2), b'\x05\x00')
            finally:
                worker._panel_stop_all(engine)
            self.assertFalse(json.loads(Path(d, 'locations.json').read_text())[0]['active'])

    def test_auth_helper_uses_core_login_and_writes_isolated_session(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'MOZVPS_DATA': d}), \
             patch.object(mozvpn, '_CFG', None), patch.object(mozvpn, 'fxa_login', return_value='aabbccdd') as login, \
             contextlib.redirect_stdout(io.StringIO()):
            result = auth_helper.authenticate({'email': 'test@example.test', 'password': 'demo-secret',
                                               'totp': '123456', 'config_path': str(Path(d, 'temp.json'))})
            self.assertTrue(result['ok'])
            self.assertTrue(login.called)
            record = json.loads(Path(d, 'temp.json').read_text())['accounts']['test@example.test']
            self.assertEqual(record['session_token'], 'aabbccdd')
            self.assertEqual(record['password'], 'demo-secret')
            self.assertFalse(Path(d, 'core.json').exists())

    def test_auth_helper_stores_valid_totp_secret(self):
        with tempfile.TemporaryDirectory() as d, patch.dict(os.environ, {'MOZVPS_DATA': d}), \
             patch.object(mozvpn, '_CFG', None), patch.object(mozvpn, 'fxa_login', return_value='aabbccdd'), \
             contextlib.redirect_stdout(io.StringIO()):
            secret = 'JBSWY3DPEHPK3PXP'
            result = auth_helper.authenticate({'email': 'test@example.test', 'password': 'demo-secret',
                                               'totp': secret, 'config_path': str(Path(d, 'temp.json'))})
            self.assertTrue(result['ok'])
            record = json.loads(Path(d, 'temp.json').read_text())['accounts']['test@example.test']
            self.assertEqual(record['totp_secret'], secret)


if __name__ == '__main__':
    unittest.main()
