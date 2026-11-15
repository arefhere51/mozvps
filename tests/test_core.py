#!/usr/bin/env python3
"""Offline socket-level tests of the unchanged upstream core."""
import socket
import sys
import threading
from pathlib import Path
from types import SimpleNamespace
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import mozvpn


def recv_exact(sock, n):
    data = b''
    while len(data) < n:
        part = sock.recv(n - len(data))
        if not part:
            break
        data += part
    return data


class CoreTests(unittest.TestCase):
    def test_quota_rotation_selects_cached_nonempty_account(self):
        accounts = {
            'current@example.com': {'session_token': 'aaaa', 'quota_remaining': 0},
            'empty@example.com': {'session_token': 'bbbb', 'quota_remaining': 0},
            'no-session@example.com': {'quota_remaining': 999999},
            'next@example.com': {'session_token': 'cccc', 'quota_remaining': 500},
            'smaller@example.com': {'session_token': 'dddd', 'quota_remaining': 100},
        }
        with patch.object(mozvpn, 'cfg_accounts', return_value=accounts):
            self.assertEqual(mozvpn.pick_rotation_account('current@example.com'), ('next@example.com', 500))
            accounts['next@example.com']['quota_remaining'] = 0
            self.assertEqual(mozvpn.pick_rotation_account('current@example.com'), ('smaller@example.com', 100))

    def test_socks5_domain_connect_and_bidirectional_bytes(self):
        client, incoming = socket.socketpair()
        upstream, fake_egress = socket.socketpair()
        client.settimeout(3)
        fake_egress.settimeout(3)
        holder = mozvpn.TokenHolder()
        holder.set('test-token')
        engine = mozvpn.BuiltinProxyEngine(SimpleNamespace(listen='127.0.0.1'), holder)
        engine._open_upstream = lambda proxy: upstream
        worker = threading.Thread(target=engine._handle_client_socks,
                                  args=(incoming, {'host': 'fake-egress'}), daemon=True)
        worker.start()
        try:
            client.sendall(b'\x05\x01\x00')
            self.assertEqual(recv_exact(client, 2), b'\x05\x00')
            domain = b'example.org'
            client.sendall(b'\x05\x01\x00\x03' + bytes([len(domain)]) + domain + (443).to_bytes(2, 'big'))
            request = b''
            while b'\r\n\r\n' not in request:
                request += fake_egress.recv(4096)
            self.assertIn(b'CONNECT example.org:443 HTTP/1.1', request)
            self.assertIn(b'Proxy-Authorization: Bearer test-token', request)
            fake_egress.sendall(b'HTTP/1.1 200 OK\r\n\r\n')
            self.assertEqual(recv_exact(client, 10)[:2], b'\x05\x00')
            client.sendall(b'hello')
            self.assertEqual(recv_exact(fake_egress, 5), b'hello')
            fake_egress.sendall(b'world')
            self.assertEqual(recv_exact(client, 5), b'world')
        finally:
            client.close()
            fake_egress.close()
            worker.join(timeout=3)

    def test_socks5_rejects_udp_associate(self):
        client, incoming = socket.socketpair()
        client.settimeout(3)
        holder = mozvpn.TokenHolder()
        holder.set('test-token')
        engine = mozvpn.BuiltinProxyEngine(SimpleNamespace(listen='127.0.0.1'), holder)
        worker = threading.Thread(target=engine._handle_client_socks,
                                  args=(incoming, {'host': 'fake-egress'}), daemon=True)
        worker.start()
        try:
            client.sendall(b'\x05\x01\x00')
            self.assertEqual(recv_exact(client, 2), b'\x05\x00')
            client.sendall(b'\x05\x03\x00\x01')
            self.assertEqual(recv_exact(client, 10)[:2], b'\x05\x07')
        finally:
            client.close()
            worker.join(timeout=3)


if __name__ == '__main__':
    unittest.main()
