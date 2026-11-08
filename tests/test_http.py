import base64
from concurrent.futures import ThreadPoolExecutor
import http.client
import os
from pathlib import Path
import socket
import tempfile
import threading
import time
import unittest
from unittest import mock

import dashboard
import test_dashboard


class HttpIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.patches = [
            mock.patch.object(dashboard, "AUTH_USER", None),
            mock.patch.object(dashboard, "AUTH_PASS", None),
            mock.patch.object(dashboard, "ALLOW_RESTART", False),
            mock.patch.object(dashboard, "collect", return_value=test_dashboard.DashboardSecurityTests().sample_data()),
            mock.patch.object(dashboard, "restart", return_value=True),
        ]
        for patch in self.patches:
            patch.start()
            self.addCleanup(patch.stop)
        self.server = dashboard.BoundedHTTPServer(("127.0.0.1", 0), dashboard.Handler, max_connections=2)
        self.thread = threading.Thread(target=self.server.serve_forever,
                                       kwargs={"poll_interval": 0.05}, daemon=True)
        self.thread.start()
        self.addCleanup(self.close_server)

    def close_server(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)

    def request(self, method, path, body=None, headers=None):
        connection = http.client.HTTPConnection(*self.server.server_address, timeout=3)
        try:
            connection.request(method, path, body, headers or {})
            response = connection.getresponse()
            return response.status, response.read().decode(), dict(response.getheaders())
        finally:
            connection.close()

    def test_readonly_page_and_restart_rejection(self):
        status, body, headers = self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertNotIn('action="/restart"', body)
        self.assertIn("solo lectura", body)
        self.assertEqual(headers["Cache-Control"], "no-store")
        self.assertEqual(self.request("POST", "/restart", "csrf_token=" + dashboard.CSRF_TOKEN)[0], 403)
        dashboard.restart.assert_not_called()

    def test_unknown_route_returns_404(self):
        self.assertEqual(self.request("GET", "/anything")[0], 404)

    def test_untrusted_host_is_rejected(self):
        self.assertEqual(self.request("GET", "/", headers={"Host": "attacker.example"})[0], 403)
        dashboard.ALLOW_RESTART = True
        self.assertEqual(self.request("POST", "/restart", "csrf_token=" + dashboard.CSRF_TOKEN,
                                      {"Host": "attacker.example"})[0], 403)
        dashboard.restart.assert_not_called()

    def test_proxy_authority_only_allows_its_explicit_port(self):
        self.server.allowed_hosts.add("proxy.example:8443")
        self.assertEqual(self.request("GET", "/", headers={"Host": "proxy.example:8443"})[0], 200)
        self.assertEqual(self.request("GET", "/", headers={"Host": "proxy.example:8444"})[0], 403)
        self.assertEqual(self.request("GET", "/", headers={"Host": "proxy.example"})[0], 403)
        dashboard.ALLOW_RESTART = True
        form = "csrf_token=" + dashboard.CSRF_TOKEN
        self.assertEqual(self.request("POST", "/restart", form, {
            "Host": "proxy.example:8443", "Origin": "https://proxy.example:8444",
        })[0], 403)
        self.assertEqual(self.request("POST", "/restart", form, {
            "Host": "proxy.example:8443", "Origin": "https://proxy.example:8443",
        })[0], 302)

    def test_get_restart_never_restarts(self):
        self.assertEqual(self.request("GET", "/restart")[0], 302)
        dashboard.restart.assert_not_called()

    def test_restart_requires_token_and_origin(self):
        dashboard.ALLOW_RESTART = True
        self.assertEqual(self.request("POST", "/restart", "csrf_token=wrong")[0], 403)
        self.assertEqual(self.request("POST", "/restart", "csrf_token=" + dashboard.CSRF_TOKEN,
                                      {"Origin": "http://evil.test"})[0], 403)
        dashboard.restart.assert_not_called()
        self.assertEqual(self.request("POST", "/restart", "csrf_token=" + dashboard.CSRF_TOKEN)[0], 302)
        dashboard.restart.assert_called_once()

    def test_auth_accepts_unicode_and_rejects_missing_auth(self):
        dashboard.AUTH_USER = "dueño"
        dashboard.AUTH_PASS = "contraseña-de-prueba"
        self.assertEqual(self.request("GET", "/")[0], 401)
        value = base64.b64encode((dashboard.AUTH_USER + ":" + dashboard.AUTH_PASS).encode()).decode()
        self.assertEqual(self.request("GET", "/", headers={"Authorization": "Basic " + value})[0], 200)

    def test_capacity_limit_closes_extra_connection(self):
        self.assertTrue(self.server.slots.acquire(False))
        self.assertTrue(self.server.slots.acquire(False))
        try:
            with socket.create_connection(self.server.server_address, timeout=2) as connection:
                connection.settimeout(2)
                self.assertEqual(connection.recv(1), b"")
        finally:
            self.server.slots.release()
            self.server.slots.release()

    def test_slow_header_fragments_release_the_slot_after_total_deadline(self):
        self.server.read_timeout = 0.5
        self.assertTrue(self.server.slots.acquire(False))
        try:
            with socket.create_connection(self.server.server_address, timeout=2) as slow:
                slow.sendall(b"GET / HTTP/1.1\r\nHost:")
                for _ in range(8):
                    time.sleep(0.1)
                    try:
                        slow.sendall(b" ")
                    except (BrokenPipeError, ConnectionResetError):
                        break
                try:
                    status = self.request("GET", "/")[0]
                except (http.client.RemoteDisconnected, ConnectionResetError):
                    status = None
                self.assertEqual(status, 200, "El cliente lento retuvo la plaza")
        finally:
            self.server.slots.release()

    def test_authenticated_body_shares_header_deadline(self):
        self.server.read_timeout = 0.6
        dashboard.ALLOW_RESTART = True
        dashboard.AUTH_USER = "tester"
        dashboard.AUTH_PASS = "local"
        auth = base64.b64encode(b"tester:local").decode()
        form = ("csrf_token=" + dashboard.CSRF_TOKEN).encode()
        request_start = ("POST /restart HTTP/1.1\r\nHost: localhost\r\n"
                         "Authorization: Basic {}\r\n".format(auth)).encode()
        with socket.create_connection(self.server.server_address, timeout=2) as slow:
            slow.sendall(request_start)
            time.sleep(0.35)
            slow.sendall(("Content-Length: {}\r\n\r\n".format(len(form))).encode())
            try:
                for offset in range(0, len(form), 8):
                    slow.sendall(form[offset:offset + 8])
                    time.sleep(0.07)
                response = slow.recv(1024)
            except (BrokenPipeError, ConnectionResetError):
                response = b""
            self.assertNotIn(b"302", response)
        dashboard.restart.assert_not_called()
        self.assertEqual(self.request("GET", "/", headers={"Authorization": "Basic " + auth})[0], 200)

    def test_truncated_body_cannot_authorize_restart(self):
        dashboard.ALLOW_RESTART = True
        form = ("csrf_token=" + dashboard.CSRF_TOKEN).encode()
        request = ("POST /restart HTTP/1.1\r\nHost: localhost\r\n"
                   "Content-Length: {}\r\n\r\n".format(len(form) + 1)).encode()
        with socket.create_connection(self.server.server_address, timeout=2) as client:
            client.sendall(request + form)
            client.shutdown(socket.SHUT_WR)
            self.assertIn(b"400", client.recv(1024))
        dashboard.restart.assert_not_called()

    def test_simultaneous_page_requests_share_a_snapshot(self):
        entered = threading.Event()
        release = threading.Event()
        both = threading.Barrier(2)
        do_get = dashboard.Handler.do_GET

        def observe_requests(handler):
            both.wait(2)
            return do_get(handler)

        def collect_once():
            entered.set()
            if not release.wait(2):
                raise TimeoutError("No se liberó el recolector de pruebas")
            return test_dashboard.DashboardSecurityTests().sample_data()

        dashboard.collect.side_effect = collect_once
        with mock.patch.object(dashboard.Handler, "do_GET", observe_requests), \
                ThreadPoolExecutor(max_workers=2) as executor:
            requests = [executor.submit(self.request, "GET", "/") for _ in range(2)]
            try:
                self.assertTrue(entered.wait(2))
            finally:
                release.set()
            self.assertEqual([request.result()[0] for request in requests], [200, 200])
        dashboard.collect.assert_called_once()

    def test_snapshot_expires_and_restart_invalidates_it_even_on_error(self):
        self.server.snapshot_ttl = 10
        self.assertIn("Instantánea", self.request("GET", "/")[1])
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertEqual(dashboard.collect.call_count, 1)

        self.server.snapshot_ttl = 0
        self.assertEqual(self.request("GET", "/")[0], 200)
        self.assertEqual(dashboard.collect.call_count, 2)
        self.server.snapshot_ttl = 10

        dashboard.ALLOW_RESTART = True
        form = "csrf_token=" + dashboard.CSRF_TOKEN
        for restart_ok, expected_status in ((True, 302), (False, 503)):
            dashboard.collect.reset_mock()
            dashboard.restart.return_value = restart_ok
            self.assertEqual(self.request("POST", "/restart", form)[0], expected_status)
            self.assertEqual(self.request("GET", "/")[0], 200)
            dashboard.collect.assert_called_once()

    def test_credentials_file_requires_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth"
            path.write_text("test-user:password-for-test\n")
            path.chmod(0o600)
            self.assertEqual(dashboard.read_auth_file(str(path)), ("test-user", "password-for-test"))
            path.chmod(0o644)
            with self.assertRaises(ValueError):
                dashboard.read_auth_file(str(path))

    def test_duplicate_csrf_and_invalid_scheme_rejected(self):
        token = dashboard.CSRF_TOKEN
        self.assertFalse(dashboard.csrf_valid("csrf_token={0}&csrf_token={0}".format(token)))
        self.assertFalse(dashboard.same_origin({"Origin": "ftp://pi.local", "Host": "pi.local"}))

    @unittest.skipUnless(hasattr(os, "mkfifo"), "Requiere FIFO de Unix")
    def test_credentials_reject_fifo_without_waiting_for_a_writer(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth"
            os.mkfifo(str(path), 0o600)
            with self.assertRaises(ValueError):
                dashboard.read_auth_file(str(path))

    def test_credentials_reject_symlink(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "auth"
            path.write_text("user:password-for-test\n")
            path.chmod(0o600)
            link = Path(directory) / "link"
            link.symlink_to(path)
            with self.assertRaises(OSError):
                dashboard.read_auth_file(str(link))

    def test_all_untrusted_card_values_are_escaped(self):
        data = test_dashboard.DashboardSecurityTests().sample_data()
        for key in ("timestamp", "gravity", "clients"):
            data[key] = '<img src=x onerror="alert(1)">'
        page = dashboard.render_html(data)
        self.assertNotIn('<img src=x', page)


if __name__ == "__main__":
    unittest.main()
