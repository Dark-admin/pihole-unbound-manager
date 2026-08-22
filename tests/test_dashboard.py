import subprocess
import unittest
from unittest import mock

import dashboard


class DashboardSecurityTests(unittest.TestCase):
    def sample_data(self):
        return {
            "timestamp": "2026-08-21 12:00:00",
            "pihole": True,
            "unbound": True,
            "dns_pihole": "192.0.2.1",
            "dns_unbound": "192.0.2.1",
            "gravity": "123",
            "clients": "4",
            "adlists": ["<script>alert(1)</script>|https://example.test"],
            "verify": {"<b>comprobación</b>": True},
        }

    def test_dynamic_html_is_escaped(self):
        page = dashboard.render_html(self.sample_data())
        self.assertNotIn("<script>alert(1)</script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertNotIn("<b>comprobación</b>", page)
        self.assertIn("&lt;b&gt;comprobación&lt;/b&gt;", page)

    def test_render_includes_csrf_token(self):
        page = dashboard.render_html(self.sample_data())
        self.assertIn('name="csrf_token"', page)
        self.assertIn(dashboard.CSRF_TOKEN, page)

    def test_csrf_requires_exact_token(self):
        good = "csrf_token={}".format(
            dashboard.urllib.parse.quote_plus(dashboard.CSRF_TOKEN))
        self.assertTrue(dashboard.csrf_valid(good))
        self.assertFalse(dashboard.csrf_valid("csrf_token=incorrecto"))
        self.assertFalse(dashboard.csrf_valid(""))

    def test_cross_origin_request_is_rejected(self):
        self.assertTrue(dashboard.same_origin({
            "Origin": "http://pi.local:8080", "Host": "pi.local:8080",
        }))
        self.assertFalse(dashboard.same_origin({
            "Origin": "https://evil.example", "Host": "pi.local:8080",
        }))

    def test_loopback_detection(self):
        self.assertTrue(dashboard.is_loopback_host("127.0.0.1"))
        self.assertTrue(dashboard.is_loopback_host("::1"))
        self.assertTrue(dashboard.is_loopback_host("localhost"))
        self.assertFalse(dashboard.is_loopback_host("0.0.0.0"))
        self.assertFalse(dashboard.is_loopback_host("192.168.1.10"))

    @mock.patch("dashboard.subprocess.run")
    def test_commands_never_use_a_shell(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            ["systemctl"], 0, stdout="active\n", stderr="")
        dashboard.run(["systemctl", "is-active", "unbound"])
        self.assertFalse(run_mock.call_args.kwargs["shell"])


if __name__ == "__main__":
    unittest.main()
