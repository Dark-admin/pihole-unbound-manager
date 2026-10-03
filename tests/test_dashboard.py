import subprocess
import unittest
from unittest import mock

import dashboard


class DashboardSecurityTests(unittest.TestCase):
    def sample_data(self):
        return {
            "timestamp": "2026-08-21 12:00:00",
            "engine": "adguard",
            "engine_label": "AdGuard Home",
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
        with mock.patch.object(dashboard, "ALLOW_RESTART", True):
            page = dashboard.render_html(self.sample_data())
        self.assertIn('name="csrf_token"', page)
        self.assertIn(dashboard.CSRF_TOKEN, page)

    def test_render_uses_active_engine_theme(self):
        page = dashboard.render_html(self.sample_data())
        self.assertIn('class="engine-adguard"', page)
        self.assertIn("AdGuard Home", page)

    def test_unknown_engine_falls_back_to_pihole_theme(self):
        data = self.sample_data()
        data["engine"] = "valor-manipulado"
        page = dashboard.render_html(data)
        self.assertIn('class="engine-pihole"', page)

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

    def test_verify_rejects_additional_public_unbound_interface(self):
        def output(command):
            return "127.0.0.1\n0.0.0.0" if "unbound-checkconf" in command else '[ "127.0.0.1#5335" ]'
        with mock.patch("builtins.open", mock.mock_open(read_data="interface: 127.0.0.1\n")), \
                mock.patch.object(dashboard, "run", side_effect=output), \
                mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertFalse(dashboard.verify()["Unbound solo en localhost"])

    def test_verify_rejects_public_fallback_upstream(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="interface: 127.0.0.1\n")), \
                mock.patch.object(dashboard, "run", return_value='[ "127.0.0.1#5335", "1.1.1.1" ]'), \
                mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertFalse(dashboard.verify()["Upstream = Unbound"])

    def test_verify_accepts_only_local_upstream(self):
        def output(command):
            return "127.0.0.1\n::1@5335" if "unbound-checkconf" in command else '[ "127.0.0.1#5335" ]'
        with mock.patch("builtins.open", mock.mock_open(read_data="interface: 127.0.0.1\n")), \
                mock.patch.object(dashboard, "run", side_effect=output), \
                mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertTrue(dashboard.verify()["Upstream = Unbound"])
            self.assertTrue(dashboard.verify()["Unbound solo en localhost"])


if __name__ == "__main__":
    unittest.main()
