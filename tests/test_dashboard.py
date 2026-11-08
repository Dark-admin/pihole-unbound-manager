from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import subprocess
import tempfile
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

    def test_pihole_cli_failure_leaves_toml_upstreams_unverified(self):
        fixtures = (
            '[dns]\n# upstreams = ["127.0.0.1#5335"]\nupstreams = []\n',
            "[dns]\nupstreams = [\"127.0.0.1#5335\", '1.1.1.1']\n",
        )
        for toml in fixtures:
            with self.subTest(toml=toml), mock.patch("builtins.open", mock.mock_open(read_data=toml)), \
                    mock.patch.object(dashboard, "run", return_value=""), \
                    mock.patch.object(dashboard, "engine", return_value="pihole"):
                self.assertIsNone(dashboard.verify()["Upstream = Unbound"])

    @mock.patch("dashboard.subprocess.run")
    def test_failed_command_output_is_not_used_for_checks(self, run_mock):
        run_mock.return_value = subprocess.CompletedProcess(
            ["pihole-FTL"], 1, stdout='["127.0.0.1#5335"]\n', stderr="error")
        with mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertIsNone(dashboard.verify()["Upstream = Unbound"])

    def test_adguard_does_not_show_file_or_fallback_as_local(self):
        fixtures = (
            ('  upstream_dns_file: /tmp/upstreams.txt\n  fallback_dns: []\n', None),
            ('  upstream_dns_file: ""\n  fallback_dns:\n    - 9.9.9.9\n', False),
            ('  upstream_dns_file: ""\n  fallback_dns: [9.9.9.9]\n', False),
            ('  upstream_dns_file: ""\n  "fallback_dns": [9.9.9.9]\n', None),
            ('  fallback_dns: []\nclients:\n  persistent:\n    - name: test\n      upstreams: [9.9.9.9]\n', None),
            ('  fallback_dns: []\nclients:\n  persistent:\n    - name: test\n      upstreams: []\n', True),
            ('  upstream_dns_file: ""\n  fallback_dns: []\n', True),
        )
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "AdGuardHome.yaml"
            for options, expected in fixtures:
                path.write_text("dns:\n  upstream_dns:\n    - 127.0.0.1:5335\n" + options, encoding="utf-8")
                with self.subTest(options=options), mock.patch.object(dashboard, "AGH_YAML", str(path)), \
                        mock.patch.object(dashboard, "run", return_value=""), \
                        mock.patch.object(dashboard, "engine", return_value="adguard"):
                    self.assertIs(dashboard.verify()["Upstream = Unbound"], expected)

    def test_verify_checks_unbound_automatic_interface_and_live_sockets(self):
        localhost_tcp = 'tcp LISTEN 0 256 127.0.0.1:5335 0.0.0.0:* users:(("unbound",pid=84,fd=4))'
        localhost_udp = 'udp UNCONN 0 0 [::1]:5335 [::]:* users:(("unbound",pid=84,fd=5))'
        wildcard_udp = 'udp UNCONN 0 0 0.0.0.0:5335 0.0.0.0:* users:(("unbound",pid=84,fd=5))'
        for automatic, sockets, expected in (
            ("yes", localhost_tcp + "\n" + localhost_udp, False),
            ("no", localhost_tcp + "\n" + wildcard_udp, False),
            ("no", localhost_tcp + "\n" + localhost_udp, True),
            ("no", "", None),
            ("", localhost_tcp + "\n" + localhost_udp, None),
        ):
            def output(command):
                if "unbound-checkconf" in command:
                    return automatic if command[-1] == "interface-automatic" else "127.0.0.1\n::1"
                if "ss" in command:
                    return sockets
                return ""

            with self.subTest(automatic=automatic, sockets=sockets), \
                    mock.patch.object(dashboard, "run", side_effect=output):
                self.assertIs(dashboard.verify()["Unbound solo en localhost"], expected)

    def test_dnssec_needs_authenticated_answer_and_working_bogus_control(self):
        ok = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\n"
        signed = ok + ";; flags: qr rd ra ad; QUERY: 1, ANSWER: 1\ncloudflare.com. 60 IN A 104.16.132.229"
        rejected = ";; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 123\n;; flags: qr rd ra; QUERY: 1, ANSWER: 0"
        control = ok + ";; flags: qr rd ra cd; QUERY: 1, ANSWER: 1\ndnssec-failed.org. 60 IN A 68.87.109.242"
        for positive, negative, unchecked, expected in (
            (signed, rejected, control, True),
            (signed.replace("ra ad;", "ra;"), rejected, control, False),
            (signed.replace("104.16.132.229", "0.0.0.0"), rejected, control, False),
            (signed, rejected, "", None),
            (signed, ";; communication error: SERVFAIL", control, None),
            (signed, control, control, False),
        ):
            def output(command):
                if "cloudflare.com" in command:
                    return positive
                if "dnssec-failed.org" in command:
                    return unchecked if "+cdflag" in command else negative
                return ""

            with self.subTest(positive=positive, negative=negative, unchecked=unchecked), \
                    mock.patch.object(dashboard, "run", side_effect=output):
                self.assertIs(dashboard.verify()["DNSSEC rechaza firmas rotas"], expected)

    def test_resolution_probe_rejects_blocking_address(self):
        reply = ";; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 123\nexample.com. 60 IN A 0.0.0.0"
        def output(command):
            return "0.0.0.0" if "+short" in command else reply
        with mock.patch.object(dashboard, "run", side_effect=output):
            self.assertEqual(dashboard.dig_test("127.0.0.1"), "")

    def test_adguard_client_count_uses_24_hours_across_rotation(self):
        now = datetime.now(timezone.utc)

        def entry(ip, when):
            timestamp = when.isoformat(timespec="microseconds").replace("+00:00", "123Z")
            return json.dumps({"T": timestamp, "IP": ip, "QH": "example.com"})

        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "querylog.json"
            path.write_text("\n".join([
                entry("192.0.2.3", now - timedelta(days=2)),
                entry("192.0.2.1", now - timedelta(minutes=5)),
                entry("192.0.2.4", now + timedelta(hours=1)),
                '{"T":"truncated',
            ]), encoding="utf-8")
            path.with_suffix(".json.1").write_text("\n".join([
                entry("192.0.2.5", now - timedelta(hours=25)),
                entry("192.0.2.1", now - timedelta(hours=10)),
                entry("192.0.2.2", now - timedelta(hours=20)),
            ]), encoding="utf-8")
            with mock.patch.object(dashboard, "AGH_LOG", str(path)), \
                    mock.patch.object(dashboard, "engine", return_value="adguard"):
                self.assertEqual(dashboard.clients_24h(), "2")

    def test_adguard_client_count_marks_truncated_window_as_lower_bound(self):
        timestamp = (datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat()
        old_in_tail = '{{"T":"{}","IP":"192.0.2.2"}}\n'.format(timestamp)
        newest = '{{"T":"{}","IP":"192.0.2.1"}}\n'.format(timestamp)
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "querylog.json"
            path.write_text(old_in_tail + "x" * 10000 + "\n" + newest, encoding="utf-8")
            with mock.patch.object(dashboard, "AGH_LOG", str(path)), \
                    mock.patch.object(dashboard, "AGH_TAIL_BYTES", 4096, create=True), \
                    mock.patch.object(dashboard, "engine", return_value="adguard"):
                self.assertEqual(dashboard.clients_24h(), "1+")

    def test_unverified_check_has_visible_label(self):
        data = self.sample_data()
        data["verify"] = {"Upstream = Unbound": None}
        self.assertIn("Sin verificar", dashboard.render_html(data))

    def test_verify_rejects_public_fallback_upstream(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="interface: 127.0.0.1\n")), \
                mock.patch.object(dashboard, "run", return_value='[ "127.0.0.1#5335", "1.1.1.1" ]'), \
                mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertFalse(dashboard.verify()["Upstream = Unbound"])

    def test_verify_accepts_only_local_upstream(self):
        with mock.patch("builtins.open", mock.mock_open(read_data="interface: 127.0.0.1\n")), \
                mock.patch.object(dashboard, "run", return_value='[ "127.0.0.1#5335" ]'), \
                mock.patch.object(dashboard, "engine", return_value="pihole"):
            self.assertTrue(dashboard.verify()["Upstream = Unbound"])

    def test_pihole_cli_unquoted_arrays_are_checked_in_full(self):
        for raw, expected in (
            ("[ 127.0.0.1#5335 ]", True),
            ("[ 127.0.0.1#5335, 9.9.9.9 ]", False),
            ("warning: [ 127.0.0.1#5335 ]", None),
        ):
            with self.subTest(raw=raw), mock.patch.object(dashboard, "run", return_value=raw), \
                    mock.patch.object(dashboard, "engine", return_value="pihole"):
                self.assertIs(dashboard.verify()["Upstream = Unbound"], expected)


if __name__ == "__main__":
    unittest.main()
